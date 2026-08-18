"""Filiolae command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import signal
import threading
from importlib.metadata import version
from pathlib import Path

from .anchor import (
    AnchorStore,
    anchor_ledger_head,
    generate_keypair,
    load_private_key,
    load_public_key,
    verify_anchor_store,
    verify_anchor_store_readonly,
)
from .audit import audit_governance
from .charter import Charter
from .demo import run_demo
from .enrollment import create_witness_enrollment, load_witness_enrollment
from .explain import discover_run_layout, explain_run, render_owner_text
from .freeze import FreezeController
from .ledger import Ledger, provision_ledger_lock
from .retention import export_receipt_retention_bundle, verify_receipt_retention_bundle
from .supervisor import ProcessGroupSupervisor
from .witness import UnixAnchorWitnessServer, UnixSocketHeadAnchor


def _socket_mode(value: str) -> int:
    try:
        mode = int(value, 8)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("socket mode must be octal 0600 or 0660") from exc
    if mode not in {0o600, 0o660}:
        raise argparse.ArgumentTypeError("socket mode must be 0600 or 0660")
    return mode


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="filiolae",
        epilog=(
            "Copyright 2026 MelaBuilt AI and Filiolae contributors. "
            "Licensed AGPL-3.0-only; this program comes with ABSOLUTELY NO WARRANTY. "
            "License and source: https://github.com/MelaBuilt-AI/Filiolae"
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {version('filiolae')}")
    commands = parser.add_subparsers(dest="command", required=True)

    audit = commands.add_parser("audit", help="verify a Ledger and its artifact bindings")
    audit.add_argument("ledger", type=Path)
    audit.add_argument("--artifact-root", type=Path, required=True)
    audit.add_argument("--charter", type=Path, required=True)
    audit.add_argument("--chain-only", action="store_true")
    audit.add_argument("--anchor-dir", type=Path)
    audit.add_argument("--anchor-public-key", type=Path)
    audit.add_argument("--candidate-eval-public-key", type=Path)
    audit.add_argument("--witness-enrollment", type=Path)

    explain = commands.add_parser("explain", help="summarize one governed run for its Owner")
    explain.add_argument("run_directory", type=Path)
    explain.add_argument("--anchor-dir", type=Path)
    explain.add_argument("--anchor-public-key", type=Path)
    explain.add_argument("--candidate-eval-public-key", type=Path)
    explain.add_argument("--witness-enrollment", type=Path)
    explain.add_argument("--max-items", type=int, default=20)
    explain.add_argument("--json", action="store_true", help="emit the bounded machine-readable report")

    demo = commands.add_parser("demo", help="run the CPU-only governance game day")
    demo.add_argument("root", type=Path)
    demo.add_argument("--charter", type=Path, required=True)
    demo.add_argument("--tamper", action="store_true")

    supervise = commands.add_parser("supervise", help="run a command under fail-closed freeze supervision")
    supervise.add_argument("--freeze-marker", type=Path, required=True)
    supervise.add_argument("--cwd", type=Path)
    supervise.add_argument("--poll-interval", type=float, default=0.05)
    supervise.add_argument("--term-grace", type=float, default=5.0)
    supervise.add_argument("supervised_command", nargs=argparse.REMAINDER)

    keygen = commands.add_parser("anchor-keygen", help="generate an Ed25519 anchor keypair")
    keygen.add_argument("--private-key", type=Path, required=True)
    keygen.add_argument("--public-key", type=Path, required=True)

    anchor = commands.add_parser("anchor-head", help="sign and persist the current Ledger head")
    anchor.add_argument("ledger", type=Path)
    anchor.add_argument("--artifact-root", type=Path)
    anchor.add_argument("--anchor-dir", type=Path, required=True)
    anchor.add_argument("--private-key", type=Path, required=True)

    verify = commands.add_parser("verify-anchors", help="verify signed Ledger-head receipts")
    verify.add_argument("ledger", type=Path)
    verify.add_argument("--artifact-root", type=Path)
    verify.add_argument("--anchor-dir", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    verify.add_argument("--allow-stale", action="store_true")

    witness_enroll = commands.add_parser(
        "anchor-witness-enroll",
        help="create a one-time reviewed enrollment for a planned witness Ledger",
    )
    witness_enroll.add_argument("ledger", type=Path)
    witness_enroll.add_argument("--charter", type=Path, required=True)
    witness_enroll.add_argument("--run-id", required=True)
    witness_enroll.add_argument("--public-key", type=Path, required=True)
    witness_enroll.add_argument("--enrollment", type=Path, required=True)

    witness_serve = commands.add_parser(
        "anchor-witness-serve",
        help="serve an explicitly enrolled Ledger from a separately managed Ed25519 witness",
    )
    witness_serve.add_argument("ledger", type=Path)
    witness_serve.add_argument("--artifact-root", type=Path)
    witness_serve.add_argument("--socket", type=Path, required=True)
    witness_serve.add_argument("--ledger-lock", type=Path, required=True)
    witness_serve.add_argument("--anchor-dir", type=Path, required=True)
    witness_serve.add_argument("--private-key", type=Path, required=True)
    witness_serve.add_argument("--enrollment", type=Path, required=True)
    witness_serve.add_argument("--allowed-uid", type=int, default=os.getuid())
    witness_serve.add_argument("--socket-mode", type=_socket_mode, default=0o600)
    witness_serve.add_argument("--socket-gid", type=int)
    witness_serve.add_argument("--connection-timeout", type=float, default=10.0)

    witness_head = commands.add_parser(
        "anchor-witness-head",
        help="request and locally mirror a witness checkpoint of the current Ledger head",
    )
    witness_head.add_argument("ledger", type=Path)
    witness_head.add_argument("--artifact-root", type=Path)
    witness_head.add_argument("--socket", type=Path, required=True)
    witness_head.add_argument("--ledger-lock", type=Path, required=True)
    witness_head.add_argument("--mirror-dir", type=Path, required=True)
    witness_head.add_argument("--public-key", type=Path, required=True)
    witness_head.add_argument("--timeout", type=float, default=10.0)

    retention_export = commands.add_parser(
        "retention-export",
        help="prepare a verified static receipt package for later immutable delivery",
    )
    retention_export.add_argument("ledger", type=Path)
    retention_export.add_argument("--artifact-root", type=Path)
    retention_export.add_argument("--ledger-lock", type=Path)
    retention_export.add_argument("--anchor-dir", type=Path, required=True)
    retention_export.add_argument("--public-key", type=Path, required=True)
    retention_export.add_argument("--witness-enrollment", type=Path)
    retention_export.add_argument("--output", type=Path, required=True)

    retention_verify = commands.add_parser(
        "retention-verify",
        help="verify a restored static receipt package against an out-of-band key",
    )
    retention_verify.add_argument("bundle", type=Path)
    retention_verify.add_argument("ledger", type=Path)
    retention_verify.add_argument("--artifact-root", type=Path)
    retention_verify.add_argument("--ledger-lock", type=Path)
    retention_verify.add_argument("--public-key", type=Path, required=True)

    lock = commands.add_parser(
        "ledger-lock-provision",
        help="create a fixed Ledger lock inode for cross-credential witness deployment",
    )
    lock.add_argument("path", type=Path)
    lock.add_argument("--mode", type=_socket_mode, default=0o660)
    lock.add_argument("--gid", type=int)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "audit":
        ledger = Ledger(args.ledger, artifact_root=args.artifact_root)
        if bool(args.anchor_dir) != bool(args.anchor_public_key):
            raise SystemExit("--anchor-dir and --anchor-public-key must be supplied together")
        if args.chain_only and (args.anchor_dir or args.candidate_eval_public_key or args.witness_enrollment):
            raise SystemExit("external verification cannot be combined with --chain-only")
        anchor_report = None
        if args.anchor_dir and args.anchor_public_key:
            anchor_report = verify_anchor_store(
                ledger,
                AnchorStore(args.anchor_dir),
                load_public_key(args.anchor_public_key),
                require_current=True,
            )
        if args.chain_only:
            report = ledger.audit(verify_artifacts=False)
            record_count = len(report.records)
        else:
            report = audit_governance(
                ledger,
                Charter.load(args.charter),
                verify_artifacts=True,
                anchor_report=anchor_report,
                candidate_eval_public_key=(
                    load_public_key(args.candidate_eval_public_key)
                    if args.candidate_eval_public_key
                    else None
                ),
                witness_enrollment=(
                    load_witness_enrollment(args.witness_enrollment) if args.witness_enrollment else None
                ),
            )
            record_count = report.record_count
        print(
            json.dumps(
                {
                    "ok": report.ok,
                    "records": record_count,
                    "anchors_checked": anchor_report is not None,
                    "anchor_receipts": len(anchor_report.receipts) if anchor_report else 0,
                    "unanchored_tail_records": (
                        anchor_report.unanchored_tail_records if anchor_report else None
                    ),
                    "issues": [issue.__dict__ for issue in report.issues],
                },
                indent=2,
            )
        )
        return 0 if report.ok else 1
    if args.command == "explain":
        if bool(args.anchor_dir) != bool(args.anchor_public_key):
            raise SystemExit("--anchor-dir and --anchor-public-key must be supplied together")
        anchor_report = None
        if args.anchor_dir and args.anchor_public_key:
            layout = discover_run_layout(args.run_directory)
            ledger = Ledger(layout.ledger, artifact_root=layout.artifacts)
            anchor_report = verify_anchor_store_readonly(
                ledger,
                AnchorStore(args.anchor_dir),
                load_public_key(args.anchor_public_key),
                require_current=True,
            )
        report = explain_run(
            args.run_directory,
            anchor_report=anchor_report,
            candidate_eval_public_key=(
                load_public_key(args.candidate_eval_public_key) if args.candidate_eval_public_key else None
            ),
            witness_enrollment=(
                load_witness_enrollment(args.witness_enrollment) if args.witness_enrollment else None
            ),
            max_items=args.max_items,
        )
        print(json.dumps(report, indent=2) if args.json else render_owner_text(report))
        return 0 if report["status"]["audit_ok"] else 1
    if args.command == "demo":
        result = run_demo(args.root, charter_path=args.charter, tamper=args.tamper)
        print(json.dumps(result, indent=2))
        return 0 if result["allowed"] != args.tamper else 1
    if args.command in {"retention-export", "retention-verify"}:
        ledger = Ledger(
            args.ledger,
            artifact_root=args.artifact_root or args.ledger.parent,
            lock_path=args.ledger_lock,
            require_existing_lock=args.ledger_lock is not None,
        )
        if args.command == "retention-export":
            report = export_receipt_retention_bundle(
                ledger,
                AnchorStore(args.anchor_dir),
                load_public_key(args.public_key),
                args.output,
                witness_enrollment=(
                    load_witness_enrollment(args.witness_enrollment) if args.witness_enrollment else None
                ),
            )
        else:
            report = verify_receipt_retention_bundle(
                ledger,
                args.bundle,
                load_public_key(args.public_key),
            )
        print(
            json.dumps(
                {
                    "ok": True,
                    "manifest_sha256": report.manifest_sha256,
                    "object_prefix": report.object_prefix,
                    "manifest_object_key": report.manifest_object_key,
                    "receipt_count": report.receipt_count,
                    "latest_ledger_seq": report.manifest["latest_ledger_seq"],
                    "provider_retention_verified": False,
                },
                indent=2,
            )
        )
        return 0
    if args.command == "anchor-keygen":
        key_id = generate_keypair(args.private_key, args.public_key)
        print(json.dumps({"algorithm": "Ed25519", "key_id": key_id}, indent=2))
        return 0
    if args.command == "anchor-head":
        ledger = Ledger(args.ledger, artifact_root=args.artifact_root or args.ledger.parent)
        receipt = anchor_ledger_head(
            ledger,
            AnchorStore(args.anchor_dir),
            load_private_key(args.private_key),
        )
        print(json.dumps(receipt.to_dict(), indent=2))
        return 0
    if args.command == "ledger-lock-provision":
        device, inode = provision_ledger_lock(args.path, mode=args.mode, gid=args.gid)
        print(json.dumps({"path": str(args.path.absolute()), "device": device, "inode": inode}, indent=2))
        return 0
    if args.command == "anchor-witness-enroll":
        enrollment = create_witness_enrollment(
            args.enrollment,
            ledger_path=args.ledger,
            run_id=args.run_id,
            genesis_charter_sha256=Charter.load(args.charter).sha256,
            public_key=load_public_key(args.public_key),
        )
        print(json.dumps({**enrollment.to_dict(), "enrollment_sha256": enrollment.sha256}, indent=2))
        return 0
    if args.command == "anchor-witness-serve":
        ledger = Ledger(
            args.ledger,
            artifact_root=args.artifact_root or args.ledger.parent,
            lock_path=args.ledger_lock,
            require_existing_lock=True,
        )
        server = UnixAnchorWitnessServer(
            args.socket,
            ledger,
            AnchorStore(args.anchor_dir),
            load_private_key(args.private_key),
            load_witness_enrollment(args.enrollment),
            allowed_uid=args.allowed_uid,
            connection_timeout=args.connection_timeout,
            socket_mode=args.socket_mode,
            socket_gid=args.socket_gid,
        )
        stop_event = threading.Event()
        previous = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}
        for signum in previous:
            signal.signal(signum, lambda _signum, _frame: stop_event.set())
        try:
            server.serve(stop_event)
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
        return 0
    if args.command == "anchor-witness-head":
        ledger = Ledger(
            args.ledger,
            artifact_root=args.artifact_root or args.ledger.parent,
            lock_path=args.ledger_lock,
            require_existing_lock=True,
        )
        report = ledger.audit()
        if not report.ok:
            raise SystemExit(report.summary())
        head = report.records[-1]
        receipt = UnixSocketHeadAnchor(
            args.socket,
            AnchorStore(args.mirror_dir),
            load_public_key(args.public_key),
            timeout=args.timeout,
        ).acknowledge(ledger, expected_seq=head.seq, expected_head=head.hash)
        print(json.dumps(receipt.to_dict(), indent=2))
        return 0
    if args.command == "verify-anchors":
        ledger = Ledger(args.ledger, artifact_root=args.artifact_root or args.ledger.parent)
        report = verify_anchor_store(
            ledger,
            AnchorStore(args.anchor_dir),
            load_public_key(args.public_key),
            require_current=not args.allow_stale,
        )
        print(
            json.dumps(
                {
                    "ok": report.ok,
                    "current_head_anchored": report.current_head_anchored,
                    "receipts": len(report.receipts),
                    "issues": [issue.__dict__ for issue in report.issues],
                },
                indent=2,
            )
        )
        return 0 if report.ok else 1
    if args.command == "supervise":
        command = list(args.supervised_command)
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            raise SystemExit("supervise requires a command after --")
        freezer = FreezeController(args.freeze_marker)
        result = ProcessGroupSupervisor(
            freezer,
            poll_interval=args.poll_interval,
            term_grace_seconds=args.term_grace,
        ).run(command, cwd=args.cwd)
        print(json.dumps(result.__dict__, indent=2))
        if freezer.state().frozen:
            return 75
        return result.returncode if result.returncode >= 0 else 128 - result.returncode
    raise AssertionError("unreachable")
