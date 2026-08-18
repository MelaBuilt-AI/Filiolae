#!/usr/bin/env python3
"""Quiescence-check, audit, and archive allowlisted local-anchor smoke evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from common import (
    SmokeToolError,
    absolute_no_symlinks,
    atomic_write_json,
    ensure_outside,
    prime_run_output,
    process_start_token,
    require_regular_file,
    require_safe_tree,
    sha256_file,
)

FULL_MODE_OMITTED_ROOTS = {"checkpoints", "weights"}


def _bounded(argv: list[str], timeout: int) -> dict[str, object]:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return {
            "argv": argv,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"argv": argv, "returncode": None, "error": repr(exc), "stdout": "", "stderr": ""}


def _sha256_stream(stream: object, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(chunk_size):
        digest.update(chunk)
    return digest.hexdigest()


def _assert_quiescent(state: dict[str, object], output: Path) -> None:
    if state.get("terminal") is not True:
        raise SmokeToolError("runner state is not terminal; refuse a live evidence snapshot")
    pid = state.get("runner_pid")
    token = state.get("runner_start_token")
    if isinstance(pid, int) and isinstance(token, str) and process_start_token(pid) == token:
        raise SmokeToolError(f"recorded runner process is still live: PID {pid}")
    gpu = _bounded(
        ["nvidia-smi", "--query-compute-apps=pid,process_name", "--format=csv,noheader,nounits"],
        30,
    )
    if gpu.get("returncode") != 0:
        raise SmokeToolError(f"cannot establish GPU quiescence: {gpu}")
    if str(gpu.get("stdout", "")).strip():
        raise SmokeToolError(f"GPU compute processes remain live: {gpu['stdout']!r}")
    needle = str(output).encode()
    for proc in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            command = proc.read_bytes()
        except OSError:
            continue
        if needle in command and any(marker in command for marker in (b"filiolae-rl", b"prime_rl")):
            raise SmokeToolError(f"governed process may remain live: {proc.parent.name}")


def _assert_success_state(state: dict[str, object], profile: str) -> None:
    if state.get("status") != "success":
        raise SmokeToolError(f"runner did not record {profile} acceptance success")
    if state.get("signal_received") is not None:
        raise SmokeToolError("runner was interrupted by a signal")
    if profile == "happy":
        if state.get("governed_returncode") != 0 or state.get("audit_ok") is not True:
            raise SmokeToolError("happy runner state has unsuccessful exit/audit semantics")
        return
    governed_returncode = state.get("governed_returncode")
    audit_returncode = state.get("expected_audit_returncode")
    if (
        not isinstance(governed_returncode, int)
        or governed_returncode == 0
        or state.get("injector_returncode") != 0
        or not isinstance(audit_returncode, int)
        or audit_returncode == 0
        or state.get("validation_error") is not None
    ):
        raise SmokeToolError("tamper runner state has unsuccessful freeze/audit semantics")


def _validate_run_inputs(
    state: dict[str, object],
    profile: str,
    output: Path,
    anchors: Path,
    submitted_config: Path,
    payload_manifest: Path,
    preflight_path: Path,
) -> dict[str, object]:
    try:
        preflight = json.loads(preflight_path.read_text())
        manifest = json.loads(payload_manifest.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SmokeToolError(f"invalid preflight/input manifest evidence: {exc}") from exc
    if not isinstance(preflight, dict) or not isinstance(manifest, dict):
        raise SmokeToolError("preflight and payload manifest evidence must be JSON objects")
    run_id = state.get("run_id")
    if (
        preflight.get("schema") != "filiolae.two-gpu-remote-preflight.v1"
        or preflight.get("ok") is not True
        or preflight.get("run_id") != run_id
        or preflight.get("profile") != profile
        or preflight.get("output") != str(output)
        or state.get("resolved_run_output") != str(prime_run_output(output))
        or preflight.get("anchor_dir") != str(anchors)
        or preflight.get("config") != str(submitted_config)
    ):
        raise SmokeToolError("remote preflight does not bind the collected run inputs and paths")
    if preflight.get("payload_manifest_sha256") != sha256_file(payload_manifest):
        raise SmokeToolError("remote preflight does not bind the supplied payload manifest")
    config_name = "smoke.toml" if profile == "happy" else "tamper.toml"
    files = manifest.get("files")
    runs = manifest.get("runs")
    if (
        manifest.get("schema") != "filiolae.two-gpu-smoke-payload.v1"
        or not isinstance(runs, dict)
        or runs.get(profile) != run_id
        or not isinstance(files, dict)
        or files.get(config_name) != sha256_file(submitted_config)
    ):
        raise SmokeToolError("payload manifest does not bind the run ID and submitted config")
    return preflight


def _control_files(output: Path) -> list[tuple[Path, str]]:
    candidates = [output / "control" / "orch.toml"]
    governance = output / "control" / "filiolae"
    for relative in ("ledger.jsonl", "ledger.jsonl.lock", "charter.yaml", "freeze.json"):
        candidate = governance / relative
        if candidate.exists():
            candidates.append(candidate)
    derived = governance / "derived"
    if derived.exists():
        candidates.extend(require_safe_tree(derived))
    result: list[tuple[Path, str]] = []
    for candidate in candidates:
        require_regular_file(candidate)
        result.append((candidate, f"run/{candidate.relative_to(output).as_posix()}"))
    return result


def _tree_files(source: Path, prefix: str) -> list[tuple[Path, str]]:
    return [(item, f"{prefix}/{item.relative_to(source).as_posix()}") for item in require_safe_tree(source)]


def _full_run_files(output: Path) -> list[tuple[Path, str]]:
    """Retain governed evidence while omitting redundant trainer/export bulk."""
    result: list[tuple[Path, str]] = []
    for item in require_safe_tree(output):
        relative = item.relative_to(output)
        if relative.parts[0] in FULL_MODE_OMITTED_ROOTS:
            continue
        result.append((item, f"run/{relative.as_posix()}"))
    return result


def collect(args: argparse.Namespace) -> dict[str, object]:
    filiolae = require_regular_file(Path(args.filiolae).absolute())
    output = Path(args.output).absolute()
    run_output = prime_run_output(output)
    anchors = Path(args.anchor_dir).absolute()
    state_dir = Path(args.state_dir).absolute()
    public_key = require_regular_file(Path(args.public_key).absolute())
    submitted_config = require_regular_file(Path(args.submitted_config).absolute())
    payload_manifest = require_regular_file(Path(args.payload_manifest).absolute())
    for tree in (output, anchors, state_dir):
        absolute_no_symlinks(tree)
    state_path = require_regular_file(state_dir / "run-state.json")
    try:
        state = json.loads(state_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SmokeToolError(f"invalid runner state: {exc}") from exc
    _assert_quiescent(state, output)
    if state.get("profile") != args.profile:
        raise SmokeToolError("runner-state profile does not match collection profile")
    _assert_success_state(state, args.profile)
    preflight_evidence = _validate_run_inputs(
        state,
        args.profile,
        output,
        anchors,
        submitted_config,
        payload_manifest,
        require_regular_file(state_dir / "remote-preflight.json"),
    )

    destination = Path(args.destination).absolute()
    checksum_path = Path(str(destination) + ".sha256")
    report_path = Path(str(destination) + ".report.json")
    ensure_outside(destination, (output, anchors, state_dir))
    absolute_no_symlinks(destination.parent)
    for path in (destination, checksum_path, report_path):
        if path.exists():
            raise SmokeToolError(f"refusing to overwrite evidence output: {path}")

    ledger = require_regular_file(run_output / "control" / "filiolae" / "ledger.jsonl")
    artifacts = run_output / "control" / "filiolae" / "artifacts"
    copied_charter = require_regular_file(run_output / "control" / "filiolae" / "charter.yaml")
    audit = _bounded(
        [
            str(filiolae),
            "audit",
            str(ledger),
            "--artifact-root",
            str(artifacts),
            "--charter",
            str(copied_charter),
            "--anchor-dir",
            str(anchors),
            "--anchor-public-key",
            str(public_key),
        ],
        args.audit_timeout,
    )
    anchor_check = _bounded(
        [
            str(filiolae),
            "verify-anchors",
            str(ledger),
            "--artifact-root",
            str(artifacts),
            "--anchor-dir",
            str(anchors),
            "--public-key",
            str(public_key),
        ],
        args.audit_timeout,
    )
    metadata: dict[str, object] = {
        "schema": "filiolae.two-gpu-evidence-collection.v1",
        "ts": datetime.now(UTC).isoformat(),
        "mode": "control" if args.control_only else "full",
        "omitted_redundant_bulk_roots": ([] if args.control_only else sorted(FULL_MODE_OMITTED_ROOTS)),
        "profile": args.profile,
        "runner_state": state,
        "submitted_output": str(output),
        "resolved_run_output": str(run_output),
        "remote_preflight": preflight_evidence,
        "audit": audit,
        "anchor_verification": anchor_check,
        "containment_nonclaim": (
            "terminal runner and zero visible GPU workloads were checked, but process-group mode "
            "cannot exclude a hostile setsid escape"
        ),
        "host": {
            "uname": _bounded(["uname", "-a"], 30),
            "nvidia_smi": _bounded(["nvidia-smi"], 30),
            "os_release": Path("/etc/os-release").read_text() if Path("/etc/os-release").is_file() else None,
        },
        "governed_environment_allowlist": state.get("child_environment"),
    }

    files: list[tuple[Path, str]] = []
    if args.control_only:
        files.extend(_control_files(run_output))
    else:
        files.extend(_full_run_files(output))
    files.extend(_tree_files(anchors, "anchors"))
    files.extend(_tree_files(state_dir, "operator-state"))
    files.extend(
        [
            (public_key, "inputs/anchor-public.pem"),
            (submitted_config, "inputs/submitted-smoke.toml"),
            (payload_manifest, "inputs/payload-manifest.json"),
        ]
    )
    member_names = [name for _, name in files]
    if len(member_names) != len(set(member_names)):
        raise SmokeToolError("duplicate archive member names detected")
    metadata["file_count"] = len(files)
    member_evidence = {
        name: {"sha256": sha256_file(path), "size": path.stat().st_size}
        for path, name in sorted(files, key=lambda item: item[1])
    }
    metadata["source_bytes"] = sum(item["size"] for item in member_evidence.values())
    metadata["archive_members"] = member_evidence

    report_member = "operator/collection-report.json"
    with tempfile.TemporaryDirectory(prefix="filiolae-evidence-meta-") as temporary:
        meta_path = Path(temporary) / "collection-report.json"
        atomic_write_json(meta_path, metadata)
        with tarfile.open(destination, "w", format=tarfile.PAX_FORMAT) as archive:
            for source, name in sorted(files, key=lambda item: item[1]):
                archive.add(source, arcname=name, recursive=False)
            archive.add(meta_path, arcname=report_member, recursive=False)
    with tarfile.open(destination, "r") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        expected_names = [*member_evidence, report_member]
        if len(names) != len(set(names)) or set(names) != set(expected_names):
            raise SmokeToolError("evidence archive member set changed during collection")
        for name, expected in member_evidence.items():
            member = archive.getmember(name)
            if not member.isfile() or member.size != expected["size"]:
                raise SmokeToolError(f"evidence archive member type/size mismatch: {name}")
            stream = archive.extractfile(member)
            if stream is None or _sha256_stream(stream) != expected["sha256"]:
                raise SmokeToolError(f"evidence archive member digest mismatch: {name}")
        if not archive.getmember(report_member).isfile():
            raise SmokeToolError("evidence archive report is not a regular file")
    with destination.open("rb") as stream:
        os.fsync(stream.fileno())
    digest = sha256_file(destination)
    checksum_path.write_text(f"{digest}  {destination.name}\n")
    with checksum_path.open("rb") as stream:
        os.fsync(stream.fileno())
    metadata.update({"archive": str(destination), "archive_sha256": digest})
    atomic_write_json(report_path, metadata)
    return metadata


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("happy", "tamper"), required=True)
    parser.add_argument("--filiolae", required=True, help="absolute .venv/bin/filiolae path")
    parser.add_argument("--output", required=True)
    parser.add_argument("--anchor-dir", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--submitted-config", required=True)
    parser.add_argument("--payload-manifest", required=True)
    parser.add_argument("--destination", required=True, help="new uncompressed tar on durable storage")
    parser.add_argument(
        "--control-only",
        action="store_true",
        help="emergency small bundle; omits bulk artifacts",
    )
    parser.add_argument("--audit-timeout", type=int, default=600)
    return parser.parse_args()


def main() -> int:
    try:
        report = collect(parse_args())
    except SmokeToolError as exc:
        print(f"evidence collection failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    audit_returncode = report["audit"].get("returncode")
    audit_ok = (
        audit_returncode == 0
        if report["profile"] == "happy"
        else (isinstance(audit_returncode, int) and audit_returncode != 0)
    )
    anchors_ok = report["anchor_verification"].get("returncode") == 0
    return 0 if audit_ok and anchors_ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
