#!/usr/bin/env python3
"""Run the bounded tamper acceptance: expect freeze/nonzero and no promotion after step 1."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from common import (
    SmokeToolError,
    absolute_no_symlinks,
    prime_run_output,
    process_start_token,
    require_regular_file,
    run_checked,
    sha256_file,
)
from run_happy import _child_env, _environment_evidence, _write_state


def _validate_tamper_ledger(path: Path) -> None:
    try:
        records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    except (OSError, json.JSONDecodeError) as exc:
        raise SmokeToolError(f"cannot parse tamper Ledger: {exc}") from exc
    promotions = [record for record in records if record.get("event") == "policy.promoted"]
    promoted_steps = [record.get("data", {}).get("step") for record in promotions]
    if promoted_steps != [1]:
        raise SmokeToolError(f"tamper run must promote only step 1, got {promoted_steps}")
    promotion_seq = promotions[0].get("seq", -1)
    later_denials = [
        record
        for record in records
        if record.get("event") in {"tripwire.fired", "gate.denied"} and record.get("seq", -1) > promotion_seq
    ]
    if not later_denials:
        raise SmokeToolError("tamper run has no post-step-1 tripwire/denial")
    later_approvals = [
        record
        for record in records
        if record.get("event") == "gate.approved" and record.get("data", {}).get("step", 0) > 1
    ]
    if later_approvals:
        raise SmokeToolError("tamper run authorized a policy after step 1")


def _validate_operator_log(path: Path, artifact_root: Path) -> dict[str, object]:
    try:
        report = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SmokeToolError(f"invalid tamper operator log: {exc}") from exc
    if (
        not isinstance(report, dict)
        or report.get("schema") != "filiolae.two-gpu-tamper-operation.v1"
        or report.get("authorized_game_day") is not True
        or report.get("ledger_modified") is not False
    ):
        raise SmokeToolError("tamper operator log has invalid policy fields")
    before = report.get("sha256_before")
    after = report.get("sha256_after")
    if (
        not isinstance(before, str)
        or not isinstance(after, str)
        or len(before) != 64
        or len(after) != 64
        or before == after
    ):
        raise SmokeToolError("tamper operator log has invalid before/after digests")
    relative = report.get("target_relative_to_artifact_root")
    if not isinstance(relative, str) or relative.startswith(("/", "../")) or "/../" in relative:
        raise SmokeToolError("tamper operator log has an unsafe target")
    target = artifact_root / relative
    if not target.resolve(strict=True).is_relative_to(artifact_root.resolve(strict=True)):
        raise SmokeToolError("tamper operator target escapes the artifact root")
    if report.get("target") != str(target):
        raise SmokeToolError("tamper operator target path is inconsistent")
    current = sha256_file(require_regular_file(target))
    if current != after:
        raise SmokeToolError("tamper operator target no longer matches its recorded after digest")
    return report


def _preflight_command(args: argparse.Namespace, report: Path) -> list[str]:
    payload = Path(args.payload_dir).absolute()
    command = [
        sys.executable,
        str(payload / "bin" / "remote_preflight.py"),
        "--payload-dir",
        str(payload),
        "--prime-rl",
        str(Path(args.prime_rl).absolute()),
        "--run-id",
        args.run_id,
        "--profile",
        "tamper",
        "--output",
        str(Path(args.output).absolute()),
        "--anchor-private-key",
        str(Path(args.anchor_private_key).absolute()),
        "--anchor-dir",
        str(Path(args.anchor_dir).absolute()),
        "--report",
        str(report),
        "--hf-home",
        str(Path(args.hf_home).absolute()),
    ]
    if args.bootstrap_source:
        command.append("--bootstrap-source")
    if args.venv_dir:
        command += ["--venv-dir", str(Path(args.venv_dir).absolute())]
    if args.bootstrap_frozen:
        command += ["--bootstrap-frozen", "--bootstrap-timeout", str(args.bootstrap_timeout)]
    if args.prefetch_model:
        command += ["--prefetch-model", "--prefetch-timeout", str(args.prefetch_timeout)]
    if args.prefetch_dataset:
        command += ["--prefetch-dataset", "--prefetch-timeout", str(args.prefetch_timeout)]
    if args.prefetch_harness:
        command += ["--prefetch-harness", "--prefetch-timeout", str(args.prefetch_timeout)]
    for path in args.require_path:
        command += ["--require-path", str(Path(path).absolute())]
    return command


def run_tamper(args: argparse.Namespace) -> int:
    state_dir = Path(args.state_dir).absolute()
    if state_dir.exists():
        raise SmokeToolError(f"fresh state directory required: {state_dir}")
    absolute_no_symlinks(state_dir.parent)
    state_dir.mkdir(mode=0o700)
    absolute_no_symlinks(state_dir)
    state_path = state_dir / "run-state.json"
    _write_state(
        state_path,
        schema="filiolae.two-gpu-run-state.v1",
        profile="tamper",
        run_id=args.run_id,
        status="preflight",
        terminal=False,
        runner_pid=os.getpid(),
        runner_start_token=process_start_token(os.getpid()),
        started_at=datetime.now(UTC).isoformat(),
        containment="POSIX process group only; not a systemd/cgroup containment claim",
    )
    report = state_dir / "remote-preflight.json"
    try:
        result = run_checked(_preflight_command(args, report), timeout=args.preflight_timeout)
        (state_dir / "remote-preflight.stdout.json").write_text(result.stdout)
    except BaseException as exc:
        _write_state(
            state_path,
            status="preflight_failed",
            terminal=True,
            finished_at=datetime.now(UTC).isoformat(),
            error=repr(exc),
        )
        raise

    payload = Path(args.payload_dir).absolute()
    output = Path(args.output).absolute()
    run_output = prime_run_output(output)
    venv_dir = Path(args.venv_dir).absolute() if args.venv_dir else Path(args.prime_rl).absolute() / ".venv"
    filiolae = str(venv_dir / "bin" / "filiolae")
    filiolae_rl = str(venv_dir / "bin" / "filiolae-rl")
    governed_command = [
        "timeout",
        "--foreground",
        "--signal=TERM",
        f"--kill-after={args.kill_after_seconds}s",
        f"{args.wall_seconds}s",
        filiolae,
        "supervise",
        "--freeze-marker",
        str(run_output / "control" / "filiolae" / "freeze.json"),
        "--cwd",
        str(Path(args.prime_rl).absolute()),
        "--",
        filiolae_rl,
        "@",
        str(payload / "tamper.toml"),
        "--output-dir",
        str(output),
    ]
    operator_log = state_dir / "tamper-operation.json"
    injector_command = [
        sys.executable,
        str(payload / "bin" / "tamper_after_step1.py"),
        "--ledger",
        str(run_output / "control" / "filiolae" / "ledger.jsonl"),
        "--artifact-root",
        str(run_output / "control" / "filiolae" / "artifacts"),
        "--operator-log",
        str(operator_log),
        "--timeout-seconds",
        str(args.injector_timeout),
    ]
    env = _child_env(args)
    _write_state(
        state_path,
        status="running",
        governed_command=governed_command,
        injector_command=injector_command,
        resolved_run_output=str(run_output),
        child_environment=_environment_evidence(env),
    )
    governed: subprocess.Popen[bytes] | None = None
    injector: subprocess.Popen[bytes] | None = None
    previous: dict[int, object] = {}
    signals_received: list[int] = []
    execution_error: BaseException | None = None

    def stop_child(process: subprocess.Popen[bytes] | None) -> None:
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    def handle_signal(signum: int, frame: object) -> None:
        del frame
        signals_received.append(signum)
        for process in (governed, injector):
            if process is not None and process.poll() is None:
                process.send_signal(signal.SIGTERM)

    for item in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        previous[item] = signal.getsignal(item)
        signal.signal(item, handle_signal)
    try:
        with (
            (state_dir / "governed-run.log").open("wb") as governed_log,
            (state_dir / "tamper-injector.log").open("wb") as injector_log,
        ):
            if signals_received:
                raise SmokeToolError("tamper run cancelled before injector launch")
            injector = subprocess.Popen(injector_command, stdout=injector_log, stderr=subprocess.STDOUT)
            if signals_received:
                stop_child(injector)
                raise SmokeToolError("tamper run cancelled before governed process launch")
            governed = subprocess.Popen(
                governed_command, env=env, stdout=governed_log, stderr=subprocess.STDOUT
            )
            if signals_received:
                stop_child(governed)
                stop_child(injector)
                raise SmokeToolError("tamper run cancelled during governed process launch")
            governed_returncode = governed.wait()
            try:
                injector_returncode = injector.wait(timeout=30)
            except subprocess.TimeoutExpired:
                stop_child(injector)
                injector_returncode = injector.returncode
    except BaseException as exc:
        execution_error = exc
        stop_child(governed)
        stop_child(injector)
    finally:
        for item, handler in previous.items():
            signal.signal(item, handler)
    if execution_error is not None:
        _write_state(
            state_path,
            status="execution_failed",
            terminal=True,
            signal_received=signals_received[-1] if signals_received else None,
            finished_at=datetime.now(UTC).isoformat(),
            error=repr(execution_error),
        )
        raise SmokeToolError("tamper processes failed before validation") from execution_error

    ledger = run_output / "control" / "filiolae" / "ledger.jsonl"
    artifacts = run_output / "control" / "filiolae" / "artifacts"
    copied_charter = run_output / "control" / "filiolae" / "charter.yaml"
    audit: subprocess.CompletedProcess[str] | None = None
    audit_execution_error: str | None = None
    try:
        audit = subprocess.run(
            [
                filiolae,
                "audit",
                str(ledger),
                "--artifact-root",
                str(artifacts),
                "--charter",
                str(copied_charter),
                "--anchor-dir",
                str(Path(args.anchor_dir).absolute()),
                "--anchor-public-key",
                str(payload / "anchor-public.pem"),
            ],
            capture_output=True,
            text=True,
            timeout=args.audit_timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        audit_execution_error = repr(exc)
    (state_dir / "expected-failing-audit.stdout").write_text(audit.stdout if audit else "")
    (state_dir / "expected-failing-audit.stderr").write_text(
        audit.stderr if audit else (audit_execution_error or "")
    )
    validation_error: str | None = None
    try:
        if signals_received:
            raise SmokeToolError(f"tamper runner received signal {signals_received[-1]}")
        if governed_returncode == 0:
            raise SmokeToolError("tamper governed command unexpectedly exited zero")
        if injector_returncode != 0 or not operator_log.is_file():
            raise SmokeToolError(f"tamper injector failed with {injector_returncode}")
        _validate_operator_log(operator_log, artifacts)
        if not (run_output / "control" / "filiolae" / "freeze.json").is_file():
            raise SmokeToolError("tamper run did not latch freeze state")
        if audit is None:
            raise SmokeToolError(f"tamper audit failed to execute: {audit_execution_error}")
        if audit.returncode == 0:
            raise SmokeToolError("tamper audit unexpectedly accepted corrupted evidence")
        _validate_tamper_ledger(ledger)
        run_checked(
            [
                filiolae,
                "verify-anchors",
                str(ledger),
                "--artifact-root",
                str(artifacts),
                "--anchor-dir",
                str(Path(args.anchor_dir).absolute()),
                "--public-key",
                str(payload / "anchor-public.pem"),
            ],
            timeout=args.audit_timeout,
        )
    except BaseException as exc:
        validation_error = repr(exc)
    success = validation_error is None
    _write_state(
        state_path,
        status="success" if success else "failed",
        terminal=True,
        governed_returncode=governed_returncode,
        injector_returncode=injector_returncode,
        expected_audit_returncode=audit.returncode if audit is not None else None,
        signal_received=signals_received[-1] if signals_received else None,
        validation_error=validation_error,
        finished_at=datetime.now(UTC).isoformat(),
    )
    return 0 if success else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload-dir", required=True)
    parser.add_argument("--prime-rl", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--anchor-private-key", required=True)
    parser.add_argument("--anchor-dir", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--venv-dir")
    parser.add_argument("--bootstrap-source", action="store_true")
    parser.add_argument("--bootstrap-frozen", action="store_true")
    parser.add_argument("--bootstrap-timeout", type=int, default=900)
    parser.add_argument("--prefetch-model", action="store_true")
    parser.add_argument("--prefetch-dataset", action="store_true")
    parser.add_argument("--prefetch-harness", action="store_true")
    parser.add_argument("--prefetch-timeout", type=int, default=900)
    parser.add_argument("--hf-home", required=True)
    parser.add_argument("--torch-home")
    parser.add_argument("--require-path", action="append", default=[])
    parser.add_argument("--wall-seconds", type=int, default=2400)
    parser.add_argument("--kill-after-seconds", type=int, default=30)
    parser.add_argument("--preflight-timeout", type=int, default=1800)
    parser.add_argument("--injector-timeout", type=int, default=1200)
    parser.add_argument("--audit-timeout", type=int, default=600)
    args = parser.parse_args()
    if args.wall_seconds < 60 or args.kill_after_seconds < 5:
        parser.error("unsafe timeout values")
    return args


def main() -> int:
    try:
        return run_tamper(parse_args())
    except SmokeToolError as exc:
        print(f"tamper run failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
