#!/usr/bin/env python3
"""Run the bounded local-anchor/process-group happy smoke and verify its control evidence."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path

from common import (
    SmokeToolError,
    absolute_no_symlinks,
    atomic_write_json,
    prime_run_output,
    process_start_token,
    run_checked,
)

SAFE_ENV_KEYS = {
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "TZ",
    "TMPDIR",
    "LD_LIBRARY_PATH",
    "CUDA_HOME",
    "VIRTUAL_ENV",
    "NVIDIA_VISIBLE_DEVICES",
}


def _write_state(path: Path, **updates: object) -> dict[str, object]:
    current: dict[str, object] = {}
    if path.exists():
        current = json.loads(path.read_text())
    current.update(updates)
    atomic_write_json(path, current)
    return current


def _validate_ledger(ledger_path: Path) -> None:
    try:
        records = [json.loads(line) for line in ledger_path.read_text().splitlines() if line.strip()]
    except (OSError, json.JSONDecodeError) as exc:
        raise SmokeToolError(f"cannot parse terminal Ledger: {exc}") from exc
    approvals = [record for record in records if record.get("event") == "gate.approved"]
    approval_steps = [record.get("data", {}).get("step") for record in approvals]
    if approval_steps != [1, 2]:
        raise SmokeToolError(f"happy run must approve exactly steps [1, 2], got {approval_steps}")
    attempt_ids = [record.get("data", {}).get("attempt_id") for record in approvals]
    if any(not isinstance(item, str) or not item for item in attempt_ids) or len(set(attempt_ids)) != 2:
        raise SmokeToolError("happy run approvals must have two distinct nonempty attempt IDs")
    forbidden = [
        record.get("event")
        for record in records
        if record.get("event") in {"tripwire.fired", "gate.denied", "weights.load_failed"}
    ]
    if forbidden:
        raise SmokeToolError(f"happy run contains fail-closed events: {forbidden}")
    for approval in approvals:
        data = approval["data"]
        matches = [
            record
            for record in records
            if record.get("event") == "policy.promoted"
            and record.get("data", {}).get("attempt_id") == data["attempt_id"]
            and record.get("data", {}).get("step") == data["step"]
        ]
        if len(matches) != 1:
            raise SmokeToolError(f"approval step {data['step']} does not have exactly one successful outcome")
    promoted_steps = [
        record.get("data", {}).get("step") for record in records if record.get("event") == "policy.promoted"
    ]
    if promoted_steps != [1, 2]:
        raise SmokeToolError(f"happy run must promote exactly steps [1, 2], got {promoted_steps}")
    exits = [record for record in records if record.get("event") == "run.exited"]
    if len(exits) != 1 or exits[0].get("data", {}).get("status") != "success":
        raise SmokeToolError("Ledger does not contain exactly one successful run.exited record")


def _child_env(args: argparse.Namespace) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key in SAFE_ENV_KEYS}
    venv_dir = Path(args.venv_dir).absolute() if args.venv_dir else Path(args.prime_rl).absolute() / ".venv"
    inherited_path = env.get("PATH", "/usr/bin:/bin")
    payload_bin = Path(args.payload_dir).absolute() / "bin"
    hf_home = Path(args.hf_home).absolute()
    env["PATH"] = f"{payload_bin}:{venv_dir / 'bin'}:{inherited_path}"
    env.update(
        {
            "HOME": str(hf_home / "filiolae-harness-home"),
            "CUDA_VISIBLE_DEVICES": "0,1",
            "FILIOLAE_CHARTER": str(Path(args.payload_dir).absolute() / "charter.yaml"),
            "FILIOLAE_LOCAL_ANCHOR_PRIVATE_KEY": str(Path(args.anchor_private_key).absolute()),
            "FILIOLAE_LOCAL_ANCHOR_DIR": str(Path(args.anchor_dir).absolute()),
            "HF_HUB_OFFLINE": "1",
            "HF_DATASETS_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "UV_OFFLINE": "1",
            "UV_CACHE_DIR": str(hf_home / "filiolae-uv-cache"),
            "XDG_CONFIG_HOME": str(hf_home / "filiolae-xdg-config"),
            "WANDB_MODE": "offline",
        }
    )
    if args.hf_home:
        env["HF_HOME"] = str(Path(args.hf_home).absolute())
    torch_home = getattr(args, "torch_home", None)
    if torch_home:
        env["TORCH_HOME"] = str(Path(torch_home).absolute())
    return env


def _environment_evidence(env: dict[str, str]) -> dict[str, str]:
    evidence = dict(sorted(env.items()))
    if "FILIOLAE_LOCAL_ANCHOR_PRIVATE_KEY" in evidence:
        evidence["FILIOLAE_LOCAL_ANCHOR_PRIVATE_KEY"] = "[PATH REDACTED]"
    return evidence


def run_happy(args: argparse.Namespace) -> int:
    state_dir = Path(args.state_dir).absolute()
    if state_dir.exists():
        raise SmokeToolError(f"fresh state directory required: {state_dir}")
    absolute_no_symlinks(state_dir.parent)
    state_dir.mkdir(mode=0o700)
    absolute_no_symlinks(state_dir)
    state_path = state_dir / "run-state.json"
    started = datetime.now(UTC).isoformat()
    _write_state(
        state_path,
        schema="filiolae.two-gpu-run-state.v1",
        run_id=args.run_id,
        profile="happy",
        status="preflight",
        terminal=False,
        runner_pid=os.getpid(),
        runner_start_token=process_start_token(os.getpid()),
        started_at=started,
        containment="POSIX process group only; not a systemd/cgroup containment claim",
    )
    preflight_script = Path(args.payload_dir).absolute() / "bin" / "remote_preflight.py"
    preflight_report = state_dir / "remote-preflight.json"
    preflight_command = [
        sys.executable,
        str(preflight_script),
        "--payload-dir",
        str(Path(args.payload_dir).absolute()),
        "--prime-rl",
        str(Path(args.prime_rl).absolute()),
        "--run-id",
        args.run_id,
        "--profile",
        "happy",
        "--output",
        str(Path(args.output).absolute()),
        "--anchor-private-key",
        str(Path(args.anchor_private_key).absolute()),
        "--anchor-dir",
        str(Path(args.anchor_dir).absolute()),
        "--report",
        str(preflight_report),
        "--hf-home",
        str(Path(args.hf_home).absolute()),
    ]
    if args.bootstrap_source:
        preflight_command += ["--bootstrap-source"]
    if args.venv_dir:
        preflight_command += ["--venv-dir", str(Path(args.venv_dir).absolute())]
    if args.bootstrap_frozen:
        preflight_command += ["--bootstrap-frozen", "--bootstrap-timeout", str(args.bootstrap_timeout)]
    if args.prefetch_model:
        preflight_command += ["--prefetch-model", "--prefetch-timeout", str(args.prefetch_timeout)]
    if args.prefetch_dataset:
        preflight_command += ["--prefetch-dataset", "--prefetch-timeout", str(args.prefetch_timeout)]
    if args.prefetch_harness:
        preflight_command += ["--prefetch-harness", "--prefetch-timeout", str(args.prefetch_timeout)]
    for path in args.require_path:
        preflight_command += ["--require-path", str(Path(path).absolute())]
    try:
        preflight = run_checked(preflight_command, timeout=args.preflight_timeout)
        (state_dir / "remote-preflight.stdout.json").write_text(preflight.stdout)
    except BaseException as exc:
        _write_state(
            state_path,
            status="preflight_failed",
            terminal=True,
            finished_at=datetime.now(UTC).isoformat(),
            error=repr(exc),
        )
        raise

    output = Path(args.output).absolute()
    run_output = prime_run_output(output)
    payload = Path(args.payload_dir).absolute()
    venv_dir = Path(args.venv_dir).absolute() if args.venv_dir else Path(args.prime_rl).absolute() / ".venv"
    filiolae = str(venv_dir / "bin" / "filiolae")
    filiolae_rl = str(venv_dir / "bin" / "filiolae-rl")
    command = [
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
        str(payload / "smoke.toml"),
        "--output-dir",
        str(output),
    ]
    log_path = state_dir / "governed-run.log"
    env = _child_env(args)
    _write_state(
        state_path,
        status="running",
        command=command,
        resolved_run_output=str(run_output),
        child_environment=_environment_evidence(env),
    )
    received_signal: list[int | None] = [None]
    process: subprocess.Popen[bytes] | None = None
    previous: dict[int, object] = {}

    def handle_signal(signum: int, frame: object) -> None:
        del frame
        received_signal[0] = signum
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGTERM)

    for item in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        previous[item] = signal.getsignal(item)
        signal.signal(item, handle_signal)
    execution_error: BaseException | None = None
    try:
        with log_path.open("wb") as log:
            if received_signal[0] is not None:
                raise SmokeToolError("happy run cancelled before governed process launch")
            process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
            if received_signal[0] is not None and process.poll() is None:
                process.terminate()
            returncode = process.wait()
    except BaseException as exc:
        execution_error = exc
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    finally:
        for item, handler in previous.items():
            signal.signal(item, handler)
    if execution_error is not None:
        _write_state(
            state_path,
            status="execution_failed",
            terminal=True,
            signal_received=received_signal[0],
            finished_at=datetime.now(UTC).isoformat(),
            error=repr(execution_error),
        )
        raise SmokeToolError("happy governed process failed before validation") from execution_error
    status = "run_exited" if returncode == 0 else "run_failed"
    _write_state(
        state_path,
        status=status,
        governed_returncode=returncode,
        signal_received=received_signal[0],
    )

    ledger = run_output / "control" / "filiolae" / "ledger.jsonl"
    artifacts = run_output / "control" / "filiolae" / "artifacts"
    copied_charter = run_output / "control" / "filiolae" / "charter.yaml"
    public_key = payload / "anchor-public.pem"
    audit_command = [
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
        str(public_key),
    ]
    audit_result: subprocess.CompletedProcess[str] | None = None
    audit_error: str | None = None
    try:
        audit_result = run_checked(audit_command, timeout=args.audit_timeout)
        (state_dir / "audit.json").write_text(audit_result.stdout)
        anchors = run_checked(
            [
                filiolae,
                "verify-anchors",
                str(ledger),
                "--artifact-root",
                str(artifacts),
                "--anchor-dir",
                str(Path(args.anchor_dir).absolute()),
                "--public-key",
                str(public_key),
            ],
            timeout=args.audit_timeout,
        )
        (state_dir / "verify-anchors.json").write_text(anchors.stdout)
        _validate_ledger(ledger)
        resolved = run_output / "control" / "orch.toml"
        resolved_config = tomllib.loads(resolved.read_text())
        if resolved_config.get("weight_broadcast", {}).get("type") != "filesystem":
            raise SmokeToolError("resolved config did not retain filesystem weight broadcasting")
        if (run_output / "control" / "filiolae" / "freeze.json").exists():
            raise SmokeToolError("freeze marker exists after purported happy run")
    except BaseException as exc:
        audit_error = repr(exc)

    success = returncode == 0 and audit_error is None and received_signal[0] is None
    _write_state(
        state_path,
        status="success" if success else "failed",
        terminal=True,
        audit_ok=audit_error is None,
        audit_error=audit_error,
        finished_at=datetime.now(UTC).isoformat(),
    )
    return 0 if success else (returncode if returncode != 0 else 1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload-dir", required=True)
    parser.add_argument("--prime-rl", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--anchor-private-key", required=True)
    parser.add_argument("--anchor-dir", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--venv-dir", help="default: PRIME_RL/.venv")
    parser.add_argument("--bootstrap-source", action="store_true")
    parser.add_argument(
        "--bootstrap-frozen",
        action="store_true",
        help="use frozen prime-rl + reverse-text-v1 sync; never --locked",
    )
    parser.add_argument("--bootstrap-timeout", type=int, default=900)
    parser.add_argument("--prefetch-model", action="store_true")
    parser.add_argument("--prefetch-dataset", action="store_true")
    parser.add_argument("--prefetch-harness", action="store_true")
    parser.add_argument("--prefetch-timeout", type=int, default=900)
    parser.add_argument("--hf-home", required=True)
    parser.add_argument("--torch-home")
    parser.add_argument("--require-path", action="append", default=[])
    parser.add_argument("--wall-seconds", type=int, default=1800)
    parser.add_argument("--kill-after-seconds", type=int, default=30)
    parser.add_argument("--preflight-timeout", type=int, default=2400)
    parser.add_argument("--audit-timeout", type=int, default=600)
    args = parser.parse_args()
    if args.wall_seconds < 60 or args.kill_after_seconds < 5:
        parser.error("unsafe timeout values")
    return args


def main() -> int:
    try:
        return run_happy(parse_args())
    except SmokeToolError as exc:
        print(f"happy smoke failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
