#!/usr/bin/env python3
"""Test-only governed orchestrator for the native systemd containment game day."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from filiolae.prime_rl_entrypoint import _build_barrier
from filiolae.update_control import WeightUpdateController


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def atomic_json(path: Path, body: dict[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def process_identity() -> dict[str, object]:
    return {
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "sid": os.getsid(0),
        "pgid": os.getpgrp(),
        "uid": os.getuid(),
        "gid": os.getgid(),
        "groups": os.getgroups(),
        "cgroup": Path("/proc/self/cgroup").read_text(),
        "timestamp": utc_now(),
    }


def hostile_child(identity_path: Path) -> int:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    atomic_json(identity_path, process_identity())
    while True:
        time.sleep(60)


def prepare_step(output: Path) -> Path:
    resolved = output / "control" / "orch.toml"
    resolved.write_text("# game-day resolved orchestrator configuration\nmax_steps = 1\n")
    weights = output / "broadcasts" / "step_1"
    weights.mkdir(parents=True, exist_ok=False)
    (weights / "model.safetensors").write_bytes(b"filiolae-native-systemd-game-day-candidate\n")
    (weights / "STABLE").write_text("ready\n")
    traces = output / "rollouts" / "step_1" / "train" / "effective" / "traces.jsonl"
    traces.parent.mkdir(parents=True, exist_ok=False)
    traces.write_text('{"reward":1,"source":"native-systemd-game-day"}\n')
    return weights


async def approve(barrier: object, output: Path, state: Path, attempt: int) -> None:
    weights = output / "broadcasts" / "step_1"
    if not weights.exists():
        weights = prepare_step(output)
    callback = state / "load-called.json"

    async def load(approved: Path) -> None:
        atomic_json(
            callback,
            {
                "approved_path": str(approved),
                "candidate_sha256": hashlib.sha256((approved / "model.safetensors").read_bytes()).hexdigest(),
                "identity": process_identity(),
            },
        )

    result_path = state / f"approve-{attempt}-result.json"
    try:
        approved = await WeightUpdateController(barrier, authorization_timeout=8, outcome_timeout=8).apply(
            step=1,
            current_policy_version=0,
            trainer_weights_path=weights,
            update_weights=load,
        )
        body: dict[str, object] = {
            "ok": True,
            "approved_path": str(approved),
            "identity": process_identity(),
        }
    except BaseException as exc:
        body = {
            "ok": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "identity": process_identity(),
        }
    atomic_json(result_path, body)


async def reconcile(barrier: object, state: Path, attempt: int) -> None:
    result_path = state / f"reconcile-{attempt}-result.json"
    try:
        receipt = await asyncio.to_thread(barrier.gate.anchor_current_head)
        body: dict[str, object] = {
            "ok": True,
            "receipt_sha256": receipt.receipt_sha256() if receipt is not None else None,
            "identity": process_identity(),
        }
    except BaseException as exc:
        body = {
            "ok": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "identity": process_identity(),
        }
    atomic_json(result_path, body)


async def orchestrator(run_id: str) -> int:
    output = Path("/srv/filiolae/runs") / run_id
    state = output / "game-day"
    commands = state / "commands"
    state.mkdir(mode=0o750)
    commands.mkdir(mode=0o750)

    config = SimpleNamespace(
        output_dir=output,
        weight_broadcast=SimpleNamespace(type="filesystem"),
        ckpt=SimpleNamespace(resume_step=None),
    )
    barrier = await asyncio.to_thread(_build_barrier, config)
    child_identity = state / "hostile-child.json"
    child = subprocess.Popen(
        [sys.executable, __file__, "--hostile-child", str(child_identity)],
        start_new_session=True,
    )
    deadline = time.monotonic() + 10
    while not child_identity.exists() and child.poll() is None and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    if not child_identity.exists() or child.poll() is not None:
        raise RuntimeError("hostile setsid descendant did not become ready")
    atomic_json(
        state / "ready.json",
        {
            "schema": "filiolae.systemd-orchestrator-harness.v1",
            "run_id": run_id,
            "identity": process_identity(),
            "hostile_child": json.loads(child_identity.read_text()),
            "ledger": str(barrier.gate.ledger.path),
            "timestamp": utc_now(),
        },
    )

    processed: set[str] = set()
    approve_attempt = 0
    reconcile_attempt = 0
    while True:
        for command in sorted(commands.glob("*.command")):
            if command.name in processed:
                continue
            processed.add(command.name)
            action = command.read_text().strip()
            if action == "approve":
                approve_attempt += 1
                await approve(barrier, output, state, approve_attempt)
            elif action == "reconcile":
                reconcile_attempt += 1
                await reconcile(barrier, state, reconcile_attempt)
            elif action == "stop":
                atomic_json(state / "stopping.json", process_identity())
                return 0
            else:
                atomic_json(
                    state / f"invalid-{len(processed)}.json",
                    {"action": action, "identity": process_identity()},
                )
        await asyncio.sleep(0.05)


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--hostile-child":
        return hostile_child(Path(sys.argv[2]))
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} RUN_ID", file=sys.stderr)
        return 64
    return asyncio.run(orchestrator(sys.argv[1]))


if __name__ == "__main__":
    raise SystemExit(main())
