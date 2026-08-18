#!/usr/bin/env python3
"""Create one pre-authorized Prime pod and arm its exact-ID deadline watchdog.

This narrow helper has no workload operation. It fails closed by terminating every
exact pod ID attributable to its unique requested name if creation or watchdog
arming is incomplete.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


class CreatorError(RuntimeError):
    """A fail-closed creator error."""


SAFE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
CREATE_ID = re.compile(r"(?m)^Successfully created pod ([A-Za-z0-9][A-Za-z0-9._-]{0,127})$")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_created_at(value: Any) -> dt.datetime:
    if not isinstance(value, str):
        raise CreatorError("pod record lacks a created_at string")
    if value.endswith(" UTC"):
        normalized = value.removesuffix(" UTC") + "+00:00"
    else:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise CreatorError("pod record has an invalid created_at timestamp") from exc
    if parsed.tzinfo is None:
        raise CreatorError("pod created_at timestamp has no timezone")
    return parsed.astimezone(dt.UTC)


def parse_created_pod_id(stdout: str) -> str:
    matches = CREATE_ID.findall(stdout)
    if len(matches) != 1:
        raise CreatorError("create output did not contain exactly one full pod ID")
    return matches[0]


def atomic_write(path: Path, content: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
        os.chmod(path, mode)
    finally:
        if temporary is not None:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)


def run(
    argv: list[str],
    *,
    timeout: float = 180,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CreatorError(f"command failed to execute: {argv[0]}") from exc
    if check and completed.returncode != 0:
        raise CreatorError(f"command failed with exit {completed.returncode}: {argv[0]}")
    return completed


def prime_json(prime_bin: str, args: list[str]) -> dict[str, Any]:
    completed = run([prime_bin, "--plain", *args])
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CreatorError("Prime CLI did not return valid JSON") from exc
    if not isinstance(value, dict):
        raise CreatorError("Prime CLI returned a non-object JSON value")
    return value


def list_active(prime_bin: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    offset = 0
    for _ in range(20):
        data = prime_json(
            prime_bin,
            ["pods", "list", "--limit", "100", "--offset", str(offset), "--output", "json"],
        )
        rows = data.get("pods")
        total = data.get("total_count")
        if not isinstance(rows, list) or not isinstance(total, int) or total < 0:
            raise CreatorError("Prime active-pod response has an invalid shape")
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                raise CreatorError("Prime active-pod response contains an invalid record")
            if not SAFE_TOKEN.fullmatch(row["id"]):
                raise CreatorError("Prime active-pod response contains an unsafe ID")
            result.append(row)
        offset += len(rows)
        if offset >= total:
            return result
        if not rows:
            raise CreatorError("Prime active-pod pagination made no progress")
    raise CreatorError("Prime active-pod pagination exceeded its safety bound")


def write_json(path: Path, value: Any) -> None:
    atomic_write(path, json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prime-bin", required=True)
    parser.add_argument("--controller", required=True, type=Path)
    parser.add_argument("--controller-sha256", required=True)
    parser.add_argument("--watchdog-template", required=True, type=Path)
    parser.add_argument("--watchdog-template-sha256", required=True)
    parser.add_argument("--watchdog-environment-dir", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--life-dir", required=True, type=Path)
    parser.add_argument("--availability-id", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--image", default="ubuntu_22_cuda_12")
    parser.add_argument("--disk-size", type=int, default=256)
    parser.add_argument("--maximum-hours", type=float, default=3.0)
    args = parser.parse_args(argv)

    if not SAFE_TOKEN.fullmatch(args.availability_id) or not SAFE_TOKEN.fullmatch(args.name):
        parser.error("availability ID and name must be full safe tokens")
    if not SHA256.fullmatch(args.controller_sha256):
        parser.error("controller digest must be lowercase SHA-256")
    if not SHA256.fullmatch(args.watchdog_template_sha256):
        parser.error("watchdog template digest must be lowercase SHA-256")
    if args.maximum_hours != 3.0:
        parser.error("this authorization-bound creator requires exactly 3 maximum hours")
    if args.disk_size != 256:
        parser.error("this execution packet requires exactly 256 GiB disk")

    life = args.life_dir.resolve()
    life.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(life, 0o700)
    controller = args.controller.resolve(strict=True)
    template = args.watchdog_template.resolve(strict=True)
    if sha256_file(controller) != args.controller_sha256:
        raise CreatorError("content-addressed controller digest mismatch")
    if sha256_file(template) != args.watchdog_template_sha256:
        raise CreatorError("watchdog template digest mismatch")

    pod_id: str | None = None
    armed = False
    success = False
    cleanup_results: list[dict[str, Any]] = []

    def interrupted(signum: int, _frame: Any) -> None:
        raise CreatorError(f"creator interrupted by signal {signum}")

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)

    try:
        before = list_active(args.prime_bin)
        write_json(life / "active-before.json", {"pods": before, "total_count": len(before)})
        if before:
            raise CreatorError("replacement creation requires zero active pods")

        started_at = dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")
        write_json(
            life / "creator-start.json",
            {
                "availability_id": args.availability_id,
                "controller_sha256": args.controller_sha256,
                "maximum_hours": args.maximum_hours,
                "name": args.name,
                "schema": "filiolae.priority6-v2-replacement-creator-start.v1",
                "started_at": started_at,
                "watchdog_template_sha256": args.watchdog_template_sha256,
            },
        )
        created = run(
            [
                args.prime_bin,
                "--plain",
                "pods",
                "create",
                "--id",
                args.availability_id,
                "--name",
                args.name,
                "--image",
                args.image,
                "--disk-size",
                str(args.disk_size),
                "--yes",
            ]
        )
        atomic_write(life / "create.stdout", created.stdout.encode())
        atomic_write(life / "create.stderr", created.stderr.encode())
        pod_id = parse_created_pod_id(created.stdout)
        atomic_write(life / "POD_ID", f"{pod_id}\n".encode())

        exact: dict[str, Any] | None = None
        for _ in range(30):
            rows = list_active(args.prime_bin)
            matching_name = [row for row in rows if row.get("name") == args.name]
            matching_id = [row for row in rows if row.get("id") == pod_id]
            if len(matching_name) > 1 or len(matching_id) > 1:
                raise CreatorError("created pod identity is ambiguous")
            if matching_id:
                if matching_id[0].get("name") != args.name or matching_name != matching_id:
                    raise CreatorError("created pod name and full ID do not resolve to one record")
                exact = matching_id[0]
                break
            time.sleep(2)
        if exact is None:
            raise CreatorError("created full pod ID did not appear in the active inventory")
        write_json(life / "selected-pod.json", exact)

        created_at = parse_created_at(exact.get("created_at"))
        deadline = created_at + dt.timedelta(hours=args.maximum_hours)
        deadline_text = deadline.isoformat().replace("+00:00", "Z")
        environment = args.watchdog_environment_dir.resolve() / f"{pod_id}.env"
        atomic_write(environment, f"DEADLINE_UTC={deadline_text}\n".encode())

        unit = f"filiolae-prime-watchdog@{pod_id}.service"
        run(["systemctl", "--user", "enable", "--now", unit], timeout=60)
        for _ in range(20):
            state = run(["systemctl", "--user", "show", unit, "-p", "ActiveState", "--value"]).stdout.strip()
            pid = run(["systemctl", "--user", "show", unit, "-p", "MainPID", "--value"]).stdout.strip()
            if state == "active" and pid.isdecimal() and int(pid) > 0:
                armed = True
                break
            time.sleep(1)
        if not armed:
            raise CreatorError("exact-ID persistent watchdog did not become active")

        exact_status = run(
            [
                str(controller),
                "--prime-bin",
                args.prime_bin,
                "--state-dir",
                str(args.state_dir.resolve()),
                "status",
                "--pod-id",
                pod_id,
            ]
        )
        status_value = json.loads(exact_status.stdout)
        if status_value.get("id") != pod_id:
            raise CreatorError("controller status did not return the exact created ID")
        write_json(life / "exact-status.json", status_value)
        write_json(
            life / "ARMED.json",
            {
                "armed_at": dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z"),
                "deadline": deadline_text,
                "main_pid": int(pid),
                "pod_id": pod_id,
                "schema": "filiolae.priority6-v2-exact-watchdog-armed.v1",
                "unit": unit,
            },
        )
        success = True
        return 0
    except Exception as exc:
        write_json(
            life / "CREATOR-ERROR.json",
            {
                "error": type(exc).__name__,
                "message": str(exc),
                "pod_id": pod_id,
                "schema": "filiolae.priority6-v2-replacement-creator-error.v1",
            },
        )
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    finally:
        if not success:
            attributable: set[str] = set()
            if pod_id is not None:
                attributable.add(pod_id)
            try:
                for row in list_active(args.prime_bin):
                    if row.get("name") == args.name:
                        attributable.add(row["id"])
            except Exception as exc:
                cleanup_results.append({"error": type(exc).__name__, "stage": "inventory"})
            for exact_id in sorted(attributable):
                completed = run(
                    [
                        str(controller),
                        "--prime-bin",
                        args.prime_bin,
                        "--state-dir",
                        str(args.state_dir.resolve()),
                        "terminate",
                        "--pod-id",
                        exact_id,
                        "--wait-seconds",
                        "180",
                        "--poll-seconds",
                        "5",
                        "--yes",
                    ],
                    timeout=240,
                    check=False,
                )
                cleanup_results.append(
                    {
                        "id": exact_id,
                        "returncode": completed.returncode,
                        "stdout": completed.stdout.strip(),
                    }
                )
                unit = f"filiolae-prime-watchdog@{exact_id}.service"
                run(["systemctl", "--user", "disable", "--now", unit], timeout=60, check=False)
                environment = args.watchdog_environment_dir.resolve() / f"{exact_id}.env"
                with contextlib.suppress(FileNotFoundError):
                    environment.unlink()
            write_json(life / "FAIL-CLOSED-CLEANUP.json", cleanup_results)


if __name__ == "__main__":
    raise SystemExit(main())
