#!/usr/bin/env python3
"""Authorized game-day helper: corrupt the exact step-1 Gate-staged candidate after promotion."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from common import SmokeToolError, absolute_no_symlinks, fsync_directory, require_regular_file


def _records(path: Path) -> list[dict[str, object]]:
    lines = path.read_bytes().splitlines()
    records: list[dict[str, object]] = []
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            if index == len(lines) - 1:
                break
            raise SmokeToolError(f"malformed non-terminal Ledger line {index + 1}: {exc}") from exc
        if not isinstance(value, dict):
            raise SmokeToolError(f"Ledger line {index + 1} is not an object")
        records.append(value)
    return records


def _candidate_after_step_one(records: list[dict[str, object]]) -> dict[str, object] | None:
    promotions = [
        record
        for record in records
        if record.get("event") == "policy.promoted" and record.get("data", {}).get("step") == 1
    ]
    if not promotions:
        return None
    if len(promotions) != 1:
        raise SmokeToolError("expected exactly one policy.promoted record for step 1")
    published = [
        record
        for record in records
        if record.get("event") == "weights.published" and record.get("data", {}).get("step") == 1
    ]
    if len(published) != 1:
        raise SmokeToolError("expected exactly one weights.published record for step 1")
    if not isinstance(published[0].get("seq"), int) or published[0]["seq"] >= promotions[0].get("seq", -1):
        raise SmokeToolError("step-1 publication does not precede promotion")
    artifacts = published[0].get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        raise SmokeToolError("step-1 publication does not bind exactly one artifact")
    artifact = artifacts[0]
    if not isinstance(artifact, dict) or artifact.get("name") != "candidate_weights":
        raise SmokeToolError("step-1 publication artifact is not candidate_weights")
    return artifact


def _choose_target(root: Path, artifact: dict[str, object]) -> Path:
    relative = artifact.get("path")
    if not isinstance(relative, str) or relative.startswith(("/", "../")) or "/../" in relative:
        raise SmokeToolError("unsafe candidate artifact path")
    candidate = root / relative
    absolute_no_symlinks(candidate)
    if not candidate.resolve().is_relative_to(root.resolve()):
        raise SmokeToolError("candidate artifact escapes artifact root")
    if candidate.is_file():
        choices = [candidate]
    elif candidate.is_dir():
        choices = []
        for base, directories, files in os.walk(candidate, followlinks=False):
            base_path = Path(base)
            for name in [*directories, *files]:
                item = base_path / name
                info = item.lstat()
                if stat.S_ISLNK(info.st_mode):
                    raise SmokeToolError(f"symlink rejected in candidate: {item}")
                if stat.S_ISREG(info.st_mode) and info.st_size > 0 and name != "STABLE":
                    choices.append(item)
                elif not stat.S_ISDIR(info.st_mode) and not stat.S_ISREG(info.st_mode):
                    raise SmokeToolError(f"special file rejected in candidate: {item}")
    else:
        raise SmokeToolError("candidate artifact is neither a regular file nor a directory")
    if not choices:
        raise SmokeToolError("candidate artifact has no nonempty regular weight file")
    preferred = [item for item in choices if item.suffix in {".safetensors", ".bin", ".pt"}]
    return sorted(preferred or choices)[0]


def _sha256_fd(descriptor: int, size: int, chunk_size: int = 1024 * 1024) -> str:
    digest = __import__("hashlib").sha256()
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(chunk_size, size - offset), offset)
        if not chunk:
            raise SmokeToolError("short read while hashing tamper target")
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _exclusive_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise SmokeToolError("short write while recording tamper operation")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    fsync_directory(path.parent)


def tamper(args: argparse.Namespace) -> dict[str, object]:
    ledger = Path(args.ledger).absolute()
    artifact_root = Path(args.artifact_root).absolute()
    operator_log = Path(args.operator_log).absolute()
    absolute_no_symlinks(operator_log.parent)
    if operator_log.exists():
        raise SmokeToolError(f"operator log already exists; refusing replay: {operator_log}")
    if operator_log.resolve(strict=False).is_relative_to(artifact_root.resolve()):
        raise SmokeToolError("operator log must be outside the artifact store")
    deadline = time.monotonic() + args.timeout_seconds
    artifact: dict[str, object] | None = None
    while time.monotonic() < deadline:
        if not ledger.exists() or not artifact_root.exists():
            time.sleep(min(args.poll_seconds, max(0.0, deadline - time.monotonic())))
            continue
        require_regular_file(ledger)
        absolute_no_symlinks(artifact_root)
        artifact = _candidate_after_step_one(_records(ledger))
        if artifact is not None:
            break
        time.sleep(min(args.poll_seconds, max(0.0, deadline - time.monotonic())))
    if artifact is None:
        raise SmokeToolError("timed out waiting for policy.promoted step 1")
    target = _choose_target(artifact_root, artifact)
    path_info = target.lstat()
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size < 1
            or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)
        ):
            raise SmokeToolError("selected tamper target changed identity/type or became empty")
        before = _sha256_fd(descriptor, info.st_size)
        original = os.pread(descriptor, 1, 0)
        if len(original) != 1:
            raise SmokeToolError("could not read first target byte")
        replacement = bytes([original[0] ^ 0x01])
        if os.pwrite(descriptor, replacement, 0) != 1:
            raise SmokeToolError("short tamper write")
        os.fsync(descriptor)
        after = _sha256_fd(descriptor, info.st_size)
        final_path_info = target.lstat()
        if (final_path_info.st_dev, final_path_info.st_ino) != (info.st_dev, info.st_ino):
            raise SmokeToolError("tamper target pathname changed during operation")
    finally:
        os.close(descriptor)
    if before == after:
        raise SmokeToolError("tamper did not change the file digest")
    report: dict[str, object] = {
        "schema": "filiolae.two-gpu-tamper-operation.v1",
        "ts": datetime.now(UTC).isoformat(),
        "authorized_game_day": True,
        "ledger_modified": False,
        "target": str(target),
        "target_relative_to_artifact_root": target.relative_to(artifact_root).as_posix(),
        "sha256_before": before,
        "sha256_after": after,
        "operation": "xor low bit of byte at offset 0 in place; fsync",
    }
    _exclusive_json(operator_log, report)
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--operator-log", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=300)
    parser.add_argument("--poll-seconds", type=float, default=0.2)
    args = parser.parse_args()
    if args.timeout_seconds <= 0 or not 0 < args.poll_seconds <= 5:
        parser.error("invalid timing values")
    return args


def main() -> int:
    try:
        report = tamper(parse_args())
    except SmokeToolError as exc:
        print(f"tamper helper failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
