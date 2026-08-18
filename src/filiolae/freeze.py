"""Irreversible, supervisor-owned freeze marker for fail-closed operation."""

from __future__ import annotations

import json
import os
import stat
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .canonical import canonical_json


@dataclass(frozen=True)
class FreezeState:
    frozen: bool
    reason: str | None = None
    details: dict[str, Any] | None = None
    ts: str | None = None


class FreezeController:
    def __init__(self, path: str | Path, *, clock: Callable[[], datetime] | None = None) -> None:
        self.path = Path(path).absolute()
        self.clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()
        self._latched: FreezeState | None = None

    def _latch_invalid(self) -> FreezeState:
        self._latched = FreezeState(True, reason="invalid freeze marker", details={})
        return self._latched

    def state(self) -> FreezeState:
        with self._lock:
            if self._latched is not None:
                return self._latched
            try:
                before = os.lstat(self.path)
            except FileNotFoundError:
                return FreezeState(False)
            except OSError:
                return self._latch_invalid()
            if not stat.S_ISREG(before.st_mode):
                return self._latch_invalid()
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(self.path, flags)
                try:
                    after = os.fstat(descriptor)
                    if (
                        (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                        or after.st_nlink != 1
                        or after.st_size > 1024 * 1024
                    ):
                        return self._latch_invalid()
                    chunks: list[bytes] = []
                    while chunk := os.read(descriptor, 65536):
                        chunks.append(chunk)
                    final = os.fstat(descriptor)
                    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                        final.st_dev,
                        final.st_ino,
                        final.st_size,
                        final.st_mtime_ns,
                    ):
                        return self._latch_invalid()
                finally:
                    os.close(descriptor)
                data = b"".join(chunks)
                value = json.loads(data)
                if (
                    not isinstance(value, dict)
                    or set(value) != {"schema", "ts", "reason", "details"}
                    or value["schema"] != "filiolae.freeze.v1"
                    or not isinstance(value["reason"], str)
                    or not value["reason"]
                    or not isinstance(value["details"], dict)
                    or not isinstance(value["ts"], str)
                    or canonical_json(value) + b"\n" != data
                ):
                    return self._latch_invalid()
                timestamp = datetime.fromisoformat(value["ts"].replace("Z", "+00:00"))
                if (
                    not value["ts"].endswith("Z")
                    or timestamp.tzinfo is None
                    or timestamp.utcoffset() != UTC.utcoffset(timestamp)
                ):
                    return self._latch_invalid()
                state = FreezeState(
                    frozen=True,
                    reason=value["reason"],
                    details=value["details"],
                    ts=value["ts"],
                )
            except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
                return self._latch_invalid()
            self._latched = state
            return state

    def freeze(self, reason: str, *, details: dict[str, Any] | None = None) -> FreezeState:
        if not reason:
            raise ValueError("freeze reason is required")
        with self._lock:
            if self._latched is not None:
                return self._latched
            self.path.parent.mkdir(parents=True, exist_ok=True)
            timestamp = self.clock().astimezone(UTC).isoformat().replace("+00:00", "Z")
            payload = {
                "schema": "filiolae.freeze.v1",
                "ts": timestamp,
                "reason": reason,
                "details": details or {},
            }
            data = canonical_json(payload) + b"\n"
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(self.path, flags, 0o600)
            except FileExistsError:
                return self.state()
            try:
                offset = 0
                while offset < len(data):
                    offset += os.write(descriptor, data[offset:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory = os.open(self.path.parent, directory_flags)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            self._latched = FreezeState(True, reason=reason, details=details or {}, ts=timestamp)
            return self._latched
