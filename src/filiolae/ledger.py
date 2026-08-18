"""Append-only, hash-chained JSONL Ledger."""

from __future__ import annotations

import fcntl
import json
import os
import stat
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .artifacts import Artifact, verify_artifact
from .canonical import canonical_json, sha256_json

SCHEMA = "filiolae.ledger.v1"
GENESIS_HASH = "0" * 64
RECORD_HASH_DOMAIN = b"filiolae-ledger-v1\0"


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


class LedgerError(RuntimeError):
    pass


class LedgerIntegrityError(LedgerError):
    pass


@dataclass(frozen=True)
class AuditIssue:
    code: str
    message: str
    seq: int | None = None


@dataclass(frozen=True)
class LedgerRecord:
    schema: str
    seq: int
    ts: str
    run_id: str
    event: str
    actor: str
    data: dict[str, Any]
    artifacts: tuple[Artifact, ...]
    prev_hash: str
    hash: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> LedgerRecord:
        required = {
            "schema",
            "seq",
            "ts",
            "run_id",
            "event",
            "actor",
            "data",
            "artifacts",
            "prev_hash",
            "hash",
        }
        if set(value) != required:
            missing = sorted(required - value.keys())
            extra = sorted(value.keys() - required)
            raise ValueError(f"record fields mismatch; missing={missing}, extra={extra}")
        if not isinstance(value["schema"], str):
            raise ValueError("schema must be a string")
        if isinstance(value["seq"], bool) or not isinstance(value["seq"], int) or value["seq"] < 0:
            raise ValueError("seq must be a non-negative integer")
        for field in ("ts", "run_id", "event", "actor", "prev_hash", "hash"):
            if not isinstance(value[field], str):
                raise ValueError(f"{field} must be a string")
        if not isinstance(value["data"], dict) or not isinstance(value["artifacts"], list):
            raise ValueError("data must be an object and artifacts must be an array")
        artifacts_list: list[Artifact] = []
        for item in value["artifacts"]:
            expected_artifact_fields = {"name", "path", "kind", "sha256", "size"}
            if not isinstance(item, dict) or set(item) != expected_artifact_fields:
                raise ValueError("artifact descriptor fields are invalid")
            if not all(isinstance(item[field], str) for field in ("name", "path", "kind", "sha256")):
                raise ValueError("artifact string fields are invalid")
            if isinstance(item["size"], bool) or not isinstance(item["size"], int) or item["size"] < 0:
                raise ValueError("artifact size must be a non-negative integer")
            artifacts_list.append(Artifact(**item))
        return cls(
            schema=value["schema"],
            seq=value["seq"],
            ts=value["ts"],
            run_id=value["run_id"],
            event=value["event"],
            actor=value["actor"],
            data=value["data"],
            artifacts=tuple(artifacts_list),
            prev_hash=value["prev_hash"],
            hash=value["hash"],
        )

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "seq": self.seq,
            "ts": self.ts,
            "run_id": self.run_id,
            "event": self.event,
            "actor": self.actor,
            "data": self.data,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "prev_hash": self.prev_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "hash": self.hash}

    def computed_hash(self) -> str:
        return sha256_json(self.unsigned_dict(), domain=RECORD_HASH_DOMAIN)


@dataclass(frozen=True)
class AuditReport:
    issues: tuple[AuditIssue, ...]
    records: tuple[LedgerRecord, ...]

    @property
    def ok(self) -> bool:
        return not self.issues

    def summary(self) -> str:
        if self.ok:
            return f"Ledger valid: {len(self.records)} record(s)"
        return "; ".join(f"{issue.code}@{issue.seq}: {issue.message}" for issue in self.issues)


def provision_ledger_lock(
    path: str | Path,
    *,
    mode: int = 0o660,
    gid: int | None = None,
) -> tuple[int, int]:
    """Create the fixed lock inode used by mutually distrustful service credentials."""
    if mode not in {0o600, 0o660}:
        raise LedgerError("Ledger lock mode must be 0600 or 0660")
    target = Path(os.path.abspath(path))
    parent_existed = target.parent.exists()
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    if not parent_existed and gid is not None:
        os.chown(target.parent, -1, gid, follow_symlinks=False)
        os.chmod(target.parent, 0o750, follow_symlinks=False)
    parent_info = target.parent.lstat()
    if not stat.S_ISDIR(parent_info.st_mode) or target.parent.is_symlink():
        raise LedgerError("Ledger lock parent must be a real directory")
    descriptor = os.open(
        target,
        os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        os.fchmod(descriptor, mode)
        if gid is not None:
            os.fchown(descriptor, -1, gid)
        os.fsync(descriptor)
        info = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return info.st_dev, info.st_ino


class Ledger:
    def __init__(
        self,
        path: str | Path,
        *,
        artifact_root: str | Path,
        clock: Callable[[], datetime] | None = None,
        lock_path: str | Path | None = None,
        require_existing_lock: bool = False,
    ) -> None:
        self.path = Path(path)
        self.artifact_root = Path(artifact_root)
        self.clock = clock or (lambda: datetime.now(UTC))
        self.lock_path = (
            Path(lock_path) if lock_path is not None else self.path.with_suffix(self.path.suffix + ".lock")
        )
        self.require_existing_lock = require_existing_lock

    @classmethod
    def create(
        cls,
        path: str | Path,
        *,
        artifact_root: str | Path,
        run_id: str,
        charter_sha256: str,
        metadata: dict[str, Any] | None = None,
        clock: Callable[[], datetime] | None = None,
        lock_path: str | Path | None = None,
        require_existing_lock: bool = False,
    ) -> Ledger:
        ledger = cls(
            path,
            artifact_root=artifact_root,
            clock=clock,
            lock_path=lock_path,
            require_existing_lock=require_existing_lock,
        )
        ledger.path.parent.mkdir(parents=True, exist_ok=True)
        if ledger.path.exists() and ledger.path.stat().st_size:
            raise LedgerError(f"refusing to overwrite existing Ledger: {ledger.path}")
        ledger.append(
            "run.genesis",
            actor="human:owner",
            data={"charter_sha256": charter_sha256, "metadata": metadata or {}},
            expected_run_id=run_id,
        )
        directory = os.open(
            ledger.path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return ledger

    @staticmethod
    def _read_descriptor(descriptor: int) -> bytes:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        return b"".join(chunks)

    def _read_unlocked(self) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags)
        except FileNotFoundError:
            return b""
        except OSError as exc:
            raise LedgerIntegrityError(f"cannot safely open Ledger: {exc}") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise LedgerIntegrityError("Ledger must be a singly-linked regular file")
            path_info = self.path.lstat()
            if (path_info.st_dev, path_info.st_ino) != (info.st_dev, info.st_ino):
                raise LedgerIntegrityError("Ledger path changed while opening")
            content = self._read_descriptor(descriptor)
            final_path_info = self.path.lstat()
            if (final_path_info.st_dev, final_path_info.st_ino) != (info.st_dev, info.st_ino):
                raise LedgerIntegrityError("Ledger path changed while reading")
            return content
        except FileNotFoundError as exc:
            raise LedgerIntegrityError("Ledger path disappeared while reading") from exc
        finally:
            os.close(descriptor)

    def audit(self, *, verify_artifacts: bool = False) -> AuditReport:
        try:
            content = self._read_unlocked()
        except LedgerIntegrityError as exc:
            return AuditReport((AuditIssue("unsafe_ledger", str(exc)),), ())
        return self._audit_bytes(content, verify_artifacts=verify_artifacts)

    def _audit_bytes(self, content: bytes, *, verify_artifacts: bool) -> AuditReport:
        issues: list[AuditIssue] = []
        records: list[LedgerRecord] = []
        if not content:
            return AuditReport((AuditIssue("empty_ledger", "Ledger is empty"),), ())
        if not content.endswith(b"\n"):
            issues.append(AuditIssue("truncated_line", "Ledger does not end with a newline"))
        expected_hash = GENESIS_HASH
        expected_run_id: str | None = None
        for line_number, raw_line in enumerate(content.splitlines(), start=1):
            if not raw_line.strip():
                issues.append(AuditIssue("blank_line", f"blank line {line_number}"))
                continue
            try:
                value = json.loads(raw_line, object_pairs_hook=_strict_object)
                if not isinstance(value, dict):
                    raise ValueError("record is not an object")
                if canonical_json(value) != raw_line:
                    issues.append(
                        AuditIssue("noncanonical_record", f"line {line_number} is not canonical JSON")
                    )
                record = LedgerRecord.from_dict(value)
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                issues.append(AuditIssue("invalid_record", f"line {line_number}: {exc}"))
                continue
            records.append(record)
            expected_seq = len(records) - 1
            if record.schema != SCHEMA:
                issues.append(
                    AuditIssue("schema_mismatch", f"expected {SCHEMA}, got {record.schema}", record.seq)
                )
            if record.seq != expected_seq:
                issues.append(
                    AuditIssue("sequence_gap", f"expected {expected_seq}, got {record.seq}", record.seq)
                )
            if len(record.prev_hash) != 64 or any(
                char not in "0123456789abcdef" for char in record.prev_hash
            ):
                issues.append(
                    AuditIssue("invalid_previous_hash", "prev_hash is not lowercase hex SHA-256", record.seq)
                )
            if len(record.hash) != 64 or any(char not in "0123456789abcdef" for char in record.hash):
                issues.append(
                    AuditIssue("invalid_record_hash", "hash is not lowercase hex SHA-256", record.seq)
                )
            if record.prev_hash != expected_hash:
                issues.append(
                    AuditIssue("previous_hash_mismatch", "record does not link to predecessor", record.seq)
                )
            if record.hash != record.computed_hash():
                issues.append(
                    AuditIssue("record_hash_mismatch", "record content hash is invalid", record.seq)
                )
            if expected_run_id is None:
                expected_run_id = record.run_id
                if record.seq != 0 or record.event != "run.genesis":
                    issues.append(
                        AuditIssue("missing_genesis", "first record must be run.genesis at seq 0", record.seq)
                    )
            elif record.run_id != expected_run_id:
                issues.append(AuditIssue("run_id_mismatch", "run_id changed within the Ledger", record.seq))
            if verify_artifacts:
                for artifact in record.artifacts:
                    error = verify_artifact(artifact, root=self.artifact_root)
                    if error:
                        issues.append(
                            AuditIssue("artifact_mismatch", f"{artifact.name}: {error}", record.seq)
                        )
            expected_hash = record.hash
        return AuditReport(tuple(issues), tuple(records))

    def records(self) -> tuple[LedgerRecord, ...]:
        report = self.audit()
        if not report.ok:
            raise LedgerIntegrityError(report.summary())
        return report.records

    def record(self, seq: int) -> LedgerRecord:
        records = self.records()
        if seq < 0 or seq >= len(records):
            raise LedgerError(f"Ledger sequence does not exist: {seq}")
        return records[seq]

    @contextmanager
    def locked(self, *, exclusive: bool = True) -> Iterator[None]:
        """Hold the Ledger lock across a stable multi-file governance transaction."""
        if self.require_existing_lock:
            flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        else:
            self.lock_path.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.lock_path, flags, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise LedgerError("Ledger lock must be a regular file")
            if self.require_existing_lock and info.st_mode & 0o007:
                raise LedgerError("pre-provisioned Ledger lock must not grant other permissions")
            path_info = self.lock_path.lstat()
            if (path_info.st_dev, path_info.st_ino) != (info.st_dev, info.st_ino):
                raise LedgerError("Ledger lock path changed while opening")
            fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            locked_path_info = self.lock_path.lstat()
            if (locked_path_info.st_dev, locked_path_info.st_ino) != (info.st_dev, info.st_ino):
                raise LedgerError("Ledger lock path changed while acquiring the lock")
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @contextmanager
    def locked_existing(self) -> Iterator[None]:
        """Hold a shared lock without creating or modifying lock state."""
        descriptor = os.open(self.lock_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise LedgerError("Ledger lock must be a regular file")
            path_info = self.lock_path.lstat()
            if (path_info.st_dev, path_info.st_ino) != (info.st_dev, info.st_ino):
                raise LedgerError("Ledger lock path changed while opening")
            fcntl.flock(descriptor, fcntl.LOCK_SH)
            locked_path_info = self.lock_path.lstat()
            if (locked_path_info.st_dev, locked_path_info.st_ino) != (info.st_dev, info.st_ino):
                raise LedgerError("Ledger lock path changed while acquiring the lock")
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def append(
        self,
        event: str,
        *,
        actor: str,
        data: dict[str, Any] | None = None,
        artifacts: Iterable[Artifact] = (),
        expected_run_id: str | None = None,
        expected_head: str | None = None,
    ) -> LedgerRecord:
        if not isinstance(event, str) or not isinstance(actor, str) or not event or not actor:
            raise LedgerError("event and actor must be non-empty strings")
        payload = data or {}
        canonical_json(payload)
        artifact_tuple = tuple(artifacts)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.locked(exclusive=True):
            flags = os.O_APPEND | os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(self.path, flags, 0o600)
            except OSError as exc:
                raise LedgerIntegrityError(f"cannot safely open Ledger for append: {exc}") from exc
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise LedgerIntegrityError("Ledger must be a singly-linked regular file")
                path_info = self.path.lstat()
                if (path_info.st_dev, path_info.st_ino) != (info.st_dev, info.st_ino):
                    raise LedgerIntegrityError("Ledger path changed while opening for append")
                content = self._read_descriptor(descriptor)
                if content:
                    report = self._audit_bytes(content, verify_artifacts=False)
                    if not report.ok:
                        raise LedgerIntegrityError(report.summary())
                    previous = report.records[-1]
                    seq = previous.seq + 1
                    prev_hash = previous.hash
                    run_id = previous.run_id
                    if expected_run_id is not None and expected_run_id != run_id:
                        raise LedgerError("expected run_id does not match existing Ledger")
                    if expected_head is not None and expected_head != prev_hash:
                        raise LedgerError("Ledger head changed since authorization evaluation")
                else:
                    if event != "run.genesis" or expected_run_id is None:
                        raise LedgerError(
                            "an empty Ledger must begin with run.genesis and an explicit run_id"
                        )
                    seq = 0
                    prev_hash = GENESIS_HASH
                    run_id = expected_run_id
                    if expected_head is not None and expected_head != GENESIS_HASH:
                        raise LedgerError("expected head does not match empty Ledger")
                timestamp = self.clock().astimezone(UTC).isoformat().replace("+00:00", "Z")
                unsigned = {
                    "schema": SCHEMA,
                    "seq": seq,
                    "ts": timestamp,
                    "run_id": run_id,
                    "event": event,
                    "actor": actor,
                    "data": payload,
                    "artifacts": [artifact.to_dict() for artifact in artifact_tuple],
                    "prev_hash": prev_hash,
                }
                record = LedgerRecord.from_dict(
                    {**unsigned, "hash": sha256_json(unsigned, domain=RECORD_HASH_DOMAIN)}
                )
                line = canonical_json(record.to_dict()) + b"\n"
                before_write = self.path.lstat()
                if (before_write.st_dev, before_write.st_ino) != (info.st_dev, info.st_ino):
                    raise LedgerIntegrityError("Ledger path changed before append")
                written = os.write(descriptor, line)
                if written != len(line):
                    os.fsync(descriptor)
                    raise LedgerIntegrityError("short write left an incomplete Ledger append")
                os.fsync(descriptor)
                after_write = self.path.lstat()
                if (after_write.st_dev, after_write.st_ino) != (info.st_dev, info.st_ino):
                    raise LedgerIntegrityError("Ledger path changed during append")
                committed = self._audit_bytes(self._read_descriptor(descriptor), verify_artifacts=False)
                if not committed.ok or not committed.records or committed.records[-1].hash != record.hash:
                    raise LedgerIntegrityError(
                        f"Ledger changed concurrently during append: {committed.summary()}"
                    )
                return record
            except FileNotFoundError as exc:
                raise LedgerIntegrityError("Ledger path disappeared during append") from exc
            finally:
                os.close(descriptor)
