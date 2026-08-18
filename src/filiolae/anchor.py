"""Ed25519-signed, hash-chained checkpoints of Filiolae Ledger heads.

These are local cryptographic checkpoints unless the key and receipt store live
in an independently protected domain. They are not public timestamps or proof
of third-party observation.
"""

from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import json
import os
import re
import stat
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_json
from .ledger import SCHEMA as LEDGER_SCHEMA
from .ledger import Ledger

SIGNATURE_DOMAIN = b"filiolae-ledger-head-receipt-v1\x00"
RECEIPT_HASH_DOMAIN = b"filiolae-ledger-head-receipt-hash-v1\x00"
KEY_ID_DOMAIN = b"filiolae-ed25519-key-id-v1\x00"
RECEIPT_SCHEMA = "filiolae.ledger-head-receipt.v1"
LOCAL_ANCHOR_KIND = "local_ed25519_checkpoint"
UNIX_WITNESS_ANCHOR_KIND = "unix_ed25519_witness"
SUPPORTED_ANCHOR_KINDS = frozenset({LOCAL_ANCHOR_KIND, UNIX_WITNESS_ANCHOR_KIND})
# Backward-compatible name for the original local signer API.
ANCHOR_KIND = LOCAL_ANCHOR_KIND
ZERO_HASH = "0" * 64
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RECEIPT_NAME = re.compile(r"^(?P<seq>[0-9]{20})-(?P<digest>[0-9a-f]{64})\.anchor\.json$")
_PENDING_NAME = re.compile(r"^\.pending-[0-9]+-[0-9a-f]{32}$")
_RECEIPT_FIELDS = {
    "schema",
    "anchor_kind",
    "anchor_seq",
    "run_id",
    "ledger_schema",
    "ledger_seq",
    "ledger_head_sha256",
    "previous_receipt_sha256",
    "signer_key_id",
    "signed_at",
    "signature",
}


class AnchorError(RuntimeError):
    pass


@dataclass(frozen=True)
class AnchorReceipt:
    schema: str
    anchor_kind: str
    anchor_seq: int
    run_id: str
    ledger_schema: str
    ledger_seq: int
    ledger_head_sha256: str
    previous_receipt_sha256: str
    signer_key_id: str
    signed_at: str
    signature: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "anchor_kind": self.anchor_kind,
            "anchor_seq": self.anchor_seq,
            "run_id": self.run_id,
            "ledger_schema": self.ledger_schema,
            "ledger_seq": self.ledger_seq,
            "ledger_head_sha256": self.ledger_head_sha256,
            "previous_receipt_sha256": self.previous_receipt_sha256,
            "signer_key_id": self.signer_key_id,
            "signed_at": self.signed_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "signature": self.signature}

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_dict()) + b"\n"

    def receipt_sha256(self) -> str:
        return hashlib.sha256(RECEIPT_HASH_DOMAIN + canonical_json(self.to_dict())).hexdigest()

    @classmethod
    def from_bytes(cls, data: bytes) -> AnchorReceipt:
        try:
            value = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AnchorError(f"invalid receipt JSON: {exc}") from exc
        if not isinstance(value, dict) or set(value) != _RECEIPT_FIELDS:
            raise AnchorError("receipt fields do not exactly match the v1 schema")
        if canonical_json(value) + b"\n" != data:
            raise AnchorError("receipt is not canonical JSON with one trailing newline")
        if value["schema"] != RECEIPT_SCHEMA or value["anchor_kind"] not in SUPPORTED_ANCHOR_KINDS:
            raise AnchorError("unsupported receipt schema or anchor kind")
        if value["ledger_schema"] != LEDGER_SCHEMA:
            raise AnchorError("unsupported Ledger schema in receipt")
        for name in ("anchor_seq", "ledger_seq"):
            if not isinstance(value[name], int) or isinstance(value[name], bool) or value[name] < 0:
                raise AnchorError(f"receipt {name} is not a nonnegative integer")
        for name in ("run_id", "signer_key_id", "signed_at", "signature"):
            if not isinstance(value[name], str) or not value[name]:
                raise AnchorError(f"receipt {name} is empty or not a string")
        for name in ("ledger_head_sha256", "previous_receipt_sha256"):
            if not isinstance(value[name], str) or _HEX64.fullmatch(value[name]) is None:
                raise AnchorError(f"receipt {name} is not a lowercase SHA-256 digest")
        try:
            timestamp = datetime.fromisoformat(value["signed_at"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise AnchorError("receipt signed_at is not ISO-8601") from exc
        if timestamp.tzinfo is None or timestamp.utcoffset() != UTC.utcoffset(timestamp):
            raise AnchorError("receipt signed_at must be UTC")
        try:
            signature = base64.b64decode(value["signature"], validate=True)
        except binascii.Error as exc:
            raise AnchorError("receipt signature is not strict base64") from exc
        if len(signature) != 64:
            raise AnchorError("receipt signature is not 64 bytes")
        if base64.b64encode(signature).decode("ascii") != value["signature"]:
            raise AnchorError("receipt signature is not canonical base64")
        if not value["signed_at"].endswith("Z"):
            raise AnchorError("receipt signed_at must use canonical UTC Z notation")
        return cls(**value)


@dataclass(frozen=True)
class AnchorIssue:
    code: str
    message: str
    receipt_index: int | None = None


@dataclass(frozen=True)
class AnchorAuditReport:
    issues: tuple[AnchorIssue, ...]
    receipts: tuple[AnchorReceipt, ...]
    current_head_anchored: bool
    unanchored_tail_records: int

    @property
    def ok(self) -> bool:
        return not self.issues

    def summary(self) -> str:
        if self.ok:
            return (
                f"Anchor chain valid: {len(self.receipts)} receipt(s), "
                f"{self.unanchored_tail_records} unanchored tail record(s)"
            )
        return "; ".join(f"{issue.code}@{issue.receipt_index}: {issue.message}" for issue in self.issues)


class HeadAnchor(Protocol):
    @property
    def anchor_kind(self) -> str: ...

    @property
    def signer_key_id(self) -> str: ...

    def acknowledge(self, ledger: Ledger, *, expected_seq: int, expected_head: str) -> AnchorReceipt: ...


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class AnchorStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).absolute()
        self.receipts_dir = self.root / "receipts"
        self.lock_path = self.root / ".anchor.lock"

    def _ensure(self) -> None:
        if self.root.is_symlink() or self.receipts_dir.is_symlink():
            raise AnchorError("anchor store root/receipts directory must not be a symlink")
        root_existed = self.root.exists()
        receipts_existed = self.receipts_dir.exists()
        self.receipts_dir.mkdir(parents=True, exist_ok=True)
        if not root_existed:
            _fsync_directory(self.root.parent)
        if not receipts_existed:
            _fsync_directory(self.root)

    @contextmanager
    def locked(self, *, exclusive: bool) -> Iterator[None]:
        self._ensure()
        lock_existed = self.lock_path.exists()
        descriptor = os.open(
            self.lock_path,
            os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        if not lock_existed:
            _fsync_directory(self.root)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @contextmanager
    def locked_existing(self) -> Iterator[None]:
        """Hold the existing store lock for read-only inspection without provisioning state."""
        if (
            self.root.is_symlink()
            or self.receipts_dir.is_symlink()
            or not self.root.is_dir()
            or not self.receipts_dir.is_dir()
        ):
            raise AnchorError("anchor store does not have a safe existing layout")
        root_info = self.root.lstat()
        receipts_info = self.receipts_dir.lstat()
        descriptor = os.open(
            self.lock_path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise AnchorError("anchor store lock must be a regular file")
            path_info = self.lock_path.lstat()
            if (path_info.st_dev, path_info.st_ino) != (info.st_dev, info.st_ino):
                raise AnchorError("anchor store lock path changed while opening")
            fcntl.flock(descriptor, fcntl.LOCK_SH)
            locked_path_info = self.lock_path.lstat()
            locked_root_info = self.root.lstat()
            locked_receipts_info = self.receipts_dir.lstat()
            if (
                (locked_path_info.st_dev, locked_path_info.st_ino) != (info.st_dev, info.st_ino)
                or (locked_root_info.st_dev, locked_root_info.st_ino) != (root_info.st_dev, root_info.st_ino)
                or (locked_receipts_info.st_dev, locked_receipts_info.st_ino)
                != (receipts_info.st_dev, receipts_info.st_ino)
            ):
                raise AnchorError("anchor store layout changed while acquiring the lock")
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _receipt_files_unlocked(self) -> list[Path]:
        files: list[Path] = []
        for path in self.receipts_dir.iterdir():
            if _PENDING_NAME.fullmatch(path.name):
                raise AnchorError(f"incomplete pending receipt requires reconciliation: {path.name}")
            if path.is_symlink() or not path.is_file() or _RECEIPT_NAME.fullmatch(path.name) is None:
                raise AnchorError(f"unexpected or unsafe anchor-store entry: {path.name}")
            files.append(path)
        return sorted(files, key=lambda path: path.name)

    def _append_unlocked(self, receipt: AnchorReceipt) -> Path:
        digest = receipt.receipt_sha256()
        filename = f"{receipt.anchor_seq:020d}-{digest}.anchor.json"
        final_path = self.receipts_dir / filename
        data = receipt.canonical_bytes()
        if final_path.exists():
            if not final_path.is_symlink() and final_path.read_bytes() == data:
                return final_path
            raise AnchorError(f"conflicting receipt already exists: {filename}")
        pending = self.receipts_dir / f".pending-{os.getpid()}-{uuid.uuid4().hex}"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(pending, flags, 0o600)
        try:
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written <= 0:
                    raise OSError("short write while creating anchor receipt")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        linked = False
        try:
            os.link(pending, final_path, follow_symlinks=False)
            linked = True
            _fsync_directory(self.receipts_dir)
            pending.unlink()
            _fsync_directory(self.receipts_dir)
        except FileExistsError:
            pending.unlink(missing_ok=True)
            raise AnchorError(f"receipt appeared concurrently: {filename}") from None
        except BaseException:
            if not linked:
                pending.unlink(missing_ok=True)
            raise
        return final_path


def _write_exclusive(path: Path, data: bytes, mode: int) -> None:
    path = path.absolute()
    parent_existed = path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not parent_existed:
        _fsync_directory(path.parent.parent)
    descriptor = os.open(
        path,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short write while creating key file")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def public_key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "sha256:" + hashlib.sha256(KEY_ID_DOMAIN + raw).hexdigest()


def generate_keypair(private_path: str | Path, public_path: str | Path) -> str:
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _write_exclusive(Path(private_path), private_bytes, 0o600)
    try:
        _write_exclusive(Path(public_path), public_bytes, 0o644)
    except BaseException:
        private = Path(private_path).absolute()
        private.unlink(missing_ok=True)
        _fsync_directory(private.parent)
        raise
    return public_key_id(private_key.public_key())


def _read_key_file(path: str | Path, *, private: bool) -> bytes:
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AnchorError("key must be a readable regular non-symlink file") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise AnchorError("key must be a regular non-symlink file")
        if private and stat.S_IMODE(info.st_mode) & 0o077:
            raise AnchorError("private key permissions must not grant group/other access")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 65536):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    data = _read_key_file(path, private=True)
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as exc:
        raise AnchorError(f"cannot load private key: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise AnchorError("private key is not Ed25519")
    return key


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    data = _read_key_file(path, private=False)
    try:
        key = serialization.load_pem_public_key(data)
    except (ValueError, TypeError) as exc:
        raise AnchorError(f"cannot load public key: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise AnchorError("public key is not Ed25519")
    return key


def _verify_unlocked(
    ledger: Ledger,
    store: AnchorStore,
    public_key: Ed25519PublicKey,
    *,
    require_current: bool,
    allow_empty: bool,
    expected_anchor_kind: str | None = None,
) -> AnchorAuditReport:
    ledger_report = ledger.audit(verify_artifacts=False)
    if not ledger_report.ok:
        return AnchorAuditReport((AnchorIssue("ledger_invalid", ledger_report.summary()),), (), False, 0)
    records = ledger_report.records
    issues: list[AnchorIssue] = []
    receipts: list[AnchorReceipt] = []
    try:
        files = store._receipt_files_unlocked()
    except (AnchorError, OSError) as exc:
        return AnchorAuditReport((AnchorIssue("store_invalid", str(exc)),), (), False, len(records))
    if not files and not allow_empty:
        issues.append(AnchorIssue("no_receipts", "anchor store contains no receipts"))
    previous: AnchorReceipt | None = None
    expected_key = public_key_id(public_key)
    metadata = records[0].data.get("metadata", {})
    anchors_required = isinstance(metadata, dict) and metadata.get("head_anchors_required") is True
    policy_key = metadata.get("anchor_signer_key_id") if isinstance(metadata, dict) else None
    policy_kind = metadata.get("anchor_kind") if isinstance(metadata, dict) else None
    if anchors_required:
        if not isinstance(policy_key, str) or not policy_key:
            issues.append(AnchorIssue("anchor_policy_invalid", "genesis anchor signer key ID missing"))
        elif policy_key != expected_key:
            issues.append(
                AnchorIssue("anchor_policy_key_mismatch", "public key differs from genesis anchor policy")
            )
        if policy_kind not in SUPPORTED_ANCHOR_KINDS:
            issues.append(AnchorIssue("anchor_policy_invalid", "genesis anchor kind is invalid"))
        if expected_anchor_kind is not None and policy_kind != expected_anchor_kind:
            issues.append(
                AnchorIssue(
                    "anchor_policy_kind_mismatch",
                    "expected anchor kind differs from genesis policy",
                )
            )
    pinned_kind = policy_kind if anchors_required else expected_anchor_kind
    for index, path in enumerate(files):
        try:
            receipt = AnchorReceipt.from_bytes(path.read_bytes())
        except (AnchorError, OSError) as exc:
            issues.append(AnchorIssue("receipt_invalid", f"{path.name}: {exc}", index))
            continue
        receipts.append(receipt)
        match = _RECEIPT_NAME.fullmatch(path.name)
        if (
            match is None
            or int(match.group("seq")) != receipt.anchor_seq
            or match.group("digest") != receipt.receipt_sha256()
        ):
            issues.append(AnchorIssue("filename_mismatch", path.name, index))
        if receipt.anchor_seq != index:
            issues.append(AnchorIssue("anchor_seq_gap", str(receipt.anchor_seq), index))
        expected_previous = previous.receipt_sha256() if previous else ZERO_HASH
        if receipt.previous_receipt_sha256 != expected_previous:
            issues.append(AnchorIssue("receipt_chain_broken", receipt.previous_receipt_sha256, index))
        if previous is not None and receipt.ledger_seq <= previous.ledger_seq:
            issues.append(AnchorIssue("ledger_seq_not_increasing", str(receipt.ledger_seq), index))
        if receipt.signer_key_id != expected_key:
            issues.append(AnchorIssue("key_id_mismatch", receipt.signer_key_id, index))
        if pinned_kind is None:
            pinned_kind = receipt.anchor_kind
        if receipt.anchor_kind != pinned_kind:
            issues.append(
                AnchorIssue(
                    "anchor_policy_kind_mismatch",
                    "receipt anchor kind differs from the pinned chain kind",
                    index,
                )
            )
        try:
            signature = base64.b64decode(receipt.signature, validate=True)
            public_key.verify(signature, SIGNATURE_DOMAIN + canonical_json(receipt.body()))
        except (binascii.Error, InvalidSignature, ValueError) as exc:
            issues.append(AnchorIssue("signature_invalid", str(exc) or "invalid signature", index))
        if receipt.run_id != records[0].run_id:
            issues.append(AnchorIssue("run_id_mismatch", receipt.run_id, index))
        if receipt.ledger_seq >= len(records):
            issues.append(AnchorIssue("ledger_seq_absent", str(receipt.ledger_seq), index))
        elif records[receipt.ledger_seq].hash != receipt.ledger_head_sha256:
            issues.append(AnchorIssue("ledger_head_mismatch", receipt.ledger_head_sha256, index))
        previous = receipt
    latest_seq = receipts[-1].ledger_seq if receipts else -1
    current = bool(
        receipts and latest_seq == records[-1].seq and receipts[-1].ledger_head_sha256 == records[-1].hash
    )
    tail = records[-1].seq - latest_seq
    if require_current and not current:
        issues.append(AnchorIssue("current_head_unanchored", "latest Ledger head has no receipt"))
    return AnchorAuditReport(tuple(issues), tuple(receipts), current, tail)


def import_anchor_receipt(
    ledger: Ledger,
    store: AnchorStore,
    public_key: Ed25519PublicKey,
    receipt: AnchorReceipt,
    *,
    expected_anchor_kind: str,
    expected_seq: int | None = None,
    expected_head: str | None = None,
) -> AnchorReceipt:
    """Verify and durably import one externally signed receipt into a local mirror."""
    # Round-trip through the strict parser so callers cannot bypass field/canonical validation by
    # constructing a dataclass directly.
    candidate = AnchorReceipt.from_bytes(receipt.canonical_bytes())
    if expected_anchor_kind not in SUPPORTED_ANCHOR_KINDS:
        raise AnchorError("unsupported expected anchor kind")
    if candidate.anchor_kind != expected_anchor_kind:
        raise AnchorError("external receipt has the wrong anchor kind")
    with ledger.locked(exclusive=False), store.locked(exclusive=True):
        existing = _verify_unlocked(
            ledger,
            store,
            public_key,
            require_current=False,
            allow_empty=True,
            expected_anchor_kind=expected_anchor_kind,
        )
        if not existing.ok:
            raise AnchorError(existing.summary())
        if candidate.anchor_seq < len(existing.receipts):
            prior = existing.receipts[candidate.anchor_seq]
            if prior.receipt_sha256() != candidate.receipt_sha256():
                raise AnchorError("external receipt conflicts with the local mirror")
            if expected_seq is not None and prior.ledger_seq != expected_seq:
                raise AnchorError("external receipt does not bind the expected Ledger sequence")
            if expected_head is not None and prior.ledger_head_sha256 != expected_head:
                raise AnchorError("external receipt does not bind the expected Ledger head")
            return prior
        if candidate.anchor_seq != len(existing.receipts):
            raise AnchorError("external receipt sequence has a gap")
        expected_previous = existing.receipts[-1].receipt_sha256() if existing.receipts else ZERO_HASH
        if candidate.previous_receipt_sha256 != expected_previous:
            raise AnchorError("external receipt does not extend the local mirror")
        if existing.receipts and candidate.ledger_seq <= existing.receipts[-1].ledger_seq:
            raise AnchorError("external receipt Ledger sequence is not increasing")

        ledger_report = ledger.audit(verify_artifacts=False)
        if not ledger_report.ok:
            raise AnchorError(ledger_report.summary())
        records = ledger_report.records
        metadata = records[0].data.get("metadata", {})
        required = isinstance(metadata, dict) and metadata.get("head_anchors_required") is True
        policy_key = metadata.get("anchor_signer_key_id") if isinstance(metadata, dict) else None
        policy_kind = metadata.get("anchor_kind") if isinstance(metadata, dict) else None
        key_id = public_key_id(public_key)
        if candidate.signer_key_id != key_id:
            raise AnchorError("external receipt signer key ID is not the pinned public key")
        if required and (policy_key != key_id or policy_kind != candidate.anchor_kind):
            raise AnchorError("external receipt contradicts genesis anchor policy")
        try:
            signature = base64.b64decode(candidate.signature, validate=True)
            public_key.verify(
                signature,
                SIGNATURE_DOMAIN + canonical_json(candidate.body()),
            )
        except (binascii.Error, InvalidSignature, ValueError) as exc:
            raise AnchorError("external receipt signature is invalid") from exc
        if candidate.run_id != records[0].run_id:
            raise AnchorError("external receipt run ID differs from the Ledger")
        if candidate.ledger_seq >= len(records):
            raise AnchorError("external receipt refers to an absent Ledger sequence")
        if records[candidate.ledger_seq].hash != candidate.ledger_head_sha256:
            raise AnchorError("external receipt does not bind its Ledger record")
        if expected_seq is not None and candidate.ledger_seq != expected_seq:
            raise AnchorError("external receipt does not bind the expected Ledger sequence")
        if expected_head is not None and candidate.ledger_head_sha256 != expected_head:
            raise AnchorError("external receipt does not bind the expected Ledger head")

        store._append_unlocked(candidate)
        verified = _verify_unlocked(
            ledger,
            store,
            public_key,
            require_current=(expected_seq is not None or expected_head is not None),
            allow_empty=False,
            expected_anchor_kind=expected_anchor_kind,
        )
        if not verified.ok:
            raise AnchorError(verified.summary())
        return candidate


def verify_anchor_store(
    ledger: Ledger,
    store: AnchorStore,
    public_key: Ed25519PublicKey,
    *,
    require_current: bool = True,
    expected_anchor_kind: str | None = None,
) -> AnchorAuditReport:
    with ledger.locked(exclusive=False), store.locked(exclusive=False):
        return _verify_unlocked(
            ledger,
            store,
            public_key,
            require_current=require_current,
            allow_empty=False,
            expected_anchor_kind=expected_anchor_kind,
        )


def verify_anchor_store_readonly(
    ledger: Ledger,
    store: AnchorStore,
    public_key: Ed25519PublicKey,
    *,
    require_current: bool = True,
    expected_anchor_kind: str | None = None,
) -> AnchorAuditReport:
    """Verify retained receipts without creating lock files or directories."""
    with ledger.locked_existing(), store.locked_existing():
        return _verify_unlocked(
            ledger,
            store,
            public_key,
            require_current=require_current,
            allow_empty=False,
            expected_anchor_kind=expected_anchor_kind,
        )


def _anchor_ledger_head_with_ledger_locked(
    ledger: Ledger,
    store: AnchorStore,
    private_key: Ed25519PrivateKey,
    *,
    expected_seq: int | None = None,
    expected_head: str | None = None,
    clock: Callable[[], datetime] | None = None,
    anchor_kind: str = LOCAL_ANCHOR_KIND,
) -> AnchorReceipt:
    if anchor_kind not in SUPPORTED_ANCHOR_KINDS:
        raise AnchorError(f"unsupported anchor kind: {anchor_kind}")
    public_key = private_key.public_key()
    with store.locked(exclusive=True):
        existing = _verify_unlocked(
            ledger,
            store,
            public_key,
            require_current=False,
            allow_empty=True,
            expected_anchor_kind=anchor_kind,
        )
        if not existing.ok:
            raise AnchorError(existing.summary())
        if any(receipt.anchor_kind != anchor_kind for receipt in existing.receipts):
            raise AnchorError("existing receipt chain uses a different anchor kind")
        ledger_report = ledger.audit(verify_artifacts=False)
        if not ledger_report.ok:
            raise AnchorError(ledger_report.summary())
        head = ledger_report.records[-1]
        if expected_seq is not None and head.seq != expected_seq:
            raise AnchorError(f"Ledger seq changed: expected {expected_seq}, found {head.seq}")
        if expected_head is not None and head.hash != expected_head:
            raise AnchorError(f"Ledger head changed: expected {expected_head}, found {head.hash}")
        if existing.current_head_anchored:
            return existing.receipts[-1]
        if existing.receipts and existing.receipts[-1].ledger_seq >= head.seq:
            raise AnchorError("anchor store is ahead of or conflicts with the Ledger")
        genesis = ledger_report.records[0]
        now = (clock or (lambda: datetime.now(UTC)))().astimezone(UTC)
        body = {
            "schema": RECEIPT_SCHEMA,
            "anchor_kind": anchor_kind,
            "anchor_seq": len(existing.receipts),
            "run_id": genesis.run_id,
            "ledger_schema": LEDGER_SCHEMA,
            "ledger_seq": head.seq,
            "ledger_head_sha256": head.hash,
            "previous_receipt_sha256": (
                existing.receipts[-1].receipt_sha256() if existing.receipts else ZERO_HASH
            ),
            "signer_key_id": public_key_id(public_key),
            "signed_at": now.isoformat().replace("+00:00", "Z"),
        }
        signature = private_key.sign(SIGNATURE_DOMAIN + canonical_json(body))
        receipt = AnchorReceipt(
            **body,
            signature=base64.b64encode(signature).decode("ascii"),
        )
        store._append_unlocked(receipt)
        verified = _verify_unlocked(
            ledger,
            store,
            public_key,
            require_current=True,
            allow_empty=False,
            expected_anchor_kind=anchor_kind,
        )
        if not verified.ok:
            raise AnchorError(verified.summary())
        return receipt


def anchor_ledger_head(
    ledger: Ledger,
    store: AnchorStore,
    private_key: Ed25519PrivateKey,
    *,
    expected_seq: int | None = None,
    expected_head: str | None = None,
    clock: Callable[[], datetime] | None = None,
    anchor_kind: str = LOCAL_ANCHOR_KIND,
) -> AnchorReceipt:
    """Sign one stable Ledger snapshot while holding Ledger then receipt-store locks."""
    with ledger.locked(exclusive=True):
        return _anchor_ledger_head_with_ledger_locked(
            ledger,
            store,
            private_key,
            expected_seq=expected_seq,
            expected_head=expected_head,
            clock=clock,
            anchor_kind=anchor_kind,
        )


class LocalEd25519HeadAnchor:
    """Gate adapter for a same-control-domain signer; not an independent witness."""

    def __init__(self, store: AnchorStore, private_key: Ed25519PrivateKey) -> None:
        self.store = store
        self.private_key = private_key

    @property
    def anchor_kind(self) -> str:
        return ANCHOR_KIND

    @property
    def signer_key_id(self) -> str:
        return public_key_id(self.private_key.public_key())

    def acknowledge(self, ledger: Ledger, *, expected_seq: int, expected_head: str) -> AnchorReceipt:
        return anchor_ledger_head(
            ledger,
            self.store,
            self.private_key,
            expected_seq=expected_seq,
            expected_head=expected_head,
        )

    def verify_acknowledgement(
        self,
        ledger: Ledger,
        receipt: AnchorReceipt,
        *,
        expected_seq: int,
        expected_head: str,
    ) -> None:
        report = verify_anchor_store(
            ledger,
            self.store,
            self.private_key.public_key(),
            require_current=True,
            expected_anchor_kind=self.anchor_kind,
        )
        if not report.ok:
            raise AnchorError(report.summary())
        current = report.receipts[-1]
        if (
            current.receipt_sha256() != receipt.receipt_sha256()
            or current.ledger_seq != expected_seq
            or current.ledger_head_sha256 != expected_head
        ):
            raise AnchorError("durable receipt does not acknowledge the expected current Ledger head")
