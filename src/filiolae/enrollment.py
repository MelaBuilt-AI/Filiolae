"""Explicit, one-time enrollment policy for a Unix Ledger witness."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .anchor import UNIX_WITNESS_ANCHOR_KIND, public_key_id
from .canonical import canonical_json, sha256_json
from .ledger import Ledger

ENROLLMENT_SCHEMA = "filiolae.witness-enrollment.v1"
ENROLLMENT_HASH_DOMAIN = b"filiolae-witness-enrollment-v1\0"
MAX_ENROLLMENT_BYTES = 16 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_FIELDS = {
    "schema",
    "run_id",
    "genesis_charter_sha256",
    "signer_key_id",
    "anchor_kind",
    "ledger_path",
}


class EnrollmentError(RuntimeError):
    pass


def _reject_symlink_components(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise EnrollmentError(f"symlink component rejected: {current}")


@dataclass(frozen=True)
class WitnessEnrollment:
    run_id: str
    genesis_charter_sha256: str
    signer_key_id: str
    ledger_path: str
    schema: str = ENROLLMENT_SCHEMA
    anchor_kind: str = UNIX_WITNESS_ANCHOR_KIND

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> WitnessEnrollment:
        if set(value) != _FIELDS:
            raise EnrollmentError("enrollment fields are invalid")
        if value["schema"] != ENROLLMENT_SCHEMA:
            raise EnrollmentError("enrollment schema is unsupported")
        if value["anchor_kind"] != UNIX_WITNESS_ANCHOR_KIND:
            raise EnrollmentError("enrollment anchor kind is unsupported")
        run_id = value["run_id"]
        charter = value["genesis_charter_sha256"]
        signer = value["signer_key_id"]
        ledger_path = value["ledger_path"]
        if not isinstance(run_id, str) or not run_id or len(run_id) > 256:
            raise EnrollmentError("enrollment run ID is invalid")
        if not isinstance(charter, str) or _HEX64.fullmatch(charter) is None:
            raise EnrollmentError("enrollment Charter digest is invalid")
        if not isinstance(signer, str) or _KEY_ID.fullmatch(signer) is None:
            raise EnrollmentError("enrollment signer key ID is invalid")
        if (
            not isinstance(ledger_path, str)
            or not Path(ledger_path).is_absolute()
            or ledger_path != os.path.abspath(ledger_path)
        ):
            raise EnrollmentError("enrollment Ledger path must be absolute and normalized")
        return cls(
            run_id=run_id,
            genesis_charter_sha256=charter,
            signer_key_id=signer,
            ledger_path=ledger_path,
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> WitnessEnrollment:
        if not raw.endswith(b"\n") or len(raw) > MAX_ENROLLMENT_BYTES:
            raise EnrollmentError("enrollment file is not a bounded newline-terminated document")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EnrollmentError("enrollment file is invalid JSON") from exc
        if not isinstance(value, dict) or canonical_json(value) + b"\n" != raw:
            raise EnrollmentError("enrollment file must be one canonical JSON object")
        return cls.from_dict(value)

    def to_dict(self) -> dict[str, str]:
        return {
            "schema": self.schema,
            "run_id": self.run_id,
            "genesis_charter_sha256": self.genesis_charter_sha256,
            "signer_key_id": self.signer_key_id,
            "anchor_kind": self.anchor_kind,
            "ledger_path": self.ledger_path,
        }

    def to_bytes(self) -> bytes:
        return canonical_json(self.to_dict()) + b"\n"

    @property
    def sha256(self) -> str:
        return sha256_json(self.to_dict(), domain=ENROLLMENT_HASH_DOMAIN)

    def validate_configuration(self, ledger: Ledger, public_key: Ed25519PublicKey) -> None:
        configured_path = str(Path(os.path.abspath(ledger.path)))
        if configured_path != self.ledger_path:
            raise EnrollmentError("configured Ledger path contradicts enrollment")
        _reject_symlink_components(Path(self.ledger_path))
        if public_key_id(public_key) != self.signer_key_id:
            raise EnrollmentError("configured signer key contradicts enrollment")

    def validate_ledger(self, ledger: Ledger) -> None:
        _reject_symlink_components(Path(self.ledger_path))
        report = ledger.audit(verify_artifacts=False)
        if not report.ok or not report.records:
            raise EnrollmentError("enrolled Ledger is unavailable or invalid")
        genesis = report.records[0]
        metadata = genesis.data.get("metadata", {})
        if not isinstance(metadata, dict):
            raise EnrollmentError("enrolled Ledger genesis metadata is invalid")
        if genesis.run_id != self.run_id:
            raise EnrollmentError("Ledger run ID contradicts enrollment")
        if genesis.data.get("charter_sha256") != self.genesis_charter_sha256:
            raise EnrollmentError("Ledger genesis Charter digest contradicts enrollment")
        if (
            metadata.get("head_anchors_required") is not True
            or metadata.get("anchor_kind") != self.anchor_kind
            or metadata.get("anchor_signer_key_id") != self.signer_key_id
            or metadata.get("witness_enrollment_sha256") != self.sha256
        ):
            raise EnrollmentError("Ledger genesis signer policy contradicts enrollment")


def create_witness_enrollment(
    path: str | Path,
    *,
    ledger_path: str | Path,
    run_id: str,
    genesis_charter_sha256: str,
    public_key: Ed25519PublicKey,
) -> WitnessEnrollment:
    target = Path(os.path.abspath(path))
    ledger_absolute = Path(os.path.abspath(ledger_path))
    _reject_symlink_components(target.parent)
    _reject_symlink_components(ledger_absolute)
    try:
        ledger_absolute.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise EnrollmentError(f"cannot inspect planned Ledger path: {exc}") from exc
    else:
        raise EnrollmentError("refusing retroactive enrollment after Ledger creation")
    enrollment = WitnessEnrollment.from_dict(
        {
            "schema": ENROLLMENT_SCHEMA,
            "run_id": run_id,
            "genesis_charter_sha256": genesis_charter_sha256,
            "signer_key_id": public_key_id(public_key),
            "anchor_kind": UNIX_WITNESS_ANCHOR_KIND,
            "ledger_path": str(ledger_absolute),
        }
    )
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    receipts = target.parent / "receipts"
    if receipts.exists() and any(receipts.iterdir()):
        raise EnrollmentError("refusing retroactive enrollment after witness receipts exist")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags, 0o600)
    except FileExistsError as exc:
        raise EnrollmentError("enrollment already exists; replay or conflict rejected") from exc
    try:
        data = enrollment.to_bytes()
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return enrollment


def load_witness_enrollment(path: str | Path) -> WitnessEnrollment:
    target = Path(os.path.abspath(path))
    _reject_symlink_components(target)
    try:
        descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise EnrollmentError(f"cannot safely open enrollment: {exc}") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_mode & 0o022
            or info.st_size > MAX_ENROLLMENT_BYTES
        ):
            raise EnrollmentError("enrollment file metadata is unsafe")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 65536):
            chunks.append(chunk)
        final = os.fstat(descriptor)
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_mtime_ns,
        ):
            raise EnrollmentError("enrollment changed while reading")
    finally:
        os.close(descriptor)
    return WitnessEnrollment.from_bytes(b"".join(chunks))
