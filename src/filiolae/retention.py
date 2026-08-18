"""Provider-neutral static export for independently retaining signed head receipts.

The bundle format preserves the existing AnchorReceipt v1 bytes.  Preparing or
verifying a bundle does not prove that any remote system accepted, retained, or
object-locked it; provider-version evidence remains a separate acceptance step.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .anchor import (
    UNIX_WITNESS_ANCHOR_KIND,
    AnchorReceipt,
    AnchorStore,
    _verify_unlocked,
    public_key_id,
    verify_anchor_store,
)
from .canonical import canonical_json
from .enrollment import EnrollmentError, WitnessEnrollment
from .ledger import Ledger

RETENTION_MANIFEST_SCHEMA = "filiolae.receipt-retention-manifest.v1"
RETENTION_NAMESPACE_DOMAIN = b"filiolae-receipt-retention-namespace-v1\0"
RETENTION_MANIFEST_HASH_DOMAIN = b"filiolae-receipt-retention-manifest-hash-v1\0"
MANIFEST_NAME = "RETENTION-MANIFEST.json"
PUBLIC_KEY_NAME = "public-key.pem"
ENROLLMENT_NAME = "witness-enrollment.json"
RECEIPTS_DIRECTORY = "receipts"
_MANIFEST_FIELDS = {
    "schema",
    "run_id",
    "anchor_kind",
    "signer_key_id",
    "witness_enrollment_sha256",
    "receipt_count",
    "latest_anchor_seq",
    "latest_ledger_seq",
    "latest_ledger_head_sha256",
    "object_prefix",
    "objects",
}
_OBJECT_FIELDS = {"path", "kind", "sha256", "bytes", "anchor_seq", "receipt_sha256"}
_OBJECT_KINDS = {"public_key", "witness_enrollment", "anchor_receipt"}


class ReceiptRetentionError(RuntimeError):
    """The static retention package is invalid or cannot be created safely."""


@dataclass(frozen=True)
class ReceiptRetentionReport:
    manifest: dict[str, Any]
    manifest_sha256: str
    manifest_object_key: str

    @property
    def receipt_count(self) -> int:
        return self.manifest["receipt_count"]

    @property
    def object_prefix(self) -> str:
        return self.manifest["object_prefix"]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest_sha256(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(RETENTION_MANIFEST_HASH_DOMAIN + canonical_json(manifest)).hexdigest()


def _object_prefix(
    *,
    run_id: str,
    anchor_kind: str,
    signer_key_id: str,
    witness_enrollment_sha256: str | None,
) -> str:
    identity = {
        "run_id": run_id,
        "anchor_kind": anchor_kind,
        "signer_key_id": signer_key_id,
        "witness_enrollment_sha256": witness_enrollment_sha256,
    }
    namespace = hashlib.sha256(RETENTION_NAMESPACE_DOMAIN + canonical_json(identity)).hexdigest()
    key_digest = signer_key_id.removeprefix("sha256:")
    return f"filiolae/ledger-head-receipts/v1/{key_digest}/{namespace}"


def _manifest_object_key(manifest: dict[str, Any], digest: str) -> str:
    return f"{manifest['object_prefix']}/manifests/{manifest['latest_anchor_seq']:020d}-{digest}.json"


def _public_key_pem(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _object(
    path: str,
    kind: str,
    data: bytes,
    *,
    anchor_seq: int | None = None,
    receipt_sha256: str | None = None,
) -> dict[str, Any]:
    return {
        "path": path,
        "kind": kind,
        "sha256": _sha256(data),
        "bytes": len(data),
        "anchor_seq": anchor_seq,
        "receipt_sha256": receipt_sha256,
    }


def _write_exclusive(path: Path, data: bytes, *, mode: int = 0o444) -> None:
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
                raise OSError("short write while creating retention package")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _snapshot_receipts(
    ledger: Ledger,
    store: AnchorStore,
    public_key: Ed25519PublicKey,
) -> tuple[tuple[AnchorReceipt, bytes, str], ...]:
    """Capture one verified current source view under Ledger -> store lock order."""
    with ledger.locked_existing(), store.locked_existing():
        report = _verify_unlocked(
            ledger,
            store,
            public_key,
            require_current=True,
            allow_empty=False,
        )
        if not report.ok:
            raise ReceiptRetentionError(report.summary())
        files = store._receipt_files_unlocked()
        if len(files) != len(report.receipts):
            raise ReceiptRetentionError("anchor store changed while preparing retention export")
        snapshot: list[tuple[AnchorReceipt, bytes, str]] = []
        for receipt, path in zip(report.receipts, files, strict=True):
            data = path.read_bytes()
            if data != receipt.canonical_bytes():
                raise ReceiptRetentionError("receipt changed while preparing retention export")
            snapshot.append((receipt, data, path.name))
        return tuple(snapshot)


def export_receipt_retention_bundle(
    ledger: Ledger,
    source_store: AnchorStore,
    public_key: Ed25519PublicKey,
    output: str | Path,
    *,
    witness_enrollment: WitnessEnrollment | None = None,
) -> ReceiptRetentionReport:
    """Create a fresh, deterministic static package for later immutable-object delivery.

    The export is complete only as a local byte package.  It deliberately performs no network or
    provider operation and creates no remote-retention claim.
    """
    snapshot = _snapshot_receipts(ledger, source_store, public_key)
    latest = snapshot[-1][0]
    if latest.anchor_kind == UNIX_WITNESS_ANCHOR_KIND:
        if witness_enrollment is None:
            raise ReceiptRetentionError("Unix-witness retention export requires its enrollment")
        try:
            witness_enrollment.validate_configuration(ledger, public_key)
            witness_enrollment.validate_ledger(ledger)
        except EnrollmentError as exc:
            raise ReceiptRetentionError(f"witness enrollment is invalid: {exc}") from exc
        enrollment_digest: str | None = witness_enrollment.sha256
        enrollment_data: bytes | None = witness_enrollment.to_bytes()
    else:
        if witness_enrollment is not None:
            raise ReceiptRetentionError("witness enrollment is only valid for Unix-witness receipts")
        enrollment_digest = None
        enrollment_data = None

    key_id = public_key_id(public_key)
    public_data = _public_key_pem(public_key)
    data_by_path: dict[str, bytes] = {PUBLIC_KEY_NAME: public_data}
    objects = [_object(PUBLIC_KEY_NAME, "public_key", public_data)]
    if enrollment_data is not None:
        data_by_path[ENROLLMENT_NAME] = enrollment_data
        objects.append(_object(ENROLLMENT_NAME, "witness_enrollment", enrollment_data))
    for receipt, data, filename in snapshot:
        relative = f"{RECEIPTS_DIRECTORY}/{filename}"
        data_by_path[relative] = data
        objects.append(
            _object(
                relative,
                "anchor_receipt",
                data,
                anchor_seq=receipt.anchor_seq,
                receipt_sha256=receipt.receipt_sha256(),
            )
        )
    objects.sort(key=lambda value: value["path"])
    manifest = {
        "schema": RETENTION_MANIFEST_SCHEMA,
        "run_id": latest.run_id,
        "anchor_kind": latest.anchor_kind,
        "signer_key_id": key_id,
        "witness_enrollment_sha256": enrollment_digest,
        "receipt_count": len(snapshot),
        "latest_anchor_seq": latest.anchor_seq,
        "latest_ledger_seq": latest.ledger_seq,
        "latest_ledger_head_sha256": latest.ledger_head_sha256,
        "object_prefix": _object_prefix(
            run_id=latest.run_id,
            anchor_kind=latest.anchor_kind,
            signer_key_id=key_id,
            witness_enrollment_sha256=enrollment_digest,
        ),
        "objects": objects,
    }
    manifest_data = canonical_json(manifest) + b"\n"
    digest = _manifest_sha256(manifest)

    target = Path(output).absolute()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.parent.is_symlink():
        raise ReceiptRetentionError("retention output parent must not be a symlink")
    try:
        target.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise ReceiptRetentionError("retention output must be a fresh absent directory") from exc
    try:
        receipts = target / RECEIPTS_DIRECTORY
        receipts.mkdir(mode=0o700)
        for relative, data in sorted(data_by_path.items()):
            _write_exclusive(target / relative, data)
        _fsync_directory(receipts)
        receipts.chmod(0o500)
        # The manifest is the package commit marker and is intentionally written last.
        _write_exclusive(target / MANIFEST_NAME, manifest_data)
        _fsync_directory(target)
        target.chmod(0o500)
        _fsync_directory(target.parent)
    except BaseException:
        target.chmod(0o700)
        if (target / RECEIPTS_DIRECTORY).exists():
            (target / RECEIPTS_DIRECTORY).chmod(0o700)
        shutil.rmtree(target, ignore_errors=True)
        raise
    return ReceiptRetentionReport(
        manifest=manifest,
        manifest_sha256=digest,
        manifest_object_key=_manifest_object_key(manifest, digest),
    )


def _read_regular(path: Path, *, maximum: int = 16 * 1024 * 1024) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ReceiptRetentionError(f"cannot inspect retention object {path.name}: {exc}") from exc
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_nlink != 1:
        raise ReceiptRetentionError(f"retention object is not a singly-linked regular file: {path.name}")
    if info.st_size > maximum:
        raise ReceiptRetentionError(f"retention object exceeds size limit: {path.name}")
    return path.read_bytes()


def _parse_manifest(data: bytes) -> dict[str, Any]:
    if not data.endswith(b"\n") or len(data) > 16 * 1024 * 1024:
        raise ReceiptRetentionError("retention manifest must be bounded and newline-terminated")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReceiptRetentionError("retention manifest is invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != _MANIFEST_FIELDS:
        raise ReceiptRetentionError("retention manifest fields are invalid")
    if canonical_json(value) + b"\n" != data:
        raise ReceiptRetentionError("retention manifest is not canonical JSON")
    if value["schema"] != RETENTION_MANIFEST_SCHEMA:
        raise ReceiptRetentionError("retention manifest schema is unsupported")
    scalar_strings = ("run_id", "anchor_kind", "signer_key_id", "latest_ledger_head_sha256")
    if any(not isinstance(value[name], str) or not value[name] for name in scalar_strings):
        raise ReceiptRetentionError("retention manifest identity fields are invalid")
    for name in ("receipt_count", "latest_anchor_seq", "latest_ledger_seq"):
        item = value[name]
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            raise ReceiptRetentionError(f"retention manifest {name} is invalid")
    if value["receipt_count"] < 1 or value["latest_anchor_seq"] != value["receipt_count"] - 1:
        raise ReceiptRetentionError("retention manifest receipt sequence is invalid")
    enrollment = value["witness_enrollment_sha256"]
    if enrollment is not None and (
        not isinstance(enrollment, str)
        or len(enrollment) != 64
        or any(char not in "0123456789abcdef" for char in enrollment)
    ):
        raise ReceiptRetentionError("retention manifest enrollment digest is invalid")
    expected_prefix = _object_prefix(
        run_id=value["run_id"],
        anchor_kind=value["anchor_kind"],
        signer_key_id=value["signer_key_id"],
        witness_enrollment_sha256=enrollment,
    )
    if value["object_prefix"] != expected_prefix:
        raise ReceiptRetentionError("retention manifest object prefix is invalid")
    objects = value["objects"]
    if not isinstance(objects, list) or not objects:
        raise ReceiptRetentionError("retention manifest objects are invalid")
    paths: list[str] = []
    for item in objects:
        if not isinstance(item, dict) or set(item) != _OBJECT_FIELDS:
            raise ReceiptRetentionError("retention object manifest fields are invalid")
        path = item["path"]
        if (
            not isinstance(path, str)
            or not path
            or Path(path).is_absolute()
            or Path(path).parts != tuple(part for part in path.split("/") if part not in {"", ".", ".."})
        ):
            raise ReceiptRetentionError("retention object path is unsafe")
        if item["kind"] not in _OBJECT_KINDS:
            raise ReceiptRetentionError("retention object kind is invalid")
        if (
            not isinstance(item["sha256"], str)
            or len(item["sha256"]) != 64
            or any(char not in "0123456789abcdef" for char in item["sha256"])
            or not isinstance(item["bytes"], int)
            or isinstance(item["bytes"], bool)
            or item["bytes"] < 0
        ):
            raise ReceiptRetentionError("retention object hash/size is invalid")
        if item["kind"] == "anchor_receipt":
            if (
                not isinstance(item["anchor_seq"], int)
                or isinstance(item["anchor_seq"], bool)
                or item["anchor_seq"] < 0
                or not isinstance(item["receipt_sha256"], str)
                or len(item["receipt_sha256"]) != 64
            ):
                raise ReceiptRetentionError("retention receipt object metadata is invalid")
        elif item["anchor_seq"] is not None or item["receipt_sha256"] is not None:
            raise ReceiptRetentionError("non-receipt retention object has receipt metadata")
        paths.append(path)
    if paths != sorted(paths) or len(set(paths)) != len(paths):
        raise ReceiptRetentionError("retention manifest object paths are not unique and sorted")
    return value


def verify_receipt_retention_bundle(
    ledger: Ledger,
    bundle: str | Path,
    trusted_public_key: Ed25519PublicKey,
) -> ReceiptRetentionReport:
    """Verify a restored static package against a Ledger and out-of-band public key."""
    root = Path(bundle).absolute()
    if root.is_symlink() or not root.is_dir():
        raise ReceiptRetentionError("retention bundle root must be a real directory")
    manifest_data = _read_regular(root / MANIFEST_NAME)
    manifest = _parse_manifest(manifest_data)
    object_map = {item["path"]: item for item in manifest["objects"]}
    expected_root = {MANIFEST_NAME, PUBLIC_KEY_NAME, RECEIPTS_DIRECTORY}
    if manifest["witness_enrollment_sha256"] is not None:
        expected_root.add(ENROLLMENT_NAME)
    actual_root = {path.name for path in root.iterdir()}
    if actual_root != expected_root:
        raise ReceiptRetentionError("retention bundle has missing or unexpected root entries")
    receipts_dir = root / RECEIPTS_DIRECTORY
    if receipts_dir.is_symlink() or not receipts_dir.is_dir():
        raise ReceiptRetentionError("retention receipts entry must be a real directory")
    actual_objects = {PUBLIC_KEY_NAME}
    if ENROLLMENT_NAME in expected_root:
        actual_objects.add(ENROLLMENT_NAME)
    actual_objects.update(f"{RECEIPTS_DIRECTORY}/{path.name}" for path in receipts_dir.iterdir())
    if actual_objects != set(object_map):
        raise ReceiptRetentionError("retention bundle objects differ from the manifest")

    data_by_path: dict[str, bytes] = {}
    for relative, item in object_map.items():
        data = _read_regular(root / relative)
        if len(data) != item["bytes"] or _sha256(data) != item["sha256"]:
            raise ReceiptRetentionError(f"retention object bytes differ from manifest: {relative}")
        data_by_path[relative] = data

    try:
        included_key = serialization.load_pem_public_key(data_by_path[PUBLIC_KEY_NAME])
    except (TypeError, ValueError) as exc:
        raise ReceiptRetentionError("retention public key is invalid") from exc
    if not isinstance(included_key, Ed25519PublicKey):
        raise ReceiptRetentionError("retention public key is not Ed25519")
    trusted_key_id = public_key_id(trusted_public_key)
    if public_key_id(included_key) != trusted_key_id or manifest["signer_key_id"] != trusted_key_id:
        raise ReceiptRetentionError("retention public key differs from the out-of-band trust root")

    receipt_items = [item for item in manifest["objects"] if item["kind"] == "anchor_receipt"]
    if len(receipt_items) != manifest["receipt_count"]:
        raise ReceiptRetentionError("retention receipt count differs from manifest")
    if [item["anchor_seq"] for item in receipt_items] != list(range(len(receipt_items))):
        raise ReceiptRetentionError("retention receipt objects are not a complete sequence")
    for item in receipt_items:
        receipt = AnchorReceipt.from_bytes(data_by_path[item["path"]])
        if receipt.anchor_seq != item["anchor_seq"] or receipt.receipt_sha256() != item["receipt_sha256"]:
            raise ReceiptRetentionError("retention receipt metadata does not match its bytes")

    with tempfile.TemporaryDirectory(prefix="filiolae-retention-verify-") as temporary:
        staged = AnchorStore(Path(temporary) / "anchors")
        staged.receipts_dir.mkdir(parents=True)
        for item in receipt_items:
            (staged.receipts_dir / Path(item["path"]).name).write_bytes(data_by_path[item["path"]])
        anchor_report = verify_anchor_store(
            ledger,
            staged,
            trusted_public_key,
            require_current=True,
            expected_anchor_kind=manifest["anchor_kind"],
        )
    if not anchor_report.ok:
        raise ReceiptRetentionError(anchor_report.summary())
    latest = anchor_report.receipts[-1]
    if (
        latest.run_id != manifest["run_id"]
        or latest.anchor_seq != manifest["latest_anchor_seq"]
        or latest.ledger_seq != manifest["latest_ledger_seq"]
        or latest.ledger_head_sha256 != manifest["latest_ledger_head_sha256"]
    ):
        raise ReceiptRetentionError("retention manifest latest head differs from verified receipts")

    enrollment_digest = manifest["witness_enrollment_sha256"]
    if manifest["anchor_kind"] == UNIX_WITNESS_ANCHOR_KIND:
        if enrollment_digest is None or ENROLLMENT_NAME not in data_by_path:
            raise ReceiptRetentionError("Unix-witness retention bundle lacks enrollment")
        try:
            enrollment = WitnessEnrollment.from_bytes(data_by_path[ENROLLMENT_NAME])
            enrollment.validate_configuration(ledger, trusted_public_key)
            enrollment.validate_ledger(ledger)
        except EnrollmentError as exc:
            raise ReceiptRetentionError(f"retained witness enrollment is invalid: {exc}") from exc
        if enrollment.sha256 != enrollment_digest:
            raise ReceiptRetentionError("retained witness enrollment digest differs from manifest")
    elif enrollment_digest is not None or ENROLLMENT_NAME in data_by_path:
        raise ReceiptRetentionError("non-witness retention bundle unexpectedly contains enrollment")

    digest = _manifest_sha256(manifest)
    return ReceiptRetentionReport(
        manifest=manifest,
        manifest_sha256=digest,
        manifest_object_key=_manifest_object_key(manifest, digest),
    )
