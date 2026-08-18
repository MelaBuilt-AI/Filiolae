"""Local, network-free primitives for Filiolae receipt transparency.

The Merkle construction follows RFC 6962: leaf hashes are SHA-256(0x00 || leaf)
and interior hashes are SHA-256(0x01 || left || right).  Checkpoints use the
C2SP tlog-checkpoint v1.0.0 three-line body and signed-note v1.0.0 Ed25519
signature encoding.  This module does not submit anything to a public log and
does not couple transparency observations to Gate authority.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .anchor import (
    SIGNATURE_DOMAIN,
    UNIX_WITNESS_ANCHOR_KIND,
    AnchorError,
    AnchorReceipt,
    public_key_id,
)
from .canonical import canonical_json

LEAF_SCHEMA = "filiolae.receipt-transparency-leaf.v1"
CHECKPOINT_SIGNATURE_TYPE = b"\x01"
MAX_LEAF_BYTES = 64 * 1024
MAX_CHECKPOINT_BYTES = 64 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_LEAF_FIELDS = {
    "schema",
    "receipt_b64",
    "signer_public_key_b64",
    "witness_enrollment_sha256",
}


class TransparencyError(RuntimeError):
    """A transparency artifact or proof is invalid."""


@dataclass(frozen=True)
class ReceiptTransparencyLeaf:
    receipt: AnchorReceipt
    receipt_bytes: bytes
    signer_public_key: Ed25519PublicKey
    witness_enrollment_sha256: str | None

    def to_dict(self) -> dict[str, Any]:
        raw_key = self.signer_public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return {
            "schema": LEAF_SCHEMA,
            "receipt_b64": base64.b64encode(self.receipt_bytes).decode("ascii"),
            "signer_public_key_b64": base64.b64encode(raw_key).decode("ascii"),
            "witness_enrollment_sha256": self.witness_enrollment_sha256,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_dict()) + b"\n"

    @property
    def receipt_sha256(self) -> str:
        return self.receipt.receipt_sha256()


@dataclass(frozen=True)
class Checkpoint:
    origin: str
    tree_size: int
    root_hash: bytes
    note_text: bytes
    signed_note: bytes
    verified_key_name: str


def _strict_b64(value: Any, *, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise TransparencyError(f"{field} must be non-empty canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise TransparencyError(f"{field} is not strict base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise TransparencyError(f"{field} is not canonical base64")
    return decoded


def _validate_receipt_leaf(
    receipt_bytes: bytes,
    public_key: Ed25519PublicKey,
    witness_enrollment_sha256: str | None,
) -> AnchorReceipt:
    try:
        receipt = AnchorReceipt.from_bytes(receipt_bytes)
    except AnchorError as exc:
        raise TransparencyError(f"receipt leaf contains an invalid receipt: {exc}") from exc
    if receipt.signer_key_id != public_key_id(public_key):
        raise TransparencyError("receipt leaf public key does not match signer_key_id")
    try:
        signature = base64.b64decode(receipt.signature, validate=True)
        public_key.verify(signature, SIGNATURE_DOMAIN + canonical_json(receipt.body()))
    except (ValueError, binascii.Error, InvalidSignature) as exc:
        raise TransparencyError("receipt leaf signature is invalid") from exc
    if receipt.anchor_kind == UNIX_WITNESS_ANCHOR_KIND:
        if (
            not isinstance(witness_enrollment_sha256, str)
            or _HEX64.fullmatch(witness_enrollment_sha256) is None
        ):
            raise TransparencyError("Unix-witness receipt leaf requires an enrollment commitment")
    elif witness_enrollment_sha256 is not None:
        raise TransparencyError("only Unix-witness receipt leaves may carry an enrollment commitment")
    return receipt


def build_receipt_transparency_leaf(
    receipt_bytes: bytes,
    public_key: Ed25519PublicKey,
    *,
    witness_enrollment_sha256: str | None = None,
    disclosure_reviewed: bool = False,
) -> ReceiptTransparencyLeaf:
    """Build a public leaf only after an explicit disclosure review.

    A receipt exposes its run ID, signed time, cadence, Ledger head, and signer
    identity.  The opt-in is deliberately mandatory so existing private
    receipts cannot be converted into publication-ready bytes accidentally.
    """
    if disclosure_reviewed is not True:
        raise TransparencyError("receipt disclosure review is required before building a public leaf")
    receipt = _validate_receipt_leaf(receipt_bytes, public_key, witness_enrollment_sha256)
    leaf = ReceiptTransparencyLeaf(receipt, receipt_bytes, public_key, witness_enrollment_sha256)
    if len(leaf.canonical_bytes()) > MAX_LEAF_BYTES:
        raise TransparencyError("receipt transparency leaf exceeds the size limit")
    return leaf


def parse_receipt_transparency_leaf(data: bytes) -> ReceiptTransparencyLeaf:
    if not data.endswith(b"\n") or len(data) > MAX_LEAF_BYTES:
        raise TransparencyError("receipt transparency leaf must be bounded and newline-terminated")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TransparencyError("receipt transparency leaf is invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != _LEAF_FIELDS or value["schema"] != LEAF_SCHEMA:
        raise TransparencyError("receipt transparency leaf fields/schema are invalid")
    if canonical_json(value) + b"\n" != data:
        raise TransparencyError("receipt transparency leaf is not canonical JSON")
    receipt_bytes = _strict_b64(value["receipt_b64"], field="receipt_b64")
    raw_key = _strict_b64(value["signer_public_key_b64"], field="signer_public_key_b64")
    if len(raw_key) != 32:
        raise TransparencyError("receipt leaf Ed25519 public key must be 32 bytes")
    public_key = Ed25519PublicKey.from_public_bytes(raw_key)
    commitment = value["witness_enrollment_sha256"]
    receipt = _validate_receipt_leaf(receipt_bytes, public_key, commitment)
    return ReceiptTransparencyLeaf(receipt, receipt_bytes, public_key, commitment)


def leaf_hash(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise TransparencyError("Merkle node inputs must be SHA-256 hashes")
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_less_than(value: int) -> int:
    if value < 2:
        raise ValueError("value must be at least two")
    return 1 << ((value - 1).bit_length() - 1)


def _root_from_hashes(hashes: Sequence[bytes]) -> bytes:
    size = len(hashes)
    if size == 0:
        return hashlib.sha256(b"").digest()
    if size == 1:
        item = hashes[0]
        if len(item) != 32:
            raise TransparencyError("Merkle leaf hash must be 32 bytes")
        return item
    split = _largest_power_of_two_less_than(size)
    return node_hash(_root_from_hashes(hashes[:split]), _root_from_hashes(hashes[split:]))


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    return _root_from_hashes(tuple(leaf_hash(leaf) for leaf in leaves))


def inclusion_proof(leaves: Sequence[bytes], leaf_index: int) -> tuple[bytes, ...]:
    hashes = tuple(leaf_hash(leaf) for leaf in leaves)
    if not isinstance(leaf_index, int) or isinstance(leaf_index, bool) or not 0 <= leaf_index < len(hashes):
        raise TransparencyError("inclusion proof leaf index is out of range")

    def path(items: Sequence[bytes], index: int) -> tuple[bytes, ...]:
        if len(items) == 1:
            return ()
        split = _largest_power_of_two_less_than(len(items))
        if index < split:
            return path(items[:split], index) + (_root_from_hashes(items[split:]),)
        return path(items[split:], index - split) + (_root_from_hashes(items[:split]),)

    return path(hashes, leaf_index)


def verify_inclusion_proof(
    leaf: bytes,
    leaf_index: int,
    tree_size: int,
    proof: Sequence[bytes],
    expected_root: bytes,
) -> bool:
    if (
        not isinstance(leaf_index, int)
        or isinstance(leaf_index, bool)
        or not isinstance(tree_size, int)
        or isinstance(tree_size, bool)
        or not 0 <= leaf_index < tree_size
        or len(expected_root) != 32
        or any(len(item) != 32 for item in proof)
    ):
        return False
    position = 0

    def rebuild(index: int, size: int) -> bytes:
        nonlocal position
        if size == 1:
            return leaf_hash(leaf)
        split = _largest_power_of_two_less_than(size)
        if index < split:
            left = rebuild(index, split)
            if position >= len(proof):
                raise TransparencyError("inclusion proof is truncated")
            right = proof[position]
            position += 1
            return node_hash(left, right)
        right = rebuild(index - split, size - split)
        if position >= len(proof):
            raise TransparencyError("inclusion proof is truncated")
        left = proof[position]
        position += 1
        return node_hash(left, right)

    try:
        rebuilt = rebuild(leaf_index, tree_size)
    except TransparencyError:
        return False
    return position == len(proof) and rebuilt == expected_root


def consistency_proof(leaves: Sequence[bytes], old_size: int) -> tuple[bytes, ...]:
    hashes = tuple(leaf_hash(leaf) for leaf in leaves)
    new_size = len(hashes)
    if not isinstance(old_size, int) or isinstance(old_size, bool) or old_size < 0 or old_size > new_size:
        raise TransparencyError("consistency proof old size is out of range")
    if old_size in {0, new_size}:
        return ()

    def subproof(m: int, items: Sequence[bytes], complete: bool) -> tuple[bytes, ...]:
        if m == len(items):
            return () if complete else (_root_from_hashes(items),)
        split = _largest_power_of_two_less_than(len(items))
        if m <= split:
            return subproof(m, items[:split], complete) + (_root_from_hashes(items[split:]),)
        return subproof(m - split, items[split:], False) + (_root_from_hashes(items[:split]),)

    return subproof(old_size, hashes, True)


def verify_consistency_proof(
    old_size: int,
    new_size: int,
    old_root: bytes,
    new_root: bytes,
    proof: Sequence[bytes],
) -> bool:
    if (
        not isinstance(old_size, int)
        or isinstance(old_size, bool)
        or not isinstance(new_size, int)
        or isinstance(new_size, bool)
        or old_size < 0
        or new_size < old_size
        or len(old_root) != 32
        or len(new_root) != 32
        or any(len(item) != 32 for item in proof)
    ):
        return False
    if old_size == 0:
        return not proof and old_root == hashlib.sha256(b"").digest()
    if old_size == new_size:
        return not proof and old_root == new_root

    fn = old_size - 1
    sn = new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    position = 0
    if fn == 0:
        first_old = old_root
        first_new = old_root
    else:
        if not proof:
            return False
        first_old = proof[0]
        first_new = proof[0]
        position = 1
    old_hash = first_old
    new_hash = first_new
    while position < len(proof):
        item = proof[position]
        position += 1
        if sn == 0:
            return False
        if (fn & 1) == 1 or fn == sn:
            old_hash = node_hash(item, old_hash)
            new_hash = node_hash(item, new_hash)
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            new_hash = node_hash(new_hash, item)
        fn >>= 1
        sn >>= 1
    return sn == 0 and old_hash == old_root and new_hash == new_root


def _validate_checkpoint_identity(origin: str, key_name: str) -> None:
    for label, value in (("checkpoint origin", origin), ("checkpoint key name", key_name)):
        if (
            not isinstance(value, str)
            or not value
            or "+" in value
            or any(character.isspace() for character in value)
        ):
            raise TransparencyError(f"{label} is invalid")


def checkpoint_key_id(key_name: str, public_key: Ed25519PublicKey) -> bytes:
    _validate_checkpoint_identity(key_name, key_name)
    raw_key = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(key_name.encode("utf-8") + b"\n" + CHECKPOINT_SIGNATURE_TYPE + raw_key).digest()[:4]


def checkpoint_verifier_key(key_name: str, public_key: Ed25519PublicKey) -> str:
    identifier = checkpoint_key_id(key_name, public_key).hex()
    raw_key = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    material = base64.b64encode(CHECKPOINT_SIGNATURE_TYPE + raw_key).decode("ascii")
    return f"{key_name}+{identifier}+{material}"


def checkpoint_text(origin: str, tree_size: int, root_hash: bytes) -> bytes:
    _validate_checkpoint_identity(origin, origin)
    if not isinstance(tree_size, int) or isinstance(tree_size, bool) or tree_size < 0:
        raise TransparencyError("checkpoint tree size is invalid")
    if len(root_hash) != 32:
        raise TransparencyError("checkpoint root must be a SHA-256 hash")
    root = base64.b64encode(root_hash).decode("ascii")
    return f"{origin}\n{tree_size}\n{root}\n".encode()


def sign_checkpoint(
    origin: str,
    tree_size: int,
    root_hash: bytes,
    private_key: Ed25519PrivateKey,
    *,
    key_name: str | None = None,
) -> bytes:
    key_name = origin if key_name is None else key_name
    _validate_checkpoint_identity(origin, key_name)
    text = checkpoint_text(origin, tree_size, root_hash)
    identifier = checkpoint_key_id(key_name, private_key.public_key())
    signature = identifier + private_key.sign(text)
    line = f"— {key_name} {base64.b64encode(signature).decode('ascii')}\n".encode()
    signed = text + b"\n" + line
    if len(signed) > MAX_CHECKPOINT_BYTES:
        raise TransparencyError("signed checkpoint exceeds the size limit")
    return signed


def verify_checkpoint(
    signed_note: bytes,
    expected_origin: str,
    public_key: Ed25519PublicKey,
    *,
    key_name: str | None = None,
) -> Checkpoint:
    key_name = expected_origin if key_name is None else key_name
    _validate_checkpoint_identity(expected_origin, key_name)
    if not signed_note.endswith(b"\n") or len(signed_note) > MAX_CHECKPOINT_BYTES:
        raise TransparencyError("signed checkpoint must be bounded and newline-terminated")
    try:
        decoded = signed_note.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TransparencyError("signed checkpoint is not UTF-8") from exc
    if any(ord(character) < 0x20 and character != "\n" for character in decoded):
        raise TransparencyError("signed checkpoint contains an ASCII control character")
    try:
        body_without_final_newline, signature_block = signed_note[:-1].rsplit(b"\n\n", 1)
    except ValueError as exc:
        raise TransparencyError("signed checkpoint lacks its signature separator") from exc
    note_text = body_without_final_newline + b"\n"
    try:
        lines = note_text.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise TransparencyError("checkpoint text is not UTF-8") from exc
    if len(lines) != 3 or any(not line for line in lines):
        raise TransparencyError("checkpoint must have exactly three non-empty lines")
    origin, size_text, root_text = lines
    if origin != expected_origin:
        raise TransparencyError("checkpoint origin is not the expected log")
    if size_text != "0" and (
        not size_text.isascii() or not size_text.isdecimal() or size_text.startswith("0")
    ):
        raise TransparencyError("checkpoint tree size is not canonical decimal")
    tree_size = int(size_text)
    root_hash = _strict_b64(root_text, field="checkpoint root")
    if len(root_hash) != 32 or checkpoint_text(origin, tree_size, root_hash) != note_text:
        raise TransparencyError("checkpoint text is not canonical")

    signature_lines = signature_block.split(b"\n")
    if not 1 <= len(signature_lines) <= 16:
        raise TransparencyError("checkpoint signature count is outside the accepted bound")
    expected_id = checkpoint_key_id(key_name, public_key)
    verified = False
    for raw_line in signature_lines:
        try:
            line = raw_line.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise TransparencyError("checkpoint signature line is not UTF-8") from exc
        parts = line.split(" ")
        if len(parts) != 3 or parts[0] != "—" or not parts[1] or not parts[2]:
            raise TransparencyError("checkpoint signature line is malformed")
        candidate_name = parts[1]
        _validate_checkpoint_identity(origin, candidate_name)
        encoded = _strict_b64(parts[2], field="checkpoint signature")
        if candidate_name != key_name or encoded[:4] != expected_id:
            continue
        if len(encoded) != 68:
            raise TransparencyError("known checkpoint Ed25519 signature has the wrong length")
        try:
            public_key.verify(encoded[4:], note_text)
        except InvalidSignature as exc:
            raise TransparencyError("known checkpoint signature is invalid") from exc
        verified = True
    if not verified:
        raise TransparencyError("checkpoint has no signature from the trusted log key")
    return Checkpoint(origin, tree_size, root_hash, note_text, signed_note, key_name)


def checkpoints_equivocate(first: Checkpoint, second: Checkpoint) -> bool:
    return (
        first.origin == second.origin
        and first.tree_size == second.tree_size
        and first.root_hash != second.root_hash
    )


def verify_checkpoint_update(
    previous: Checkpoint,
    current: Checkpoint,
    proof: Sequence[bytes],
) -> None:
    if previous.origin != current.origin:
        raise TransparencyError("checkpoint update changed log origin")
    if current.tree_size < previous.tree_size:
        raise TransparencyError("checkpoint rollback detected")
    if current.tree_size == previous.tree_size:
        if current.root_hash != previous.root_hash:
            raise TransparencyError("same-size checkpoint equivocation detected")
        if proof:
            raise TransparencyError("same-size checkpoint must not carry a consistency proof")
        return
    if not verify_consistency_proof(
        previous.tree_size,
        current.tree_size,
        previous.root_hash,
        current.root_hash,
        proof,
    ):
        raise TransparencyError("checkpoint is not append-only from the previous checkpoint")


def verify_complete_mirror(leaves: Sequence[bytes], checkpoint: Checkpoint) -> None:
    if len(leaves) != checkpoint.tree_size:
        raise TransparencyError("mirror entry count does not match checkpoint tree size")
    if merkle_root(leaves) != checkpoint.root_hash:
        raise TransparencyError("mirror entries do not reconstruct the checkpoint root")
