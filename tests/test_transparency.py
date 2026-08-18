from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from filiolae.anchor import (
    UNIX_WITNESS_ANCHOR_KIND,
    AnchorStore,
    anchor_ledger_head,
    generate_keypair,
    load_private_key,
    load_public_key,
)
from filiolae.canonical import canonical_json
from filiolae.ledger import Ledger
from filiolae.transparency import (
    LEAF_SCHEMA,
    TransparencyError,
    build_receipt_transparency_leaf,
    checkpoint_key_id,
    checkpoint_verifier_key,
    checkpoints_equivocate,
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    node_hash,
    parse_receipt_transparency_leaf,
    sign_checkpoint,
    verify_checkpoint,
    verify_checkpoint_update,
    verify_complete_mirror,
    verify_consistency_proof,
    verify_inclusion_proof,
)


def _receipt(tmp_path: Path, *, unix: bool = False):
    ledger = Ledger.create(
        tmp_path / "ledger.jsonl",
        artifact_root=tmp_path / "artifacts",
        run_id="opaque-7fb01f58c1b94e36b6909e0da3f755c8",
        charter_sha256="a" * 64,
    )
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    generate_keypair(private_path, public_path)
    private_key = load_private_key(private_path)
    public_key = load_public_key(public_path)
    anchor_kwargs = {"anchor_kind": UNIX_WITNESS_ANCHOR_KIND} if unix else {}
    receipt = anchor_ledger_head(
        ledger,
        AnchorStore(tmp_path / "anchors"),
        private_key,
        **anchor_kwargs,
    )
    return receipt, public_key


def _flip(value: bytes) -> bytes:
    return bytes([value[0] ^ 1]) + value[1:]


def test_public_leaf_preserves_exact_receipt_and_verification_material(tmp_path: Path) -> None:
    receipt, public_key = _receipt(tmp_path)
    with pytest.raises(TransparencyError, match="disclosure review"):
        build_receipt_transparency_leaf(receipt.canonical_bytes(), public_key)

    leaf = build_receipt_transparency_leaf(
        receipt.canonical_bytes(),
        public_key,
        disclosure_reviewed=True,
    )
    data = leaf.canonical_bytes()
    assert data.endswith(b"\n")
    assert leaf.receipt_bytes == receipt.canonical_bytes()
    parsed = parse_receipt_transparency_leaf(data)
    assert parsed.receipt == receipt
    assert parsed.receipt_bytes == receipt.canonical_bytes()
    assert parsed.receipt_sha256 == receipt.receipt_sha256()
    assert parsed.witness_enrollment_sha256 is None

    value = json.loads(data)
    assert value["schema"] == LEAF_SCHEMA
    assert base64.b64decode(value["receipt_b64"], validate=True) == receipt.canonical_bytes()
    assert len(base64.b64decode(value["signer_public_key_b64"], validate=True)) == 32
    assert set(value) == {
        "schema",
        "receipt_b64",
        "signer_public_key_b64",
        "witness_enrollment_sha256",
    }


def test_public_leaf_rejects_tampering_wrong_key_and_noncanonical_bytes(tmp_path: Path) -> None:
    receipt, public_key = _receipt(tmp_path / "first")
    _, wrong_key = _receipt(tmp_path / "second")
    with pytest.raises(TransparencyError, match="signer_key_id"):
        build_receipt_transparency_leaf(
            receipt.canonical_bytes(),
            wrong_key,
            disclosure_reviewed=True,
        )
    leaf = build_receipt_transparency_leaf(
        receipt.canonical_bytes(),
        public_key,
        disclosure_reviewed=True,
    )
    value = leaf.to_dict()
    receipt_value = json.loads(receipt.canonical_bytes())
    receipt_value["ledger_head_sha256"] = "b" * 64
    value["receipt_b64"] = base64.b64encode(canonical_json(receipt_value) + b"\n").decode("ascii")
    with pytest.raises(TransparencyError, match="signature"):
        parse_receipt_transparency_leaf(canonical_json(value) + b"\n")
    with pytest.raises(TransparencyError, match="canonical JSON"):
        parse_receipt_transparency_leaf(json.dumps(leaf.to_dict()).encode() + b"\n")


def test_unix_witness_leaf_requires_only_enrollment_commitment(tmp_path: Path) -> None:
    receipt, public_key = _receipt(tmp_path, unix=True)
    with pytest.raises(TransparencyError, match="enrollment commitment"):
        build_receipt_transparency_leaf(
            receipt.canonical_bytes(),
            public_key,
            disclosure_reviewed=True,
        )
    commitment = "c" * 64
    leaf = build_receipt_transparency_leaf(
        receipt.canonical_bytes(),
        public_key,
        witness_enrollment_sha256=commitment,
        disclosure_reviewed=True,
    )
    assert parse_receipt_transparency_leaf(leaf.canonical_bytes()).witness_enrollment_sha256 == commitment
    assert b"witness-enrollment" not in leaf.canonical_bytes()


def test_rfc6962_hash_vectors_and_exhaustive_inclusion_proofs() -> None:
    assert merkle_root([]).hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert leaf_hash(b"").hex() == "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    leaves = [f"leaf-{index}".encode() for index in range(40)]
    for size in range(1, len(leaves) + 1):
        root = merkle_root(leaves[:size])
        for index in range(size):
            proof = inclusion_proof(leaves[:size], index)
            assert verify_inclusion_proof(leaves[index], index, size, proof, root)
            assert not verify_inclusion_proof(leaves[index] + b"x", index, size, proof, root)
            assert not verify_inclusion_proof(leaves[index], index, size, proof + (b"x" * 32,), root)
            if proof:
                altered = (_flip(proof[0]),) + proof[1:]
                assert not verify_inclusion_proof(leaves[index], index, size, altered, root)


def test_rfc9162_seven_leaf_consistency_proof_structure() -> None:
    leaves = [f"d{index}".encode() for index in range(7)]
    hashes = [leaf_hash(leaf) for leaf in leaves]
    g = node_hash(hashes[0], hashes[1])
    h = node_hash(hashes[2], hashes[3])
    i = node_hash(hashes[4], hashes[5])
    k = node_hash(g, h)
    ell = node_hash(i, hashes[6])
    # RFC 9162 section 2.1.5: [c,d,g,l], [l], and [i,j,k].
    assert consistency_proof(leaves, 3) == (hashes[2], hashes[3], g, ell)
    assert consistency_proof(leaves, 4) == (ell,)
    assert consistency_proof(leaves, 6) == (i, hashes[6], k)


def test_exhaustive_consistency_proofs_and_tampering() -> None:
    leaves = [f"entry-{index}".encode() for index in range(40)]
    empty = merkle_root([])
    for new_size in range(len(leaves) + 1):
        new_root = merkle_root(leaves[:new_size])
        for old_size in range(new_size + 1):
            old_root = merkle_root(leaves[:old_size])
            proof = consistency_proof(leaves[:new_size], old_size)
            assert verify_consistency_proof(old_size, new_size, old_root, new_root, proof)
            if proof:
                altered = (_flip(proof[0]),) + proof[1:]
                assert not verify_consistency_proof(old_size, new_size, old_root, new_root, altered)
            if old_size not in {0, new_size}:
                assert not verify_consistency_proof(old_size, new_size, _flip(old_root), new_root, proof)
    assert not verify_consistency_proof(0, 1, _flip(empty), merkle_root(leaves[:1]), ())
    with pytest.raises(TransparencyError, match="out of range"):
        consistency_proof(leaves, 41)


def test_c2sp_checkpoint_signed_note_snapshot_and_verifier_key() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public_key = private_key.public_key()
    origin = "filiolae.example/log/receipts/v1"
    root = merkle_root([b"first", b"second", b"third"])
    signed = sign_checkpoint(origin, 3, root, private_key)
    expected = (
        b"filiolae.example/log/receipts/v1\n"
        b"3\n"
        + base64.b64encode(root)
        + b"\n\n"
        + "— filiolae.example/log/receipts/v1 ".encode()
        + base64.b64encode(
            checkpoint_key_id(origin, public_key)
            + private_key.sign(b"filiolae.example/log/receipts/v1\n3\n" + base64.b64encode(root) + b"\n")
        )
        + b"\n"
    )
    assert signed == expected
    assert checkpoint_verifier_key(origin, public_key).startswith(
        f"{origin}+{checkpoint_key_id(origin, public_key).hex()}+AQ"
    )
    verified = verify_checkpoint(signed, origin, public_key)
    assert verified.tree_size == 3
    assert verified.root_hash == root
    assert verified.note_text.endswith(b"\n")


def test_checkpoint_verification_ignores_unknown_cosignature_but_rejects_known_tamper() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    origin = "example.test/filiolae"
    signed = sign_checkpoint(origin, 1, merkle_root([b"leaf"]), private_key)
    unknown = base64.b64encode(b"wxyz" + b"u" * 64)
    with_unknown = signed + "— witness.example/key ".encode() + unknown + b"\n"
    assert verify_checkpoint(with_unknown, origin, public_key).tree_size == 1

    body, signature = signed[:-1].rsplit(b"\n\n", 1)
    raw = base64.b64decode(signature.split(b" ")[2], validate=True)
    broken = body + b"\n\n" + f"— {origin} ".encode() + base64.b64encode(raw[:4] + _flip(raw[4:])) + b"\n"
    with pytest.raises(TransparencyError, match="signature is invalid"):
        verify_checkpoint(broken, origin, public_key)
    with pytest.raises(TransparencyError, match="expected log"):
        verify_checkpoint(signed, "other.example/log", public_key)


def test_monitor_detects_append_only_growth_rollback_and_same_size_fork() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    origin = "monitor.example/filiolae"
    leaves = [f"leaf-{index}".encode() for index in range(8)]
    first = verify_checkpoint(
        sign_checkpoint(origin, 3, merkle_root(leaves[:3]), private_key),
        origin,
        public_key,
    )
    second = verify_checkpoint(
        sign_checkpoint(origin, 8, merkle_root(leaves), private_key),
        origin,
        public_key,
    )
    proof = consistency_proof(leaves, 3)
    verify_checkpoint_update(first, second, proof)

    with pytest.raises(TransparencyError, match="append-only"):
        verify_checkpoint_update(first, second, (_flip(proof[0]),) + proof[1:])
    with pytest.raises(TransparencyError, match="rollback"):
        verify_checkpoint_update(second, first, ())

    fork = verify_checkpoint(
        sign_checkpoint(origin, 3, merkle_root([b"fork-0", b"fork-1", b"fork-2"]), private_key),
        origin,
        public_key,
    )
    assert checkpoints_equivocate(first, fork)
    with pytest.raises(TransparencyError, match="equivocation"):
        verify_checkpoint_update(first, fork, ())
    verify_checkpoint_update(first, first, ())


def test_complete_mirror_and_inclusion_against_verified_checkpoint() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    origin = "mirror.example/filiolae"
    leaves = [b"receipt-a", b"receipt-b", b"receipt-c"]
    checkpoint = verify_checkpoint(
        sign_checkpoint(origin, len(leaves), merkle_root(leaves), private_key),
        origin,
        public_key,
    )
    verify_complete_mirror(leaves, checkpoint)
    proof = inclusion_proof(leaves, 1)
    assert verify_inclusion_proof(leaves[1], 1, checkpoint.tree_size, proof, checkpoint.root_hash)
    with pytest.raises(TransparencyError, match="entry count"):
        verify_complete_mirror(leaves[:-1], checkpoint)
    with pytest.raises(TransparencyError, match="reconstruct"):
        verify_complete_mirror([leaves[0], b"altered", leaves[2]], checkpoint)
