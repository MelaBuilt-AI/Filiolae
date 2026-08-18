from __future__ import annotations

import base64
import json
import random
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from filiolae.transparency import (
    TransparencyError,
    leaf_hash,
    merkle_root,
    parse_receipt_transparency_leaf,
    verify_checkpoint,
    verify_consistency_proof,
    verify_inclusion_proof,
)

ROOT = Path(__file__).parents[1]
VECTOR_PATH = ROOT / "tests" / "vectors" / "transparency-interop-v1.json"


def _vectors() -> tuple[dict[str, object], list[bytes]]:
    value = json.loads(VECTOR_PATH.read_bytes())
    leaves = [base64.b64decode(item, validate=True) for item in value["leaves_b64"]]
    return value, leaves


def _proof(items: list[str]) -> tuple[bytes, ...]:
    return tuple(bytes.fromhex(item) for item in items)


def test_frozen_vectors_are_current_and_dependency_pins_are_explicit() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "generate_transparency_interop_vectors.py"),
            "--check",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    vectors, _ = _vectors()
    assert vectors["schema"] == "filiolae.transparency-interop-v1"
    implementations = {item["module"]: item for item in vectors["independent_implementations"]}
    merkle = implementations["github.com/transparency-dev/merkle"]
    assert merkle["version"] == "v0.0.3-0.20260810124916-18521bfa2091"
    assert merkle["commit"] == "18521bfa2091e6ca34f242106002c33184098429"
    assert implementations["golang.org/x/mod/sumdb/note"]["version"] == "v0.39.0"
    go_mod = (ROOT / "interop" / "go" / "go.mod").read_text()
    assert "github.com/transparency-dev/merkle v0.0.3-0.20260810124916-18521bfa2091" in go_mod
    assert "golang.org/x/mod v0.39.0" in go_mod


def test_s2_plan_is_pinned_and_records_bounded_execution() -> None:
    plan = (ROOT / "docs" / "tessera-loopback-shadow-plan.md").read_text()
    assert "v1.0.4" in plan
    assert "6bca8e8d5e23c9941f2b8a08f512b373f7131730" in plan
    assert "bounded S2 acceptance passed" in plan
    assert 'net.Listen("tcp4", "127.0.0.1:0")' in plan
    assert "two complete monitor processes" in plan
    assert "Owner authorized execution" in plan
    assert "no S2 process, listener" in (ROOT / "docs" / "tessera-loopback-shadow-acceptance.md").read_text()


def test_frozen_go_python_vectors_verify_in_filiolae() -> None:
    vectors, leaves = _vectors()
    assert [leaf_hash(leaf).hex() for leaf in leaves] == vectors["leaf_hashes_hex"]
    roots = {item["tree_size"]: bytes.fromhex(item["root_hex"]) for item in vectors["roots"]}
    assert roots == {size: merkle_root(leaves[:size]) for size in range(len(leaves) + 1)}

    for item in vectors["inclusion_proofs"]:
        assert verify_inclusion_proof(
            leaves[item["leaf_index"]],
            item["leaf_index"],
            item["tree_size"],
            _proof(item["proof_hex"]),
            roots[item["tree_size"]],
        )
    for item in vectors["consistency_proofs"]:
        assert verify_consistency_proof(
            item["old_size"],
            item["new_size"],
            roots[item["old_size"]],
            roots[item["new_size"]],
            _proof(item["proof_hex"]),
        )

    checkpoint = vectors["checkpoint"]
    verifier_material = base64.b64decode(checkpoint["verifier_key"].split("+", 2)[2], validate=True)
    assert verifier_material[0] == 1
    public_key = Ed25519PublicKey.from_public_bytes(verifier_material[1:])
    parsed = verify_checkpoint(
        base64.b64decode(checkpoint["signed_note_b64"], validate=True),
        checkpoint["origin"],
        public_key,
    )
    assert parsed.tree_size == checkpoint["tree_size"]
    assert parsed.root_hash == roots[checkpoint["tree_size"]]
    parse_receipt_transparency_leaf(leaves[0])


def test_bounded_mutation_corpus_rejects_leaf_checkpoint_and_proof_tampering() -> None:
    vectors, leaves = _vectors()
    rng = random.Random(0xF1101AE)

    for original, verifier in (
        (leaves[0], parse_receipt_transparency_leaf),
        (
            base64.b64decode(vectors["checkpoint"]["signed_note_b64"], validate=True),
            lambda raw: verify_checkpoint(
                raw,
                vectors["checkpoint"]["origin"],
                Ed25519PublicKey.from_public_bytes(
                    base64.b64decode(
                        vectors["checkpoint"]["verifier_key"].split("+", 2)[2],
                        validate=True,
                    )[1:]
                ),
            ),
        ),
    ):
        for _ in range(256):
            altered = bytearray(original)
            position = rng.randrange(len(altered))
            altered[position] ^= 1 << rng.randrange(8)
            with pytest.raises(TransparencyError):
                verifier(bytes(altered))

    roots = {item["tree_size"]: bytes.fromhex(item["root_hex"]) for item in vectors["roots"]}
    for item in vectors["inclusion_proofs"]:
        proof = list(_proof(item["proof_hex"]))
        if not proof:
            continue
        altered = bytearray(proof[0])
        altered[rng.randrange(len(altered))] ^= 1 << rng.randrange(8)
        proof[0] = bytes(altered)
        assert not verify_inclusion_proof(
            leaves[item["leaf_index"]],
            item["leaf_index"],
            item["tree_size"],
            proof,
            roots[item["tree_size"]],
        )
    for item in vectors["consistency_proofs"]:
        proof = list(_proof(item["proof_hex"]))
        if not proof:
            continue
        altered = bytearray(proof[0])
        altered[rng.randrange(len(altered))] ^= 1 << rng.randrange(8)
        proof[0] = bytes(altered)
        assert not verify_consistency_proof(
            item["old_size"],
            item["new_size"],
            roots[item["old_size"]],
            roots[item["new_size"]],
            proof,
        )
