#!/usr/bin/env python3
"""Generate frozen, synthetic S1 transparency interoperability vectors.

The embedded Ed25519 seeds are public test material and MUST NOT be used for
real receipts or log checkpoints.  Generation is deterministic and network-free.
"""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from filiolae.anchor import (
    LOCAL_ANCHOR_KIND,
    RECEIPT_SCHEMA,
    SIGNATURE_DOMAIN,
    ZERO_HASH,
    AnchorReceipt,
    public_key_id,
)
from filiolae.canonical import canonical_json
from filiolae.ledger import SCHEMA as LEDGER_SCHEMA
from filiolae.transparency import (
    build_receipt_transparency_leaf,
    checkpoint_verifier_key,
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    sign_checkpoint,
)

ROOT = Path(__file__).parents[1]
DEFAULT_OUTPUT = ROOT / "tests" / "vectors" / "transparency-interop-v1.json"
MERKLE_MODULE = "github.com/transparency-dev/merkle"
MERKLE_VERSION = "v0.0.3-0.20260810124916-18521bfa2091"
MERKLE_COMMIT = "18521bfa2091e6ca34f242106002c33184098429"
NOTE_MODULE = "golang.org/x/mod/sumdb/note"
NOTE_VERSION = "v0.39.0"


def _synthetic_public_leaf() -> bytes:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public_key = private_key.public_key()
    body = {
        "schema": RECEIPT_SCHEMA,
        "anchor_kind": LOCAL_ANCHOR_KIND,
        "anchor_seq": 0,
        "run_id": "synthetic-interop-7fb01f58c1b94e36b6909e0da3f755c8",
        "ledger_schema": LEDGER_SCHEMA,
        "ledger_seq": 6,
        "ledger_head_sha256": "ab" * 32,
        "previous_receipt_sha256": ZERO_HASH,
        "signer_key_id": public_key_id(public_key),
        "signed_at": "2026-08-13T12:00:00.000000Z",
    }
    signature = private_key.sign(SIGNATURE_DOMAIN + canonical_json(body))
    receipt = AnchorReceipt(**body, signature=base64.b64encode(signature).decode("ascii"))
    return build_receipt_transparency_leaf(
        receipt.canonical_bytes(),
        public_key,
        disclosure_reviewed=True,
    ).canonical_bytes()


def build_vectors() -> dict[str, object]:
    leaves = [
        _synthetic_public_leaf(),
        b"",
        b"filiolae-synthetic-alpha\n",
        b"\x00\x01\x02binary\xff\n",
        "synthetic-unicode-aster-\u2736\n".encode(),
        bytes(range(32)),
        bytes((index * 73 + 19) % 256 for index in range(257)),
    ]
    roots = [
        {"tree_size": size, "root_hex": merkle_root(leaves[:size]).hex()} for size in range(len(leaves) + 1)
    ]
    inclusions = [
        {
            "tree_size": size,
            "leaf_index": index,
            "proof_hex": [item.hex() for item in inclusion_proof(leaves[:size], index)],
        }
        for size in (1, 3, 5, 7)
        for index in range(size)
    ]
    consistencies = [
        {
            "old_size": old_size,
            "new_size": new_size,
            "proof_hex": [item.hex() for item in consistency_proof(leaves[:new_size], old_size)],
        }
        for new_size in (1, 3, 5, 7)
        for old_size in range(1, new_size + 1)
    ]

    origin = "filiolae.invalid/synthetic-interop/v1"
    checkpoint_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    final_root = merkle_root(leaves)
    signed_note = sign_checkpoint(origin, len(leaves), final_root, checkpoint_key)
    return {
        "schema": "filiolae.transparency-interop-v1",
        "description": "Synthetic public test material; no production receipt or secret is present.",
        "independent_implementations": [
            {
                "module": MERKLE_MODULE,
                "version": MERKLE_VERSION,
                "commit": MERKLE_COMMIT,
                "roles": ["leaf_hash", "merkle_root", "inclusion_proof", "consistency_proof"],
            },
            {
                "module": NOTE_MODULE,
                "version": NOTE_VERSION,
                "roles": ["signed_note_checkpoint_verification"],
            },
        ],
        "leaves_b64": [base64.b64encode(leaf).decode("ascii") for leaf in leaves],
        "leaf_hashes_hex": [leaf_hash(leaf).hex() for leaf in leaves],
        "roots": roots,
        "inclusion_proofs": inclusions,
        "consistency_proofs": consistencies,
        "checkpoint": {
            "origin": origin,
            "tree_size": len(leaves),
            "root_hex": final_root.hex(),
            "verifier_key": checkpoint_verifier_key(origin, checkpoint_key.public_key()),
            "signed_note_b64": base64.b64encode(signed_note).decode("ascii"),
        },
    }


def encoded_vectors() -> bytes:
    return (json.dumps(build_vectors(), indent=2, sort_keys=True) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true", help="Fail unless the frozen file is current")
    args = parser.parse_args()
    encoded = encoded_vectors()
    if args.check:
        if not args.output.is_file() or args.output.read_bytes() != encoded:
            parser.error(f"frozen vector file is missing or stale: {args.output}")
        print(f"interop vectors current: {args.output}")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encoded)
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
