#!/usr/bin/env python3
"""Generate deterministic public synthetic receipt leaves for S2."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
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
from filiolae.transparency import build_receipt_transparency_leaf


def generate(count: int) -> tuple[list[bytes], dict[str, object]]:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public_key = private_key.public_key()
    previous = ZERO_HASH
    leaves: list[bytes] = []
    receipts: list[str] = []
    base_time = datetime(2026, 8, 13, 14, 0, tzinfo=UTC)
    for index in range(count):
        body = {
            "schema": RECEIPT_SCHEMA,
            "anchor_kind": LOCAL_ANCHOR_KIND,
            "anchor_seq": index,
            "run_id": f"synthetic-s2-{index:04d}-7fb01f58c1b94e36b6909e0da3f755c8",
            "ledger_schema": LEDGER_SCHEMA,
            "ledger_seq": index + 1,
            "ledger_head_sha256": hashlib.sha256(f"synthetic-s2-ledger-{index}".encode()).hexdigest(),
            "previous_receipt_sha256": previous,
            "signer_key_id": public_key_id(public_key),
            "signed_at": (base_time + timedelta(seconds=index))
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
        }
        signature = private_key.sign(SIGNATURE_DOMAIN + canonical_json(body))
        receipt = AnchorReceipt(**body, signature=base64.b64encode(signature).decode())
        leaf = build_receipt_transparency_leaf(
            receipt.canonical_bytes(),
            public_key,
            disclosure_reviewed=True,
        ).canonical_bytes()
        leaves.append(leaf)
        receipts.append(receipt.receipt_sha256())
        previous = receipt.receipt_sha256()
    manifest = {
        "schema": "filiolae.transparency-s2-synthetic-fixture.v1",
        "description": "Public deterministic synthetic test material; forbidden for production signing.",
        "count": count,
        "leaves": [
            {
                "index": index,
                "filename": f"{index:020d}.leaf",
                "sha256": hashlib.sha256(leaf).hexdigest(),
                "receipt_sha256": receipts[index],
            }
            for index, leaf in enumerate(leaves)
        ],
    }
    return leaves, manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, default=16)
    args = parser.parse_args()
    if not 12 <= args.count <= 64:
        parser.error("count must be between 12 and 64")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    leaves, manifest = generate(args.count)
    for index, leaf in enumerate(leaves):
        path = args.output / f"{index:020d}.leaf"
        path.write_bytes(leaf)
        path.chmod(0o600)
    manifest_path = args.output / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    manifest_path.chmod(0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
