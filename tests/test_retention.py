from __future__ import annotations

import json
from pathlib import Path

import pytest

from filiolae.anchor import (
    UNIX_WITNESS_ANCHOR_KIND,
    AnchorStore,
    anchor_ledger_head,
    generate_keypair,
    load_private_key,
    load_public_key,
)
from filiolae.cli import main
from filiolae.enrollment import create_witness_enrollment
from filiolae.ledger import Ledger, provision_ledger_lock
from filiolae.retention import (
    MANIFEST_NAME,
    ReceiptRetentionError,
    export_receipt_retention_bundle,
    verify_receipt_retention_bundle,
)


def _retained_witness(tmp_path: Path):
    private = tmp_path / "keys" / "private.pem"
    public = tmp_path / "keys" / "public.pem"
    key_id = generate_keypair(private, public)
    lock = tmp_path / "run" / "ledger.lock"
    provision_ledger_lock(lock, mode=0o600)
    ledger_path = tmp_path / "run" / "ledger.jsonl"
    enrollment_path = tmp_path / "witness" / "enrollment.json"
    enrollment = create_witness_enrollment(
        enrollment_path,
        ledger_path=ledger_path,
        run_id="retention-run",
        genesis_charter_sha256="a" * 64,
        public_key=load_public_key(public),
    )
    ledger = Ledger.create(
        ledger_path,
        artifact_root=tmp_path / "run",
        lock_path=lock,
        require_existing_lock=True,
        run_id="retention-run",
        charter_sha256="a" * 64,
        metadata={
            "head_anchors_required": True,
            "anchor_kind": UNIX_WITNESS_ANCHOR_KIND,
            "anchor_signer_key_id": key_id,
            "witness_enrollment_sha256": enrollment.sha256,
        },
    )
    store = AnchorStore(tmp_path / "witness" / "authoritative")
    anchor_ledger_head(
        ledger,
        store,
        load_private_key(private),
        anchor_kind=UNIX_WITNESS_ANCHOR_KIND,
    )
    ledger.append("test.observed", actor="service:test", data={"value": 1})
    anchor_ledger_head(
        ledger,
        store,
        load_private_key(private),
        anchor_kind=UNIX_WITNESS_ANCHOR_KIND,
    )
    return ledger, store, private, public, enrollment, enrollment_path


def _make_writable(path: Path) -> None:
    path.chmod(0o700 if path.is_dir() else 0o600)


def test_static_retention_export_is_deterministic_and_verifies(tmp_path: Path) -> None:
    ledger, store, _, public, enrollment, _ = _retained_witness(tmp_path)
    first = export_receipt_retention_bundle(
        ledger,
        store,
        load_public_key(public),
        tmp_path / "export-one",
        witness_enrollment=enrollment,
    )
    second = export_receipt_retention_bundle(
        ledger,
        store,
        load_public_key(public),
        tmp_path / "export-two",
        witness_enrollment=enrollment,
    )
    assert first.manifest == second.manifest
    assert first.manifest_sha256 == second.manifest_sha256
    assert first.manifest_object_key == second.manifest_object_key
    assert first.receipt_count == 2
    assert "retention-run" not in first.object_prefix
    assert first.manifest_object_key.startswith(first.object_prefix + "/manifests/")

    verified = verify_receipt_retention_bundle(
        ledger,
        tmp_path / "export-one",
        load_public_key(public),
    )
    assert verified == first
    manifest = json.loads((tmp_path / "export-one" / MANIFEST_NAME).read_bytes())
    assert manifest["witness_enrollment_sha256"] == enrollment.sha256
    assert [item["anchor_seq"] for item in manifest["objects"] if item["kind"] == "anchor_receipt"] == [
        0,
        1,
    ]


def test_export_requires_fresh_output_and_witness_enrollment(tmp_path: Path) -> None:
    ledger, store, _, public, enrollment, _ = _retained_witness(tmp_path)
    with pytest.raises(ReceiptRetentionError, match="requires its enrollment"):
        export_receipt_retention_bundle(
            ledger,
            store,
            load_public_key(public),
            tmp_path / "missing-enrollment",
        )
    output = tmp_path / "export"
    export_receipt_retention_bundle(
        ledger,
        store,
        load_public_key(public),
        output,
        witness_enrollment=enrollment,
    )
    with pytest.raises(ReceiptRetentionError, match="fresh absent"):
        export_receipt_retention_bundle(
            ledger,
            store,
            load_public_key(public),
            output,
            witness_enrollment=enrollment,
        )


def test_verifier_rejects_tamper_extra_objects_and_wrong_trust_root(tmp_path: Path) -> None:
    ledger, store, _, public, enrollment, _ = _retained_witness(tmp_path)
    bundle = tmp_path / "export"
    export_receipt_retention_bundle(
        ledger,
        store,
        load_public_key(public),
        bundle,
        witness_enrollment=enrollment,
    )
    receipt = next((bundle / "receipts").iterdir())
    _make_writable(receipt)
    receipt.write_bytes(receipt.read_bytes()[:-2] + b"0\n")
    with pytest.raises(ReceiptRetentionError, match="bytes differ"):
        verify_receipt_retention_bundle(ledger, bundle, load_public_key(public))

    clean = tmp_path / "clean-export"
    export_receipt_retention_bundle(
        ledger,
        store,
        load_public_key(public),
        clean,
        witness_enrollment=enrollment,
    )
    _make_writable(clean)
    (clean / "unexpected.txt").write_text("not manifested")
    with pytest.raises(ReceiptRetentionError, match="unexpected root"):
        verify_receipt_retention_bundle(ledger, clean, load_public_key(public))
    (clean / "unexpected.txt").unlink()

    other_private = tmp_path / "other-private.pem"
    other_public = tmp_path / "other-public.pem"
    generate_keypair(other_private, other_public)
    with pytest.raises(ReceiptRetentionError, match="out-of-band trust root"):
        verify_receipt_retention_bundle(ledger, clean, load_public_key(other_public))


def test_cli_exports_and_verifies_without_remote_retention_claim(tmp_path: Path, capsys) -> None:
    ledger, store, _, public, _, enrollment_path = _retained_witness(tmp_path)
    output = tmp_path / "cli-export"
    assert (
        main(
            [
                "retention-export",
                str(ledger.path),
                "--artifact-root",
                str(ledger.artifact_root),
                "--ledger-lock",
                str(ledger.lock_path),
                "--anchor-dir",
                str(store.root),
                "--public-key",
                str(public),
                "--witness-enrollment",
                str(enrollment_path),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    exported = json.loads(capsys.readouterr().out)
    assert exported["ok"] is True
    assert exported["provider_retention_verified"] is False
    assert exported["receipt_count"] == 2

    assert (
        main(
            [
                "retention-verify",
                str(output),
                str(ledger.path),
                "--artifact-root",
                str(ledger.artifact_root),
                "--ledger-lock",
                str(ledger.lock_path),
                "--public-key",
                str(public),
            ]
        )
        == 0
    )
    verified = json.loads(capsys.readouterr().out)
    assert verified["ok"] is True
    assert verified["manifest_sha256"] == exported["manifest_sha256"]
    assert verified["provider_retention_verified"] is False
