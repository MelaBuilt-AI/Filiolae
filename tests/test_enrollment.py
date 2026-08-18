from __future__ import annotations

import json
from pathlib import Path

import pytest

from filiolae.anchor import UNIX_WITNESS_ANCHOR_KIND, generate_keypair, load_public_key
from filiolae.canonical import canonical_json
from filiolae.charter import Charter
from filiolae.cli import main
from filiolae.enrollment import (
    EnrollmentError,
    create_witness_enrollment,
    load_witness_enrollment,
)
from filiolae.ledger import Ledger


def _keys(tmp_path: Path):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    generate_keypair(private, public)
    return private, public


def test_pre_enrollment_binds_planned_genesis_before_ledger_exists(
    tmp_path: Path, charter_path: Path
) -> None:
    _, public = _keys(tmp_path)
    charter = Charter.load(charter_path)
    ledger_path = tmp_path / "planned" / "ledger.jsonl"
    manifest = tmp_path / "witness" / "enrollment.json"

    created = create_witness_enrollment(
        manifest,
        ledger_path=ledger_path,
        run_id="reviewed-run",
        genesis_charter_sha256=charter.sha256,
        public_key=load_public_key(public),
    )
    loaded = load_witness_enrollment(manifest)

    assert loaded == created
    assert manifest.stat().st_mode & 0o777 == 0o600
    assert loaded.anchor_kind == UNIX_WITNESS_ANCHOR_KIND
    ledger = Ledger.create(
        ledger_path,
        artifact_root=tmp_path / "artifacts",
        run_id="reviewed-run",
        charter_sha256=charter.sha256,
        metadata={
            "head_anchors_required": True,
            "anchor_kind": loaded.anchor_kind,
            "anchor_signer_key_id": loaded.signer_key_id,
            "witness_enrollment_sha256": loaded.sha256,
        },
    )
    loaded.validate_configuration(ledger, load_public_key(public))
    loaded.validate_ledger(ledger)


def test_enrollment_is_strictly_one_time_not_idempotent(tmp_path: Path, charter_path: Path) -> None:
    _, public = _keys(tmp_path)
    kwargs = {
        "ledger_path": tmp_path / "ledger.jsonl",
        "run_id": "one-time",
        "genesis_charter_sha256": Charter.load(charter_path).sha256,
        "public_key": load_public_key(public),
    }
    manifest = tmp_path / "enrollment.json"
    create_witness_enrollment(manifest, **kwargs)

    with pytest.raises(EnrollmentError, match="replay or conflict"):
        create_witness_enrollment(manifest, **kwargs)
    with pytest.raises(EnrollmentError, match="replay or conflict"):
        create_witness_enrollment(manifest, **{**kwargs, "run_id": "conflict"})


def test_enrollment_rejects_run_charter_path_and_signer_substitution(
    tmp_path: Path, charter_path: Path
) -> None:
    _, public = _keys(tmp_path / "right")
    _, wrong_public = _keys(tmp_path / "wrong")
    charter = Charter.load(charter_path)
    ledger_path = tmp_path / "ledger.jsonl"
    manifest = tmp_path / "enrollment.json"
    enrollment = create_witness_enrollment(
        manifest,
        ledger_path=ledger_path,
        run_id="bound-run",
        genesis_charter_sha256=charter.sha256,
        public_key=load_public_key(public),
    )

    wrong_path = Ledger(tmp_path / "substitute.jsonl", artifact_root=tmp_path)
    with pytest.raises(EnrollmentError, match="path contradicts"):
        enrollment.validate_configuration(wrong_path, load_public_key(public))
    configured = Ledger(ledger_path, artifact_root=tmp_path)
    with pytest.raises(EnrollmentError, match="signer key contradicts"):
        enrollment.validate_configuration(configured, load_public_key(wrong_public))

    for run_id, digest, message in [
        ("wrong-run", charter.sha256, "run ID contradicts"),
        ("bound-run", "b" * 64, "Charter digest contradicts"),
    ]:
        candidate = tmp_path / f"{run_id}-{digest[:4]}.jsonl"
        ledger = Ledger.create(
            candidate,
            artifact_root=tmp_path,
            run_id=run_id,
            charter_sha256=digest,
            metadata={
                "head_anchors_required": True,
                "anchor_kind": enrollment.anchor_kind,
                "anchor_signer_key_id": enrollment.signer_key_id,
                "witness_enrollment_sha256": enrollment.sha256,
            },
        )
        # Test genesis tuple independently of the separately checked path binding.
        with pytest.raises(EnrollmentError, match=message):
            enrollment.validate_ledger(ledger)


def test_enrollment_rejects_genesis_signer_policy_substitution(tmp_path: Path, charter_path: Path) -> None:
    _, public = _keys(tmp_path)
    charter = Charter.load(charter_path)
    ledger_path = tmp_path / "ledger.jsonl"
    enrollment = create_witness_enrollment(
        tmp_path / "enrollment.json",
        ledger_path=ledger_path,
        run_id="policy-run",
        genesis_charter_sha256=charter.sha256,
        public_key=load_public_key(public),
    )
    ledger = Ledger.create(
        ledger_path,
        artifact_root=tmp_path,
        run_id="policy-run",
        charter_sha256=charter.sha256,
        metadata={
            "head_anchors_required": True,
            "anchor_kind": enrollment.anchor_kind,
            "anchor_signer_key_id": "sha256:" + "f" * 64,
            "witness_enrollment_sha256": enrollment.sha256,
        },
    )
    with pytest.raises(EnrollmentError, match="signer policy contradicts"):
        enrollment.validate_ledger(ledger)


def test_enrollment_loader_rejects_tamper_noncanonical_and_unsafe_mode(
    tmp_path: Path, charter_path: Path
) -> None:
    _, public = _keys(tmp_path)
    manifest = tmp_path / "enrollment.json"
    enrollment = create_witness_enrollment(
        manifest,
        ledger_path=tmp_path / "ledger.jsonl",
        run_id="strict-run",
        genesis_charter_sha256=Charter.load(charter_path).sha256,
        public_key=load_public_key(public),
    )
    value = enrollment.to_dict()
    manifest.write_text(json.dumps(value, indent=2) + "\n")
    with pytest.raises(EnrollmentError, match="canonical"):
        load_witness_enrollment(manifest)
    invalid_signer = {**value, "signer_key_id": "sha256:" + "g" * 64}
    manifest.write_bytes(canonical_json(invalid_signer) + b"\n")
    with pytest.raises(EnrollmentError, match="signer key ID"):
        load_witness_enrollment(manifest)
    manifest.write_bytes(canonical_json(value) + b"\n")
    manifest.chmod(0o666)
    with pytest.raises(EnrollmentError, match="metadata is unsafe"):
        load_witness_enrollment(manifest)


def test_enrollment_cli_creates_reviewable_manifest_once(tmp_path: Path, charter_path: Path, capsys) -> None:
    _, public = _keys(tmp_path)
    manifest = tmp_path / "witness" / "enrollment.json"
    args = [
        "anchor-witness-enroll",
        str(tmp_path / "planned" / "ledger.jsonl"),
        "--charter",
        str(charter_path),
        "--run-id",
        "owner-reviewed-run",
        "--public-key",
        str(public),
        "--enrollment",
        str(manifest),
    ]
    assert main(args) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["schema"] == "filiolae.witness-enrollment.v1"
    assert output["enrollment_sha256"] == load_witness_enrollment(manifest).sha256
    with pytest.raises(EnrollmentError, match="replay or conflict"):
        main(args)


def test_enrollment_rejects_retroactive_receipt_store(tmp_path: Path, charter_path: Path) -> None:
    _, public = _keys(tmp_path)
    receipts = tmp_path / "witness" / "receipts"
    receipts.mkdir(parents=True)
    (receipts / "existing.anchor.json").write_text("retained")
    with pytest.raises(EnrollmentError, match="retroactive"):
        create_witness_enrollment(
            tmp_path / "witness" / "enrollment.json",
            ledger_path=tmp_path / "ledger.jsonl",
            run_id="too-late",
            genesis_charter_sha256=Charter.load(charter_path).sha256,
            public_key=load_public_key(public),
        )


def test_enrollment_cli_rejects_existing_ledger(tmp_path: Path, charter_path: Path) -> None:
    _, public = _keys(tmp_path)
    ledger_path = tmp_path / "already-created.jsonl"
    Ledger.create(
        ledger_path,
        artifact_root=tmp_path / "artifacts",
        run_id="too-late",
        charter_sha256=Charter.load(charter_path).sha256,
    )

    with pytest.raises(EnrollmentError, match="retroactive"):
        main(
            [
                "anchor-witness-enroll",
                str(ledger_path),
                "--charter",
                str(charter_path),
                "--run-id",
                "too-late",
                "--public-key",
                str(public),
                "--enrollment",
                str(tmp_path / "enrollment.json"),
            ]
        )


def test_enrollment_rechecks_late_symlinked_ledger_parent(tmp_path: Path, charter_path: Path) -> None:
    _, public = _keys(tmp_path / "keys")
    charter = Charter.load(charter_path)
    planned = tmp_path / "planned" / "control" / "ledger.jsonl"
    enrollment = create_witness_enrollment(
        tmp_path / "witness" / "enrollment.json",
        ledger_path=planned,
        run_id="late-symlink",
        genesis_charter_sha256=charter.sha256,
        public_key=load_public_key(public),
    )
    substitute = tmp_path / "substitute" / "control" / "ledger.jsonl"
    Ledger.create(
        substitute,
        artifact_root=tmp_path / "artifacts",
        run_id="late-symlink",
        charter_sha256=charter.sha256,
        metadata={
            "head_anchors_required": True,
            "anchor_kind": enrollment.anchor_kind,
            "anchor_signer_key_id": enrollment.signer_key_id,
            "witness_enrollment_sha256": enrollment.sha256,
        },
    )
    (tmp_path / "planned").symlink_to(tmp_path / "substitute", target_is_directory=True)

    with pytest.raises(EnrollmentError, match="symlink component rejected"):
        enrollment.validate_ledger(Ledger(planned, artifact_root=tmp_path / "artifacts"))
