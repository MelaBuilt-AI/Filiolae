from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from filiolae.cli import main
from filiolae.explain import (
    MAX_ACTUAL_ARTIFACT_BYTES,
    MAX_ITEMS,
    ExplainError,
    explain_run,
    render_owner_text,
)

from .helpers import governed_run


def test_explain_owner_view_names_exact_authorized_weights(
    tmp_path: Path, charter, charter_path: Path
) -> None:
    ledger, _, files, request, _, gate = governed_run(tmp_path, charter)
    shutil.copyfile(charter_path, tmp_path / "control" / "charter.yaml")
    decision = gate.authorize(request, current_policy_version=0, pending_weights_path=files["weights"])
    ledger.append(
        "policy.promoted",
        actor="adapter",
        data={
            "attempt_id": request.attempt_id,
            "step": request.step,
            "source_policy_version": request.source_policy_version,
            "gate_approval_seq": decision.ledger_seq,
        },
    )

    report = explain_run(tmp_path)

    assert report["status"] == {
        "integrity": "valid",
        "operational": "promotion_recorded_run_open",
        "audit_ok": True,
        "promotion_count": 1,
        "history_suppressed": False,
    }
    assert report["decisions"][0]["decision"] == "promoted"
    authorized = report["decisions"][0]["authorized_weights"]
    approval = ledger.record(decision.ledger_seq or -1)
    assert authorized["path"] == approval.data["approved_checkpoint"]["path"]
    assert authorized["sha256"] == approval.data["approved_checkpoint"]["sha256"]
    text = render_owner_text(report)
    assert "authorized weights:" in text
    assert "Current non-claims:" in text
    assert "not independently evaluated" in text


def test_explain_surfaces_ambiguous_unconsumed_approval(tmp_path: Path, charter, charter_path: Path) -> None:
    _, _, files, request, _, gate = governed_run(tmp_path, charter)
    shutil.copyfile(charter_path, tmp_path / "control" / "charter.yaml")
    decision = gate.authorize(request, current_policy_version=0, pending_weights_path=files["weights"])
    assert decision.allowed

    report = explain_run(tmp_path)

    assert not report["status"]["audit_ok"]
    assert report["status"]["operational"] == "ambiguous"
    assert report["decisions"][0]["decision"] == "ambiguous_authorization"
    assert {issue["code"] for issue in report["ambiguities"]} == {"ambiguous_unconsumed_approval"}


def test_explain_required_receipts_are_not_silently_claimed_verified(
    tmp_path: Path, charter, charter_path: Path
) -> None:
    metadata = {
        "head_anchors_required": True,
        "anchor_kind": "filiolae.anchor.ed25519.v1",
        "anchor_signer_key_id": "a" * 64,
    }
    governed_run(tmp_path, charter, metadata=metadata)
    shutil.copyfile(charter_path, tmp_path / "control" / "charter.yaml")

    report = explain_run(tmp_path)

    assert report["anchors"]["required"] is True
    assert report["anchors"]["checked"] is False
    assert report["anchors"]["ok"] is None
    assert "anchors_unverified" in {issue["code"] for issue in report["audit_issues"]}


def test_explain_suppresses_history_when_ledger_structure_fails(
    tmp_path: Path, charter, charter_path: Path
) -> None:
    ledger, _, files, request, _, gate = governed_run(tmp_path, charter)
    shutil.copyfile(charter_path, tmp_path / "control" / "charter.yaml")
    decision = gate.authorize(request, current_policy_version=0, pending_weights_path=files["weights"])
    assert decision.allowed
    raw = ledger.path.read_bytes()
    assert b"attempt-1" in raw
    ledger.path.write_bytes(raw.replace(b"attempt-1", b"attempt-X"))

    report = explain_run(tmp_path)

    assert report["status"]["history_suppressed"] is True
    assert report["run"]["run_id"] is None
    assert report["decisions"] == []
    assert "record_hash_mismatch" in {issue["code"] for issue in report["audit_issues"]}


def test_explain_cli_text_and_json(tmp_path: Path, charter_path: Path, capsys) -> None:
    run = tmp_path / "demo"
    assert main(["demo", str(run), "--charter", str(charter_path)]) == 0
    capsys.readouterr()

    assert main(["explain", str(run)]) == 0
    text = capsys.readouterr().out
    assert "Filiolae run explanation" in text
    assert "step 1: promoted" in text

    assert main(["explain", str(run), "--json"]) == 0
    value = json.loads(capsys.readouterr().out)
    assert value["schema"] == "filiolae.explain.v1"
    assert value["run"]["run_id"] == "filiolae-prime-smoke"


def test_explain_rejects_ambiguous_layout_and_unbounded_output(tmp_path: Path, charter_path: Path) -> None:
    (tmp_path / "control" / "filiolae").mkdir(parents=True)
    (tmp_path / "control" / "ledger.jsonl").write_text("x")
    (tmp_path / "control" / "filiolae" / "ledger.jsonl").write_text("x")
    try:
        explain_run(tmp_path)
    except ExplainError as exc:
        assert "exactly one" in str(exc)
    else:
        raise AssertionError("ambiguous layout accepted")

    clean = tmp_path / "clean"
    clean.mkdir()
    try:
        explain_run(clean, max_items=MAX_ITEMS + 1)
    except ExplainError as exc:
        assert "max_items" in str(exc)
    else:
        raise AssertionError("unbounded output accepted")


def test_explain_rejects_symlinked_run_layout(tmp_path: Path, charter_path: Path) -> None:
    run = tmp_path / "real-run"
    assert main(["demo", str(run), "--charter", str(charter_path)]) == 0
    alias = tmp_path / "run-alias"
    alias.symlink_to(run, target_is_directory=True)
    with pytest.raises(ExplainError, match="symlink component rejected"):
        explain_run(alias)


def test_explain_rejects_actual_artifact_size_before_hashing(
    tmp_path: Path, charter, charter_path: Path
) -> None:
    ledger, _, _, _, _, _ = governed_run(tmp_path, charter)
    shutil.copyfile(charter_path, tmp_path / "control" / "charter.yaml")
    artifact = next(record.artifacts[0] for record in ledger.records() if record.artifacts)
    retained = ledger.artifact_root / artifact.path
    with retained.open("r+b") as stream:
        stream.truncate(MAX_ACTUAL_ARTIFACT_BYTES + 1)

    with pytest.raises(ExplainError, match="actual artifact bytes"):
        explain_run(tmp_path)
