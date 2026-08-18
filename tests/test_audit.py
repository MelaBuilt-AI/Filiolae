from __future__ import annotations

from pathlib import Path

from filiolae.audit import audit_governance

from .helpers import governed_run


def test_unauthorized_promotion_detected(tmp_path: Path, charter) -> None:
    ledger, _, _, _, _, _ = governed_run(tmp_path, charter)
    ledger.append(
        "policy.promoted",
        actor="attacker",
        data={"attempt_id": "x", "step": 1, "source_policy_version": 0, "gate_approval_seq": 999},
    )
    report = audit_governance(ledger, charter)
    assert "unauthorized_promotion" in {issue.code for issue in report.issues}


def test_unconsumed_approval_is_ambiguous(tmp_path: Path, charter) -> None:
    ledger, _, files, request, _, gate = governed_run(tmp_path, charter)
    assert gate.authorize(request, current_policy_version=0, pending_weights_path=files["weights"]).allowed
    report = audit_governance(ledger, charter)
    assert "ambiguous_unconsumed_approval" in {issue.code for issue in report.issues}


def test_promotion_after_tripwire_detected(tmp_path: Path, charter) -> None:
    ledger, _, _, _, _, _ = governed_run(tmp_path, charter)
    ledger.append("tripwire.fired", actor="gate", data={"class": "T-REC", "reason": "test"})
    ledger.append(
        "policy.promoted",
        actor="attacker",
        data={"attempt_id": "x", "step": 1, "source_policy_version": 0, "gate_approval_seq": 1},
    )
    codes = {issue.code for issue in audit_governance(ledger, charter).issues}
    assert "promotion_after_tripwire" in codes


def test_run_exit_is_terminal_and_structurally_validated(tmp_path: Path, charter) -> None:
    ledger, _, _, _, _, _ = governed_run(tmp_path, charter)
    ledger.append(
        "run.exited",
        actor="service:test",
        data={"status": "unknown", "error": 7},
    )
    ledger.append(
        "run.exited",
        actor="service:test",
        data={"status": "success", "error": None},
    )
    ledger.append(
        "policy.promoted",
        actor="attacker",
        data={"attempt_id": "x", "step": 1, "source_policy_version": 0, "gate_approval_seq": 1},
    )
    codes = {issue.code for issue in audit_governance(ledger, charter).issues}
    assert {
        "run_exit_status_invalid",
        "run_exit_error_invalid",
        "duplicate_run_exit",
        "promotion_after_exit",
    } <= codes


def test_required_anchor_signatures_cannot_be_silently_skipped(tmp_path: Path, charter) -> None:
    from filiolae.ledger import Ledger

    ledger = Ledger.create(
        tmp_path / "ledger.jsonl",
        artifact_root=tmp_path / "artifacts",
        run_id="anchors-required",
        charter_sha256=charter.sha256,
        metadata={"head_anchors_required": True},
    )
    codes = {issue.code for issue in audit_governance(ledger, charter).issues}
    assert "anchors_unverified" in codes


def test_skipped_policy_transition_is_detected_offline(tmp_path: Path, charter) -> None:
    ledger, _, _, _, _, _ = governed_run(tmp_path, charter)
    prior_head = ledger.records()[-1].hash
    approval = ledger.append(
        "gate.approved",
        actor="gate",
        data={
            "attempt_id": "skip-to-2",
            "step": 2,
            "source_policy_version": 1,
            "evaluated_head": prior_head,
            "charter_sha256": charter.sha256,
        },
        expected_head=prior_head,
    )
    ledger.append(
        "policy.promoted",
        actor="adapter",
        data={
            "attempt_id": "skip-to-2",
            "step": 2,
            "source_policy_version": 1,
            "gate_approval_seq": approval.seq,
        },
    )
    codes = {issue.code for issue in audit_governance(ledger, charter).issues}
    assert "approval_policy_state_mismatch" in codes
    assert "promotion_policy_state_mismatch" in codes


def test_multiple_failure_outcomes_cannot_consume_one_approval(tmp_path: Path, charter) -> None:
    ledger, _, files, request, _, gate = governed_run(tmp_path, charter)
    decision = gate.authorize(
        request,
        current_policy_version=0,
        pending_weights_path=files["weights"],
    )
    assert decision.allowed
    for message in ("first", "second"):
        ledger.append(
            "weights.load_failed",
            actor="gate",
            data={
                "attempt_id": request.attempt_id,
                "step": request.step,
                "gate_approval_seq": decision.ledger_seq,
                "error": message,
            },
        )
    codes = {issue.code for issue in audit_governance(ledger, charter).issues}
    assert "reused_approval" in codes
