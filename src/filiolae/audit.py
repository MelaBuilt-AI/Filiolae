"""Offline structural and semantic audit."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .anchor import SUPPORTED_ANCHOR_KINDS, UNIX_WITNESS_ANCHOR_KIND, AnchorAuditReport
from .charter import Charter
from .enrollment import EnrollmentError, WitnessEnrollment
from .ledger import AuditIssue, AuditReport, Ledger
from .paired_eval import verify_terminal_evidence
from .shadow_eval import (
    CandidateEvalError,
    CandidateEvalReceipt,
    CandidateEvalRequest,
    verify_candidate_eval_receipt,
)


@dataclass(frozen=True)
class GovernanceAuditReport:
    issues: tuple[AuditIssue, ...]
    record_count: int
    promotion_count: int

    @property
    def ok(self) -> bool:
        return not self.issues

    def summary(self) -> str:
        if self.ok:
            return f"Governance audit valid: {self.record_count} records, {self.promotion_count} promotion(s)"
        return "; ".join(f"{issue.code}@{issue.seq}: {issue.message}" for issue in self.issues)


def audit_governance(
    ledger: Ledger,
    charter: Charter,
    *,
    verify_artifacts: bool = True,
    anchor_report: AnchorAuditReport | None = None,
    candidate_eval_public_key: Ed25519PublicKey | None = None,
    witness_enrollment: WitnessEnrollment | None = None,
    structural_report: AuditReport | None = None,
) -> GovernanceAuditReport:
    structural = structural_report or ledger.audit(verify_artifacts=verify_artifacts)
    issues = list(structural.issues)
    records = structural.records
    if not records:
        return GovernanceAuditReport(tuple(issues), 0, 0)

    try:
        candidate_policy = charter.candidate_eval_policy()
    except (ValueError, CandidateEvalError) as exc:
        issues.append(AuditIssue("candidate_eval_policy_invalid", str(exc), 0))
        candidate_policy = None

    known_events = {
        "run.genesis",
        "config.resolved",
        "batch.committed",
        "source_eval.result",
        "weights.published",
        "candidate_eval.result",
        "candidate_eval.configured",
        "weights.load_failed",
        "gate.approved",
        "policy.promoted",
        "tripwire.fired",
        "gate.denied",
        "run.exited",
    }
    metadata = records[0].data.get("metadata", {})
    anchors_required = isinstance(metadata, dict) and metadata.get("head_anchors_required") is True
    policy_key = metadata.get("anchor_signer_key_id") if isinstance(metadata, dict) else None
    policy_kind = metadata.get("anchor_kind") if isinstance(metadata, dict) else None
    if anchors_required and (
        not isinstance(policy_key, str) or not policy_key or policy_kind not in SUPPORTED_ANCHOR_KINDS
    ):
        issues.append(
            AuditIssue(
                "anchor_policy_invalid",
                "genesis required-anchor policy lacks a valid signer key ID or anchor kind",
                0,
            )
        )
    enrollment_digest = metadata.get("witness_enrollment_sha256") if isinstance(metadata, dict) else None
    if policy_kind == UNIX_WITNESS_ANCHOR_KIND and (
        not isinstance(enrollment_digest, str)
        or len(enrollment_digest) != 64
        or any(character not in "0123456789abcdef" for character in enrollment_digest)
    ):
        issues.append(
            AuditIssue(
                "witness_enrollment_policy_invalid",
                "Unix witness genesis lacks a valid explicit enrollment digest",
                0,
            )
        )
    if policy_kind == UNIX_WITNESS_ANCHOR_KIND:
        if witness_enrollment is None:
            issues.append(
                AuditIssue(
                    "witness_enrollment_unverified",
                    "Unix witness policy requires the retained enrollment manifest for audit",
                    0,
                )
            )
        else:
            try:
                if witness_enrollment.ledger_path != str(Path(os.path.abspath(ledger.path))):
                    raise EnrollmentError("enrollment Ledger path differs from audited Ledger")
                witness_enrollment.validate_ledger(ledger)
            except EnrollmentError as exc:
                issues.append(AuditIssue("witness_enrollment_invalid", str(exc), 0))
    elif witness_enrollment is not None:
        issues.append(
            AuditIssue(
                "witness_enrollment_unexpected",
                "an enrollment manifest was supplied for a non-witness Ledger",
                0,
            )
        )
    receipts_by_digest = {}
    if anchor_report is None:
        if anchors_required:
            issues.append(
                AuditIssue(
                    "anchors_unverified",
                    "genesis requires signed head receipts but no anchor audit was supplied",
                    0,
                )
            )
    else:
        if anchors_required and not anchor_report.current_head_anchored:
            issues.append(
                AuditIssue(
                    "current_head_unanchored",
                    "genesis requires the terminal Ledger head to be signed",
                    records[-1].seq,
                )
            )
        for anchor_issue in anchor_report.issues:
            issues.append(
                AuditIssue(
                    f"anchor_{anchor_issue.code}",
                    anchor_issue.message,
                    anchor_issue.receipt_index,
                )
            )
        receipts_by_digest = {receipt.receipt_sha256(): receipt for receipt in anchor_report.receipts}
        if anchor_report.current_head_anchored:
            current_receipt = anchor_report.receipts[-1] if anchor_report.receipts else None
            if (
                current_receipt is None
                or current_receipt.run_id != records[0].run_id
                or current_receipt.ledger_seq != records[-1].seq
                or current_receipt.ledger_head_sha256 != records[-1].hash
            ):
                issues.append(
                    AuditIssue(
                        "anchor_snapshot_mismatch",
                        "anchor report does not bind the audited Ledger snapshot",
                        records[-1].seq,
                    )
                )
        if anchors_required and any(
            receipt.signer_key_id != policy_key or receipt.anchor_kind != policy_kind
            for receipt in anchor_report.receipts
        ):
            issues.append(
                AuditIssue(
                    "anchor_policy_mismatch",
                    "verified receipts contradict the signer/kind declared in genesis",
                    0,
                )
            )

    approvals_by_seq = {}
    approval_steps: set[int] = set()
    approval_attempts: set[str] = set()
    consumed_approvals: set[int] = set()
    promoted_steps: set[int] = set()
    current_policy_version = 0
    tripwire_seq: int | None = None
    run_exit_seq: int | None = None

    for index, record in enumerate(records):
        if record.event not in known_events:
            issues.append(AuditIssue("unknown_event", f"unknown event: {record.event}", record.seq))
        if record.event == "tripwire.fired" and tripwire_seq is None:
            tripwire_seq = record.seq
        if (
            run_exit_seq is not None
            and record.seq > run_exit_seq
            and record.event
            in {
                "gate.approved",
                "policy.promoted",
            }
        ):
            issues.append(
                AuditIssue("promotion_after_exit", "promotion authority used after run exit", record.seq)
            )
        if record.event == "run.exited":
            if run_exit_seq is not None:
                issues.append(AuditIssue("duplicate_run_exit", "run exited more than once", record.seq))
            run_exit_seq = record.seq
            if record.data.get("status") not in {"success", "failed"}:
                issues.append(AuditIssue("run_exit_status_invalid", "run exit status invalid", record.seq))
            error = record.data.get("error")
            if error is not None and not isinstance(error, str):
                issues.append(AuditIssue("run_exit_error_invalid", "run exit error invalid", record.seq))
        if (
            tripwire_seq is not None
            and record.seq > tripwire_seq
            and record.event
            in {
                "gate.approved",
                "policy.promoted",
            }
        ):
            issues.append(
                AuditIssue("promotion_after_tripwire", "promotion authority used after tripwire", record.seq)
            )
        if record.event == "gate.approved":
            data = record.data
            attempt = data.get("attempt_id")
            step = data.get("step")
            source = data.get("source_policy_version")
            previous_hash = records[index - 1].hash if index else None
            if not isinstance(attempt, str) or not attempt:
                issues.append(
                    AuditIssue("approval_attempt_invalid", "approval attempt_id missing", record.seq)
                )
            if isinstance(step, bool) or not isinstance(step, int) or step <= 0:
                issues.append(AuditIssue("approval_step_invalid", "approval step invalid", record.seq))
            if isinstance(source, bool) or not isinstance(source, int) or source < 0 or step != source + 1:
                issues.append(
                    AuditIssue(
                        "approval_transition_invalid", "approval source/target transition invalid", record.seq
                    )
                )
            elif source != current_policy_version:
                issues.append(
                    AuditIssue(
                        "approval_policy_state_mismatch",
                        f"approval source {source} does not match promoted version {current_policy_version}",
                        record.seq,
                    )
                )
            if data.get("evaluated_head") != previous_hash:
                issues.append(
                    AuditIssue(
                        "approval_head_mismatch", "approval was not evaluated at prior head", record.seq
                    )
                )
            anchor_ack = data.get("anchor_ack")
            if anchors_required and not isinstance(anchor_ack, dict):
                issues.append(
                    AuditIssue(
                        "approval_anchor_missing",
                        "approval lacks the required signed-head acknowledgement",
                        record.seq,
                    )
                )
            if isinstance(anchor_ack, dict):
                receipt_digest = anchor_ack.get("receipt_sha256")
                receipt = receipts_by_digest.get(receipt_digest)
                if anchor_report is None:
                    issues.append(
                        AuditIssue(
                            "approval_anchor_unverified",
                            "approval anchor was not cryptographically verified",
                            record.seq,
                        )
                    )
                elif receipt is None:
                    issues.append(
                        AuditIssue(
                            "approval_anchor_receipt_missing",
                            "approval references no verified anchor receipt",
                            record.seq,
                        )
                    )
                elif (
                    receipt.ledger_seq != record.seq - 1
                    or receipt.ledger_head_sha256 != previous_hash
                    or anchor_ack.get("anchor_seq") != receipt.anchor_seq
                    or anchor_ack.get("signer_key_id") != receipt.signer_key_id
                    or anchor_ack.get("ledger_seq") != receipt.ledger_seq
                    or anchor_ack.get("ledger_head_sha256") != receipt.ledger_head_sha256
                ):
                    issues.append(
                        AuditIssue(
                            "approval_anchor_binding_mismatch",
                            "approval anchor does not bind its immediate predecessor",
                            record.seq,
                        )
                    )
            if data.get("charter_sha256") != charter.sha256:
                issues.append(
                    AuditIssue("approval_charter_mismatch", "approval Charter digest mismatch", record.seq)
                )
            evidence_refs = data.get("evidence")
            candidate_seq = (
                evidence_refs.get("candidate_eval_seq") if isinstance(evidence_refs, dict) else None
            )
            if candidate_policy is not None:
                config_seq = (
                    evidence_refs.get("candidate_eval_config_seq")
                    if isinstance(evidence_refs, dict)
                    else None
                )
                expected_control = {
                    "candidate_evaluator_bundle": candidate_policy.evaluator_sha256,
                    "candidate_eval_suite": candidate_policy.suite_sha256,
                    "candidate_eval_config": candidate_policy.config_sha256,
                    "source_policy_manifest": candidate_policy.source_policy_sha256,
                }
                if (
                    isinstance(config_seq, bool)
                    or not isinstance(config_seq, int)
                    or config_seq < 0
                    or config_seq >= len(records)
                    or records[config_seq].event != "candidate_eval.configured"
                    or records[config_seq].data != {"immutable": True, "authorization": "charter-pinned"}
                    or len(records[config_seq].artifacts) != len(expected_control)
                    or {artifact.name: artifact.sha256 for artifact in records[config_seq].artifacts}
                    != expected_control
                ):
                    issues.append(
                        AuditIssue(
                            "candidate_eval_config_invalid",
                            "approval evaluator/suite/config digests contradict the Charter",
                            record.seq,
                        )
                    )
                if (
                    isinstance(candidate_seq, bool)
                    or not isinstance(candidate_seq, int)
                    or candidate_seq < 0
                    or candidate_seq >= len(records)
                ):
                    issues.append(
                        AuditIssue(
                            "candidate_eval_missing",
                            "approval lacks required candidate shadow-evaluation evidence",
                            record.seq,
                        )
                    )
                elif candidate_eval_public_key is None:
                    issues.append(
                        AuditIssue(
                            "candidate_eval_unverified",
                            "candidate evaluation policy requires its pinned public key for audit",
                            record.seq,
                        )
                    )
                else:
                    try:
                        checkpoint_seq = evidence_refs.get("checkpoint_seq")
                        if (
                            isinstance(checkpoint_seq, bool)
                            or not isinstance(checkpoint_seq, int)
                            or checkpoint_seq < 0
                            or checkpoint_seq >= len(records)
                        ):
                            raise CandidateEvalError("checkpoint evidence reference is invalid")
                        checkpoint_record = records[checkpoint_seq]
                        candidate_record = records[candidate_seq]
                        artifact_names = tuple(artifact.name for artifact in candidate_record.artifacts)
                        if (
                            candidate_record.event != "candidate_eval.result"
                            or candidate_record.seq != checkpoint_record.seq + 1
                            or candidate_record.prev_hash != checkpoint_record.hash
                            or candidate_record.seq != record.seq - 1
                            or len(checkpoint_record.artifacts) != 1
                            or artifact_names
                            not in {
                                ("candidate_eval_receipt",),
                                ("candidate_eval_receipt", "candidate_eval_terminal"),
                            }
                        ):
                            raise CandidateEvalError(
                                "candidate evaluation ordering or artifact binding is invalid"
                            )
                        receipt_artifact = candidate_record.artifacts[0]
                        terminal_artifact = (
                            candidate_record.artifacts[1] if len(candidate_record.artifacts) == 2 else None
                        )
                        receipt = CandidateEvalReceipt.from_bytes(
                            (ledger.artifact_root / receipt_artifact.path).read_bytes()
                        )
                        evaluation_request = CandidateEvalRequest(
                            run_id=record.run_id,
                            attempt_id=data.get("attempt_id"),
                            step=data.get("step"),
                            source_policy_version=data.get("source_policy_version"),
                            candidate_sha256=checkpoint_record.artifacts[0].sha256,
                            evaluated_ledger_seq=checkpoint_record.seq,
                            evaluated_ledger_head_sha256=checkpoint_record.hash,
                            policy=candidate_policy,
                        )
                        metrics = verify_candidate_eval_receipt(
                            receipt,
                            evaluation_request,
                            candidate_eval_public_key,
                            now=datetime.fromisoformat(record.ts.replace("Z", "+00:00")),
                        )
                        if terminal_artifact is not None:
                            if (
                                isinstance(config_seq, bool)
                                or not isinstance(config_seq, int)
                                or config_seq < 0
                                or config_seq >= len(records)
                            ):
                                raise CandidateEvalError(
                                    "candidate terminal evidence has no valid configuration"
                                )
                            suite_artifact = next(
                                artifact
                                for artifact in records[config_seq].artifacts
                                if artifact.name == "candidate_eval_suite"
                            )
                            terminal_receipt = verify_terminal_evidence(
                                ledger.artifact_root / terminal_artifact.path,
                                evaluation_request,
                                candidate_eval_public_key,
                                ledger.artifact_root / suite_artifact.path,
                            )
                            if terminal_receipt.to_bytes() != receipt.to_bytes():
                                raise CandidateEvalError(
                                    "candidate terminal evidence differs from the Ledger receipt"
                                )
                        expected_result_data = {
                            "step": data.get("step"),
                            "source_policy_version": data.get("source_policy_version"),
                            "attempt_id": data.get("attempt_id"),
                            "status": receipt.body["status"],
                        }
                        if candidate_record.data != expected_result_data:
                            raise CandidateEvalError(
                                "candidate-evaluation Ledger result differs from the signed receipt"
                            )
                        expected_summary = {
                            **metrics,
                            "receipt_sha256": receipt_artifact.sha256,
                            "candidate_eval_seq": candidate_record.seq,
                            "evaluator_signer_key_id": receipt.signer_key_id,
                            **(
                                {"terminal_evidence_sha256": terminal_artifact.sha256}
                                if terminal_artifact is not None
                                else {}
                            ),
                        }
                        if data.get("shadow_eval") != expected_summary:
                            raise CandidateEvalError(
                                "approval candidate-evaluation summary differs from signed receipt"
                            )
                    except (CandidateEvalError, OSError, TypeError, ValueError) as exc:
                        issues.append(
                            AuditIssue(
                                "candidate_eval_invalid",
                                str(exc),
                                record.seq,
                            )
                        )
            elif isinstance(evidence_refs, dict) and (
                evidence_refs.get("candidate_eval_config_seq") is not None or candidate_seq is not None
            ):
                issues.append(
                    AuditIssue(
                        "candidate_eval_unexpected",
                        "approval references candidate evaluation absent from the Charter",
                        record.seq,
                    )
                )
            if isinstance(step, int) and step in approval_steps:
                issues.append(
                    AuditIssue("duplicate_step_approval", f"step {step} approved twice", record.seq)
                )
            if isinstance(attempt, str) and attempt in approval_attempts:
                issues.append(AuditIssue("duplicate_attempt", f"attempt {attempt} reused", record.seq))
            if isinstance(step, int):
                approval_steps.add(step)
            if isinstance(attempt, str):
                approval_attempts.add(attempt)
            approvals_by_seq[record.seq] = record
        elif record.event == "weights.load_failed":
            data = record.data
            approval_seq = data.get("gate_approval_seq")
            approval = approvals_by_seq.get(approval_seq)
            if approval is None:
                issues.append(
                    AuditIssue("unbound_load_failure", "load failure lacks a prior approval", record.seq)
                )
            else:
                if approval_seq in consumed_approvals:
                    issues.append(
                        AuditIssue("reused_approval", "approval consumed more than once", record.seq)
                    )
                consumed_approvals.add(approval_seq)
                for field in ("attempt_id", "step"):
                    if data.get(field) != approval.data.get(field):
                        issues.append(
                            AuditIssue(
                                "load_failure_binding_mismatch", f"load failure {field} differs", record.seq
                            )
                        )
        elif record.event == "policy.promoted":
            data = record.data
            approval_seq = data.get("gate_approval_seq")
            approval = approvals_by_seq.get(approval_seq)
            if approval is None:
                issues.append(
                    AuditIssue("unauthorized_promotion", "promotion lacks a prior approval", record.seq)
                )
                continue
            approval_already_consumed = approval_seq in consumed_approvals
            if approval_already_consumed:
                issues.append(AuditIssue("reused_approval", "approval consumed more than once", record.seq))
            consumed_approvals.add(approval_seq)
            for field in ("attempt_id", "step", "source_policy_version"):
                if data.get(field) != approval.data.get(field):
                    issues.append(
                        AuditIssue(
                            "promotion_binding_mismatch",
                            f"promotion {field} differs from approval",
                            record.seq,
                        )
                    )
            step = data.get("step")
            source = data.get("source_policy_version")
            if isinstance(step, int) and not isinstance(step, bool) and step in promoted_steps:
                issues.append(AuditIssue("duplicate_promotion", f"step {step} promoted twice", record.seq))
            if (
                isinstance(step, int)
                and not isinstance(step, bool)
                and isinstance(source, int)
                and not isinstance(source, bool)
            ):
                promoted_steps.add(step)
                if source != current_policy_version or step != current_policy_version + 1:
                    issues.append(
                        AuditIssue(
                            "promotion_policy_state_mismatch",
                            f"promotion {source}->{step} does not advance version {current_policy_version}",
                            record.seq,
                        )
                    )
                elif not approval_already_consumed and all(
                    data.get(field) == approval.data.get(field)
                    for field in ("attempt_id", "step", "source_policy_version")
                ):
                    current_policy_version = step

    for approval_seq in sorted(set(approvals_by_seq) - consumed_approvals):
        issues.append(
            AuditIssue(
                "ambiguous_unconsumed_approval",
                "authorization intent has no promotion outcome; restart must freeze and reconcile",
                approval_seq,
            )
        )
    genesis_digest = records[0].data.get("charter_sha256")
    if genesis_digest != charter.sha256:
        issues.append(AuditIssue("genesis_charter_mismatch", "genesis Charter digest differs", 0))
    return GovernanceAuditReport(tuple(issues), len(records), len(promoted_steps))
