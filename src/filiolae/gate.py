"""Fail-closed policy-promotion Gate."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .anchor import (
    SUPPORTED_ANCHOR_KINDS,
    AnchorReceipt,
    AnchorStore,
    HeadAnchor,
    verify_anchor_store,
)
from .artifacts import ArtifactError, digest_path
from .charter import Charter
from .freeze import FreezeController
from .ledger import Ledger, LedgerError, LedgerRecord
from .paired_eval import verify_terminal_evidence
from .shadow_eval import (
    CandidateEvalError,
    CandidateEvalReceipt,
    CandidateEvalRequest,
    verify_candidate_eval_receipt,
)


class PromotionDenied(RuntimeError):
    pass


@dataclass(frozen=True)
class PromotionRequest:
    attempt_id: str
    step: int
    source_policy_version: int
    config_seq: int
    rollout_batch_seq: int
    eval_result_seq: int
    checkpoint_seq: int
    candidate_eval_config_seq: int | None = None
    candidate_eval_seq: int | None = None


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason: str
    step: int
    ledger_seq: int | None = None
    ledger_hash: str | None = None
    approved_checkpoint_path: str | None = None


class PromotionGate:
    """Authorize a policy promotion only from intact, attested evidence."""

    REQUIRED_RULES = {"immutable_artifacts", "promotion_evidence_required", "freeze_on_integrity_failure"}
    EVENT_BY_FIELD = {
        "config_seq": "config.resolved",
        "rollout_batch_seq": "batch.committed",
        "eval_result_seq": "source_eval.result",
        "checkpoint_seq": "weights.published",
    }
    ARTIFACT_BY_FIELD = {
        "config_seq": "config",
        "rollout_batch_seq": "rollout_batch",
        "eval_result_seq": "source_eval_result",
        "checkpoint_seq": "candidate_weights",
    }

    def __init__(
        self,
        ledger: Ledger,
        charter: Charter,
        freezer: FreezeController,
        *,
        actor: str = "service:filiolae-gate",
        head_anchor: HeadAnchor | None = None,
        anchor_store: AnchorStore | None = None,
        anchor_public_key: Ed25519PublicKey | None = None,
        require_head_anchor: bool = False,
        candidate_eval_public_key: Ed25519PublicKey | None = None,
        clock=None,
    ) -> None:
        self.ledger = ledger
        self.charter = charter
        self.freezer = freezer
        self.actor = actor
        self.head_anchor = head_anchor
        self.anchor_store = anchor_store
        self.anchor_public_key = anchor_public_key
        self.require_head_anchor = require_head_anchor
        self.candidate_eval_public_key = candidate_eval_public_key
        self.clock = clock or (lambda: datetime.now(UTC))

    def _verify_anchor_receipt(
        self,
        receipt: AnchorReceipt,
        *,
        expected_seq: int,
        expected_head: str,
    ) -> None:
        if self.head_anchor is None or self.anchor_store is None or self.anchor_public_key is None:
            raise RuntimeError("Gate-owned anchor verifier/store is unavailable")
        report = verify_anchor_store(
            self.ledger,
            self.anchor_store,
            self.anchor_public_key,
            require_current=True,
            expected_anchor_kind=self.head_anchor.anchor_kind,
        )
        if not report.ok:
            raise RuntimeError(report.summary())
        current = report.receipts[-1]
        if (
            current.receipt_sha256() != receipt.receipt_sha256()
            or current.ledger_seq != expected_seq
            or current.ledger_head_sha256 != expected_head
        ):
            raise RuntimeError("durable verified receipt does not bind the expected current head")

    def _deny(self, request: PromotionRequest, reason: str, *, chain_intact: bool) -> GateDecision:
        step = request.step
        safe_step = step if isinstance(step, int) and not isinstance(step, bool) else -1
        if chain_intact:
            # Commit and anchor the denial before exposing the filesystem freeze marker.
            # The external supervisor reacts immediately to that marker and may otherwise
            # terminate this process before the durable denial reaches the Ledger.
            detected_at = self.clock().astimezone(UTC).isoformat().replace("+00:00", "Z")
            try:
                self.ledger.append(
                    "tripwire.fired",
                    actor=self.actor,
                    data={
                        "class": "T-REC",
                        "step": safe_step,
                        "reason": reason,
                        "freeze_ts": detected_at,
                    },
                )
                self.ledger.append(
                    "gate.denied",
                    actor=self.actor,
                    data={"step": safe_step, "reason": reason},
                )
                self.anchor_current_head()
            except Exception as exc:
                reason = f"{reason}; durable denial commit failed: {type(exc).__name__}: {exc}"
        self.freezer.freeze(reason, details={"step": safe_step})
        return GateDecision(False, reason, safe_step)

    def authorize(
        self,
        request: PromotionRequest,
        *,
        current_policy_version: int,
        pending_weights_path: str | Path | None,
    ) -> GateDecision:
        if not isinstance(request.attempt_id, str) or not request.attempt_id:
            return self._deny(
                request,
                "promotion attempt_id must be a non-empty string",
                chain_intact=self.ledger.audit().ok,
            )
        version_fields = (request.step, request.source_policy_version, current_policy_version)
        evidence_fields = (
            request.config_seq,
            request.rollout_batch_seq,
            request.eval_result_seq,
            request.checkpoint_seq,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) for value in version_fields):
            return self._deny(
                request, "promotion versions must be integers", chain_intact=self.ledger.audit().ok
            )
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in evidence_fields
        ):
            return self._deny(
                request,
                "promotion evidence sequences must be non-negative integers",
                chain_intact=self.ledger.audit().ok,
            )
        if request.step <= 0 or request.source_policy_version < 0 or current_policy_version < 0:
            return self._deny(request, "invalid promotion version", chain_intact=self.ledger.audit().ok)
        if (
            request.source_policy_version != current_policy_version
            or request.step != current_policy_version + 1
        ):
            return self._deny(
                request, "stale, skipped, or false source policy version", chain_intact=self.ledger.audit().ok
            )
        if pending_weights_path is None:
            return self._deny(
                request,
                "governed mode requires filesystem weight broadcast",
                chain_intact=self.ledger.audit().ok,
            )
        frozen = self.freezer.state()
        if frozen.frozen:
            return GateDecision(False, f"run already frozen: {frozen.reason}", request.step)
        chain_report = self.ledger.audit()
        if not chain_report.ok:
            return self._deny(
                request, f"Ledger integrity failure: {chain_report.summary()}", chain_intact=False
            )
        artifact_report = self.ledger.audit(verify_artifacts=True)
        if not artifact_report.ok:
            return self._deny(
                request, f"artifact integrity failure: {artifact_report.summary()}", chain_intact=True
            )
        records = chain_report.records
        genesis = records[0]
        if any(record.event in {"tripwire.fired", "gate.denied"} for record in records[1:]):
            self.freezer.freeze(
                "run has a prior permanent denial or tripwire", details={"step": request.step}
            )
            return GateDecision(False, "run has a prior permanent denial or tripwire", request.step)
        if any(
            record.event in {"gate.approved", "policy.promoted"}
            and (
                record.data.get("step") == request.step or record.data.get("attempt_id") == request.attempt_id
            )
            for record in records
        ):
            return self._deny(request, "duplicate or replayed promotion attempt", chain_intact=True)
        if genesis.data.get("charter_sha256") != self.charter.sha256:
            return self._deny(request, "active Charter digest differs from genesis", chain_intact=True)
        rules = {clause.rule for clause in self.charter.clauses if clause.severity == "hard"}
        missing_rules = sorted(self.REQUIRED_RULES - rules)
        if missing_rules:
            return self._deny(
                request, f"required hard Charter rules missing: {', '.join(missing_rules)}", chain_intact=True
            )
        evidence: dict[str, LedgerRecord] = {}
        for field, expected_event in self.EVENT_BY_FIELD.items():
            seq = getattr(request, field)
            if seq < 0 or seq >= len(records):
                return self._deny(request, f"{field} references absent Ledger seq {seq}", chain_intact=True)
            record = records[seq]
            if record.event != expected_event:
                return self._deny(
                    request,
                    f"{field} expected {expected_event}, found {record.event}",
                    chain_intact=True,
                )
            evidence[field] = record
        for field in ("rollout_batch_seq", "eval_result_seq", "checkpoint_seq"):
            if evidence[field].data.get("step") != request.step:
                return self._deny(request, f"{field} belongs to a different step", chain_intact=True)
        checkpoint = evidence["checkpoint_seq"]
        if checkpoint.data.get("source_policy_version") != request.source_policy_version:
            return self._deny(request, "published weights source policy version mismatch", chain_intact=True)
        for field, record in evidence.items():
            expected_name = self.ARTIFACT_BY_FIELD[field]
            if len(record.artifacts) != 1 or record.artifacts[0].name != expected_name:
                return self._deny(
                    request,
                    f"{field} must bind exactly one {expected_name} artifact",
                    chain_intact=True,
                )
        checkpoint_artifact = checkpoint.artifacts[0]
        shadow_eval_summary: dict[str, object] | None = None
        candidate_policy = self.charter.candidate_eval_policy()
        if candidate_policy is None:
            if request.candidate_eval_config_seq is not None or request.candidate_eval_seq is not None:
                return self._deny(
                    request,
                    "candidate evaluation was supplied without a Charter policy",
                    chain_intact=True,
                )
        else:
            config_seq = request.candidate_eval_config_seq
            if (
                isinstance(config_seq, bool)
                or not isinstance(config_seq, int)
                or config_seq < 0
                or config_seq >= len(records)
            ):
                return self._deny(
                    request,
                    "required candidate evaluator configuration is missing",
                    chain_intact=True,
                )
            config_record = records[config_seq]
            expected_control = {
                "candidate_evaluator_bundle": candidate_policy.evaluator_sha256,
                "candidate_eval_suite": candidate_policy.suite_sha256,
                "candidate_eval_config": candidate_policy.config_sha256,
                "source_policy_manifest": candidate_policy.source_policy_sha256,
            }
            if (
                config_record.event != "candidate_eval.configured"
                or config_record.data != {"immutable": True, "authorization": "charter-pinned"}
                or len(config_record.artifacts) != len(expected_control)
                or {artifact.name: artifact.sha256 for artifact in config_record.artifacts}
                != expected_control
            ):
                return self._deny(
                    request,
                    "candidate evaluator/suite/config digests contradict the Charter",
                    chain_intact=True,
                )
            candidate_seq = request.candidate_eval_seq
            if (
                isinstance(candidate_seq, bool)
                or not isinstance(candidate_seq, int)
                or candidate_seq < 0
                or candidate_seq >= len(records)
            ):
                return self._deny(
                    request,
                    "required candidate shadow-evaluation result is missing",
                    chain_intact=True,
                )
            if self.candidate_eval_public_key is None:
                return self._deny(
                    request,
                    "candidate shadow-evaluation public key is unavailable",
                    chain_intact=True,
                )
            candidate_record = records[candidate_seq]
            if (
                candidate_record.event != "candidate_eval.result"
                or candidate_record.seq != checkpoint.seq + 1
                or candidate_record.prev_hash != checkpoint.hash
                or candidate_record.seq != records[-1].seq
            ):
                return self._deny(
                    request,
                    "candidate shadow-evaluation is stale or not bound immediately after weights",
                    chain_intact=True,
                )
            if candidate_record.data.get("step") != request.step:
                return self._deny(
                    request,
                    "candidate shadow-evaluation belongs to a different step",
                    chain_intact=True,
                )
            artifact_names = tuple(artifact.name for artifact in candidate_record.artifacts)
            if artifact_names not in {
                ("candidate_eval_receipt",),
                ("candidate_eval_receipt", "candidate_eval_terminal"),
            }:
                return self._deny(
                    request,
                    "candidate shadow-evaluation artifact binding is invalid",
                    chain_intact=True,
                )
            receipt_artifact = candidate_record.artifacts[0]
            terminal_artifact = (
                candidate_record.artifacts[1] if len(candidate_record.artifacts) == 2 else None
            )
            evaluation_request = CandidateEvalRequest(
                run_id=genesis.run_id,
                attempt_id=request.attempt_id,
                step=request.step,
                source_policy_version=request.source_policy_version,
                candidate_sha256=checkpoint_artifact.sha256,
                evaluated_ledger_seq=checkpoint.seq,
                evaluated_ledger_head_sha256=checkpoint.hash,
                policy=candidate_policy,
            )
            try:
                receipt = CandidateEvalReceipt.from_bytes(
                    (self.ledger.artifact_root / receipt_artifact.path).read_bytes()
                )
                shadow_eval_summary = verify_candidate_eval_receipt(
                    receipt,
                    evaluation_request,
                    self.candidate_eval_public_key,
                    now=self.clock(),
                )
                if terminal_artifact is not None:
                    suite_artifact = next(
                        artifact
                        for artifact in config_record.artifacts
                        if artifact.name == "candidate_eval_suite"
                    )
                    terminal_receipt = verify_terminal_evidence(
                        self.ledger.artifact_root / terminal_artifact.path,
                        evaluation_request,
                        self.candidate_eval_public_key,
                        self.ledger.artifact_root / suite_artifact.path,
                    )
                    if terminal_receipt.to_bytes() != receipt.to_bytes():
                        raise CandidateEvalError(
                            "candidate terminal evidence differs from the Ledger receipt"
                        )
                expected_result_data = {
                    "step": request.step,
                    "source_policy_version": request.source_policy_version,
                    "attempt_id": request.attempt_id,
                    "status": receipt.body["status"],
                }
                if candidate_record.data != expected_result_data:
                    raise CandidateEvalError(
                        "candidate-evaluation Ledger result differs from the signed receipt"
                    )
            except (CandidateEvalError, OSError, ValueError) as exc:
                return self._deny(
                    request,
                    f"candidate shadow-evaluation failed: {exc}",
                    chain_intact=True,
                )
            shadow_eval_summary = {
                **shadow_eval_summary,
                "receipt_sha256": receipt_artifact.sha256,
                "candidate_eval_seq": candidate_record.seq,
                "evaluator_signer_key_id": receipt.signer_key_id,
                **(
                    {"terminal_evidence_sha256": terminal_artifact.sha256}
                    if terminal_artifact is not None
                    else {}
                ),
            }
        try:
            pending_kind, pending_digest, pending_size = digest_path(pending_weights_path)
        except (ArtifactError, FileNotFoundError, OSError, TypeError, ValueError) as exc:
            return self._deny(request, f"cannot digest pending weights: {exc}", chain_intact=True)
        if (pending_kind, pending_digest, pending_size) != (
            checkpoint_artifact.kind,
            checkpoint_artifact.sha256,
            checkpoint_artifact.size,
        ):
            return self._deny(
                request, "pending weights differ from the attested candidate", chain_intact=True
            )
        try:
            approved_checkpoint = (self.ledger.artifact_root / checkpoint_artifact.path).resolve(strict=True)
            approved_checkpoint.relative_to(self.ledger.artifact_root.resolve(strict=True))
        except (FileNotFoundError, OSError, ValueError) as exc:
            return self._deny(
                request,
                f"approved checkpoint path became unsafe: {exc}",
                chain_intact=True,
            )
        evaluated_head = records[-1].hash
        anchor_ack: dict[str, object] | None = None
        metadata = records[0].data.get("metadata", {})
        genesis_requires_anchor = isinstance(metadata, dict) and metadata.get("head_anchors_required") is True
        anchor_required = self.require_head_anchor or genesis_requires_anchor
        if anchor_required and self.head_anchor is None:
            return self._deny(request, "required Ledger-head anchor is unavailable", chain_intact=True)
        if anchor_required and (self.anchor_store is None or self.anchor_public_key is None):
            return self._deny(
                request,
                "required Gate-owned anchor verifier/store is unavailable",
                chain_intact=True,
            )
        if anchor_required:
            policy_key = metadata.get("anchor_signer_key_id") if isinstance(metadata, dict) else None
            policy_kind = metadata.get("anchor_kind") if isinstance(metadata, dict) else None
            if (
                not genesis_requires_anchor
                or not isinstance(policy_key, str)
                or not policy_key
                or policy_kind not in SUPPORTED_ANCHOR_KINDS
                or getattr(self.head_anchor, "signer_key_id", None) != policy_key
                or getattr(self.head_anchor, "anchor_kind", None) != policy_kind
            ):
                return self._deny(
                    request,
                    "required Ledger-head anchor contradicts genesis signer policy",
                    chain_intact=True,
                )
        if self.head_anchor is not None:
            try:
                receipt = self.head_anchor.acknowledge(
                    self.ledger,
                    expected_seq=records[-1].seq,
                    expected_head=evaluated_head,
                )
                self._verify_anchor_receipt(
                    receipt,
                    expected_seq=records[-1].seq,
                    expected_head=evaluated_head,
                )
                if (
                    receipt.run_id != records[0].run_id
                    or receipt.ledger_seq != records[-1].seq
                    or receipt.ledger_head_sha256 != evaluated_head
                ):
                    raise RuntimeError("anchor receipt does not bind the expected run/head")
            except Exception as exc:
                return self._deny(
                    request,
                    f"Ledger-head anchoring failed: {type(exc).__name__}: {exc}",
                    chain_intact=self.ledger.audit().ok,
                )
            anchor_ack = {
                "anchor_kind": receipt.anchor_kind,
                "anchor_seq": receipt.anchor_seq,
                "receipt_sha256": receipt.receipt_sha256(),
                "signer_key_id": receipt.signer_key_id,
                "ledger_seq": receipt.ledger_seq,
                "ledger_head_sha256": receipt.ledger_head_sha256,
            }
            if self.freezer.state().frozen:
                return self._deny(
                    request,
                    "run froze while Ledger-head anchoring was in progress",
                    chain_intact=self.ledger.audit().ok,
                )
        approval_data = {
            "attempt_id": request.attempt_id,
            "step": request.step,
            "source_policy_version": request.source_policy_version,
            "evaluated_head": evaluated_head,
            "charter_sha256": self.charter.sha256,
            "evidence": asdict(request),
            "approved_checkpoint": checkpoint_artifact.to_dict(),
        }
        if anchor_ack is not None:
            approval_data["anchor_ack"] = anchor_ack
        if shadow_eval_summary is not None:
            approval_data["shadow_eval"] = shadow_eval_summary
        if self.freezer.state().frozen:
            return self._deny(
                request,
                "run froze before authorization commit",
                chain_intact=self.ledger.audit().ok,
            )
        try:
            record = self.ledger.append(
                "gate.approved",
                actor=self.actor,
                data=approval_data,
                expected_head=evaluated_head,
            )
        except LedgerError as exc:
            return self._deny(
                request, f"authorization commit failed: {exc}", chain_intact=self.ledger.audit().ok
            )
        return GateDecision(
            True,
            "promotion evidence satisfies Charter",
            request.step,
            record.seq,
            record.hash,
            str(approved_checkpoint),
        )

    def fail_closed_control_error(
        self,
        *,
        step: int,
        source_policy_version: int,
        reason: str,
    ) -> None:
        """Freeze and retain a denial when control-plane evidence construction fails."""
        safe_step = step if isinstance(step, int) and not isinstance(step, bool) else -1
        state = self.freezer.freeze(
            reason,
            details={"step": safe_step, "source_policy_version": source_policy_version},
        )
        report = self.ledger.audit()
        if not report.ok or any(
            record.event in {"tripwire.fired", "gate.denied"} for record in report.records
        ):
            return
        try:
            self.ledger.append(
                "tripwire.fired",
                actor=self.actor,
                data={
                    "class": "T-EVAL",
                    "step": safe_step,
                    "reason": reason,
                    "freeze_ts": state.ts,
                },
            )
            self.ledger.append(
                "gate.denied",
                actor=self.actor,
                data={"step": safe_step, "reason": reason},
            )
        except LedgerError:
            pass

    def anchor_current_head(self) -> None:
        """Durably checkpoint the current post-decision/outcome head when configured."""
        report = self.ledger.audit()
        if not report.ok:
            raise RuntimeError(report.summary())
        metadata = report.records[0].data.get("metadata", {})
        genesis_requires = isinstance(metadata, dict) and metadata.get("head_anchors_required") is True
        anchor_required = self.require_head_anchor or genesis_requires
        if anchor_required and self.head_anchor is None:
            raise RuntimeError("required Ledger-head anchor is unavailable")
        if anchor_required and (self.anchor_store is None or self.anchor_public_key is None):
            raise RuntimeError("required Gate-owned anchor verifier/store is unavailable")
        if self.head_anchor is None:
            return
        policy_key = metadata.get("anchor_signer_key_id") if isinstance(metadata, dict) else None
        policy_kind = metadata.get("anchor_kind") if isinstance(metadata, dict) else None
        if anchor_required and (
            not genesis_requires
            or self.head_anchor.signer_key_id != policy_key
            or self.head_anchor.anchor_kind != policy_kind
        ):
            raise RuntimeError("configured Ledger-head anchor contradicts genesis signer policy")
        head = report.records[-1]
        receipt = self.head_anchor.acknowledge(
            self.ledger,
            expected_seq=head.seq,
            expected_head=head.hash,
        )
        self._verify_anchor_receipt(
            receipt,
            expected_seq=head.seq,
            expected_head=head.hash,
        )
        if (
            receipt.run_id != report.records[0].run_id
            or receipt.ledger_seq != head.seq
            or receipt.ledger_head_sha256 != head.hash
        ):
            raise RuntimeError("anchor receipt does not bind the expected terminal run/head")

    def require_authorized(
        self,
        request: PromotionRequest,
        *,
        current_policy_version: int,
        pending_weights_path: str | Path | None,
    ) -> GateDecision:
        decision = self.authorize(
            request,
            current_policy_version=current_policy_version,
            pending_weights_path=pending_weights_path,
        )
        if not decision.allowed:
            raise PromotionDenied(decision.reason)
        return decision
