"""Bounded, owner-readable explanation of one governed run."""

from __future__ import annotations

import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .anchor import UNIX_WITNESS_ANCHOR_KIND, AnchorAuditReport
from .audit import audit_governance
from .charter import Charter
from .enrollment import WitnessEnrollment
from .freeze import FreezeController
from .ledger import Ledger, LedgerRecord

REPORT_SCHEMA = "filiolae.explain.v1"
DEFAULT_MAX_ITEMS = 20
MAX_ITEMS = 100
MAX_LEDGER_BYTES = 64 * 1024 * 1024
MAX_CHARTER_BYTES = 1024 * 1024
MAX_LEDGER_RECORDS = 100_000
MAX_ARTIFACT_DESCRIPTORS = 100_000
MAX_DECLARED_ARTIFACT_BYTES = 1 << 40
MAX_ACTUAL_ARTIFACT_BYTES = 64 * (1 << 30)
MAX_ACTUAL_ARTIFACT_ENTRIES = 1_000_000


class ExplainError(ValueError):
    pass


@dataclass(frozen=True)
class RunLayout:
    run_root: Path
    control_root: Path
    ledger: Path
    artifacts: Path
    charter: Path
    freeze: Path


@dataclass(frozen=True)
class StepExplanation:
    step: int | None
    attempt_id: str | None
    decision: str
    reason: str | None
    approval_seq: int | None
    outcome_seq: int | None
    source_policy_version: int | None
    authorized_weights: dict[str, Any] | None
    shadow_eval: dict[str, Any] | None


def _reject_symlink_components(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ExplainError(f"symlink component rejected: {current}")


def _require_real_directory(path: Path, name: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ExplainError(f"{name} directory is unavailable: {exc}") from exc
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink():
        raise ExplainError(f"{name} must be a real directory")


def _require_safe_regular(path: Path, name: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ExplainError(f"{name} is unavailable: {exc}") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path.is_symlink():
        raise ExplainError(f"{name} must be a singly-linked regular file")


def discover_run_layout(run_directory: str | Path) -> RunLayout:
    root = Path(os.path.abspath(run_directory))
    _reject_symlink_components(root)
    _require_real_directory(root, "run")
    candidates = [root / "control" / "filiolae", root / "control", root]
    matches = []
    for candidate in candidates:
        try:
            (candidate / "ledger.jsonl").lstat()
        except FileNotFoundError:
            continue
        matches.append(candidate)
    # Nested candidates are intentionally distinct layouts; never guess between two Ledgers.
    if len(matches) != 1:
        raise ExplainError(f"expected exactly one governed Ledger under RUN_DIRECTORY; found {len(matches)}")
    control = matches[0]
    _reject_symlink_components(control)
    _require_real_directory(control, "governance")
    required = {"artifacts": control / "artifacts", "charter": control / "charter.yaml"}
    _require_real_directory(required["artifacts"], "artifact root")
    _require_safe_regular(required["charter"], "Charter")
    _require_safe_regular(control / "ledger.jsonl", "Ledger")
    return RunLayout(
        run_root=root,
        control_root=control,
        ledger=control / "ledger.jsonl",
        artifacts=required["artifacts"],
        charter=required["charter"],
        freeze=control / "freeze.json",
    )


def _check_actual_artifact_budget(root: Path, records: tuple[LedgerRecord, ...]) -> None:
    """Reject implausibly large retained trees before hashing their contents."""
    root_resolved = root.resolve(strict=True)
    seen: set[Path] = set()
    total_bytes = 0
    total_entries = 0
    for record in records:
        for artifact in record.artifacts:
            supplied = root / artifact.path
            _reject_symlink_components(supplied)
            try:
                target = supplied.resolve(strict=True)
                target.relative_to(root_resolved)
            except (FileNotFoundError, OSError, ValueError) as exc:
                raise ExplainError(f"artifact path is unavailable or unsafe: {artifact.path}: {exc}") from exc
            if target in seen:
                continue
            seen.add(target)
            pending = [target]
            while pending:
                current = pending.pop()
                try:
                    info = current.lstat()
                except OSError as exc:
                    raise ExplainError(f"artifact entry is unavailable: {current}: {exc}") from exc
                if stat.S_ISLNK(info.st_mode):
                    raise ExplainError(f"symlinked artifact entry rejected: {current}")
                total_entries += 1
                if total_entries > MAX_ACTUAL_ARTIFACT_ENTRIES:
                    raise ExplainError("actual artifact entry count exceeds the explanation limit")
                if stat.S_ISREG(info.st_mode):
                    total_bytes += info.st_size
                    if total_bytes > MAX_ACTUAL_ARTIFACT_BYTES:
                        raise ExplainError("actual artifact bytes exceed the explanation limit")
                elif stat.S_ISDIR(info.st_mode):
                    try:
                        pending.extend(Path(entry.path) for entry in os.scandir(current))
                    except OSError as exc:
                        raise ExplainError(f"artifact directory is unreadable: {current}: {exc}") from exc
                else:
                    raise ExplainError(f"special artifact entry rejected: {current}")


def _bounded_verified_snapshot(ledger: Ledger, layout: RunLayout):
    with ledger.locked_existing():
        structural = ledger.audit()
        descriptor_count = sum(len(record.artifacts) for record in structural.records)
        declared_bytes = sum(artifact.size for record in structural.records for artifact in record.artifacts)
        if len(structural.records) > MAX_LEDGER_RECORDS:
            raise ExplainError("Ledger record count exceeds the bounded explanation limit")
        if descriptor_count > MAX_ARTIFACT_DESCRIPTORS:
            raise ExplainError("artifact descriptor count exceeds the bounded explanation limit")
        if declared_bytes > MAX_DECLARED_ARTIFACT_BYTES:
            raise ExplainError("declared artifact bytes exceed the bounded explanation limit")
        if structural.ok:
            _check_actual_artifact_budget(layout.artifacts, structural.records)
            structural = ledger.audit(verify_artifacts=True)
        return structural


def _integer(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _step_explanations(records: tuple[LedgerRecord, ...]) -> list[StepExplanation]:
    approvals: dict[int, LedgerRecord] = {}
    outcomes: dict[int, LedgerRecord] = {}
    explanations: list[StepExplanation] = []
    for record in records:
        if record.event == "gate.approved":
            approvals[record.seq] = record
        elif record.event in {"policy.promoted", "weights.load_failed"}:
            approval_seq = _integer(record.data.get("gate_approval_seq"))
            if approval_seq is not None:
                outcomes[approval_seq] = record
        elif record.event == "gate.denied":
            explanations.append(
                StepExplanation(
                    step=_integer(record.data.get("step")),
                    attempt_id=_text(record.data.get("attempt_id")),
                    decision="denied",
                    reason=_text(record.data.get("reason")),
                    approval_seq=None,
                    outcome_seq=record.seq,
                    source_policy_version=None,
                    authorized_weights=None,
                    shadow_eval=None,
                )
            )
    for approval_seq, approval in approvals.items():
        outcome = outcomes.get(approval_seq)
        checkpoint = approval.data.get("approved_checkpoint")
        authorized = None
        if isinstance(checkpoint, dict):
            authorized = {
                key: checkpoint.get(key) for key in ("path", "kind", "sha256", "size") if key in checkpoint
            }
        if outcome is None:
            decision = "ambiguous_authorization"
            reason = "approval has no committed load outcome"
        elif outcome.event == "policy.promoted":
            decision = "promoted"
            reason = None
        else:
            decision = "load_failed"
            reason = _text(outcome.data.get("error"))
        explanations.append(
            StepExplanation(
                step=_integer(approval.data.get("step")),
                attempt_id=_text(approval.data.get("attempt_id")),
                decision=decision,
                reason=reason,
                approval_seq=approval_seq,
                outcome_seq=outcome.seq if outcome else None,
                source_policy_version=_integer(approval.data.get("source_policy_version")),
                authorized_weights=authorized,
                shadow_eval=(
                    approval.data.get("shadow_eval")
                    if isinstance(approval.data.get("shadow_eval"), dict)
                    else None
                ),
            )
        )
    explanations.sort(
        key=lambda item: (
            item.step is None,
            item.step if item.step is not None else 0,
            item.approval_seq if item.approval_seq is not None else item.outcome_seq or 0,
        )
    )
    return explanations


def explain_run(
    run_directory: str | Path,
    *,
    anchor_report: AnchorAuditReport | None = None,
    candidate_eval_public_key: Ed25519PublicKey | None = None,
    witness_enrollment: WitnessEnrollment | None = None,
    max_items: int = DEFAULT_MAX_ITEMS,
) -> dict[str, Any]:
    if isinstance(max_items, bool) or not isinstance(max_items, int) or not 1 <= max_items <= MAX_ITEMS:
        raise ExplainError(f"max_items must be in [1, {MAX_ITEMS}]")
    layout = discover_run_layout(run_directory)
    if layout.ledger.stat().st_size > MAX_LEDGER_BYTES:
        raise ExplainError("Ledger exceeds the bounded explanation size limit")
    if layout.charter.stat().st_size > MAX_CHARTER_BYTES:
        raise ExplainError("Charter exceeds the bounded explanation size limit")
    charter = Charter.load(layout.charter)
    ledger = Ledger(layout.ledger, artifact_root=layout.artifacts)
    structural = _bounded_verified_snapshot(ledger, layout)
    report = audit_governance(
        ledger,
        charter,
        verify_artifacts=False,
        anchor_report=anchor_report,
        candidate_eval_public_key=candidate_eval_public_key,
        witness_enrollment=witness_enrollment,
        structural_report=structural,
    )
    records = structural.records if structural.ok else ()
    genesis = records[0] if records else None
    issues_for_output = report.issues if structural.ok else structural.issues
    metadata = genesis.data.get("metadata", {}) if genesis else {}
    if not isinstance(metadata, dict):
        metadata = {}
    steps = _step_explanations(records)
    frozen = FreezeController(layout.freeze).state()
    run_exits = [record for record in records if record.event == "run.exited"]
    terminal = run_exits[-1] if run_exits else None
    anchors_required = metadata.get("head_anchors_required") is True
    ambiguities = [
        asdict(issue)
        for issue in issues_for_output
        if issue.code.startswith("ambiguous_")
        or issue.code in {"anchors_unverified", "current_head_unanchored"}
    ]
    non_claims = [
        "This explanation is a bounded view of retained evidence, not new promotion authority.",
        (
            "Signed receipts do not by themselves prove remote, WORM, transparent, "
            "or public-timestamp retention."
        ),
        "Same-host witness evidence does not protect against witness, root, or kernel compromise.",
        "Process-group CPU tests do not prove production cgroup containment or live GPU integration.",
    ]
    if metadata.get("evaluator_mode") == "cpu_mock":
        non_claims.append(
            "CPU mock shadow-evaluation proves control-plane behavior, not real model quality or "
            "evaluator independence."
        )
    elif metadata.get("candidate_quality_evaluated") is not True:
        non_claims.append("Candidate model quality/regression was not independently evaluated for this run.")
    shown = steps[-max_items:]
    integrity = "valid" if report.ok else "invalid_or_incomplete"
    if frozen.frozen:
        operational = "frozen"
    elif ambiguities:
        operational = "ambiguous"
    elif terminal is not None:
        operational = f"exited_{terminal.data.get('status', 'invalid')}"
    elif any(step.decision == "promoted" for step in steps):
        operational = "promotion_recorded_run_open"
    elif any(step.decision == "denied" for step in steps):
        operational = "denied"
    else:
        operational = "in_progress_or_no_decision"
    return {
        "schema": REPORT_SCHEMA,
        "run": {
            "directory": str(layout.run_root),
            "run_id": genesis.run_id if genesis else None,
            "host": metadata.get("host"),
            "records": len(records),
            "ledger_head_sha256": records[-1].hash if records else None,
        },
        "status": {
            "integrity": integrity,
            "operational": operational,
            "audit_ok": report.ok,
            "promotion_count": report.promotion_count if structural.ok else 0,
            "history_suppressed": not structural.ok,
        },
        "freeze": asdict(frozen),
        "terminal": (
            {
                "seq": terminal.seq,
                "status": terminal.data.get("status"),
                "error": terminal.data.get("error"),
            }
            if terminal
            else None
        ),
        "anchors": {
            "required": anchors_required,
            "checked": anchor_report is not None,
            "ok": anchor_report.ok if anchor_report is not None else None,
            "current_head_anchored": (
                anchor_report.current_head_anchored if anchor_report is not None else None
            ),
            "receipt_count": len(anchor_report.receipts) if anchor_report is not None else None,
            "signer_key_id": metadata.get("anchor_signer_key_id"),
            "kind": metadata.get("anchor_kind"),
            "enrollment_sha256": metadata.get("witness_enrollment_sha256"),
            "enrollment_checked": witness_enrollment is not None,
        },
        "decisions": [asdict(item) for item in shown],
        "decisions_omitted": len(steps) - len(shown),
        "audit_issues": [asdict(issue) for issue in issues_for_output[:max_items]],
        "audit_issues_omitted": max(0, len(issues_for_output) - max_items),
        "ambiguities": ambiguities[:max_items],
        "ambiguities_omitted": max(0, len(ambiguities) - max_items),
        "non_claims": non_claims,
    }


def render_owner_text(report: dict[str, Any]) -> str:
    run = report["run"]
    status = report["status"]
    freeze = report["freeze"]
    anchors = report["anchors"]
    lines = [
        "Filiolae run explanation",
        f"Run: {run['run_id'] or 'unknown'}",
        f"Status: {status['operational']} | evidence {status['integrity']}",
        f"Ledger: {run['records']} record(s), head {run['ledger_head_sha256'] or 'unavailable'}",
        f"Promotions: {status['promotion_count']}",
    ]
    if freeze["frozen"]:
        lines.append(f"FREEZE: {freeze['reason']} ({freeze['ts'] or 'timestamp unavailable'})")
    if anchors["required"]:
        checked = "verified" if anchors["checked"] and anchors["ok"] else "NOT VERIFIED"
        kind = anchors["kind"] or "unknown kind"
        lines.append(
            f"Signed head checkpoints ({kind}): required, {checked}; "
            f"current head={anchors['current_head_anchored']}"
        )
        if kind == UNIX_WITNESS_ANCHOR_KIND:
            enrollment = "checked" if anchors["enrollment_checked"] else "NOT CHECKED"
            lines.append(f"Unix witness enrollment: {enrollment}")
    else:
        lines.append("Signed head checkpoints: not required by genesis")
    lines.append("\nDecisions:")
    if not report["decisions"]:
        lines.append("- No Gate decision retained.")
    for item in report["decisions"]:
        label = f"step {item['step']}" if item["step"] is not None else "unknown step"
        lines.append(f"- {label}: {item['decision']}")
        if item["reason"]:
            lines.append(f"  reason: {item['reason']}")
        if item["authorized_weights"]:
            weight = item["authorized_weights"]
            lines.append(f"  recorded authorized weights: {weight.get('path')} sha256={weight.get('sha256')}")
        if item["shadow_eval"]:
            evaluation = item["shadow_eval"]
            lines.append(
                "  signed shadow eval: "
                f"candidate={evaluation.get('candidate_quality_bps')}bps "
                f"source={evaluation.get('source_quality_bps')}bps "
                f"regression={evaluation.get('regression_bps')}bps"
            )
    if report["decisions_omitted"]:
        lines.append(f"- ... {report['decisions_omitted']} older decision(s) omitted")
    lines.append("\nAudit issues / ambiguities:")
    if not report["audit_issues"]:
        lines.append("- None detected.")
    for issue in report["audit_issues"]:
        lines.append(f"- {issue['code']}@{issue['seq']}: {issue['message']}")
    if report["audit_issues_omitted"]:
        lines.append(f"- ... {report['audit_issues_omitted']} issue(s) omitted")
    lines.append("\nCurrent non-claims:")
    lines.extend(f"- {claim}" for claim in report["non_claims"])
    return "\n".join(lines)
