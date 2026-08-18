from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from filiolae.anchor import public_key_id
from filiolae.audit import audit_governance
from filiolae.charter import Charter, CharterError
from filiolae.freeze import FreezeController
from filiolae.gate import PromotionGate
from filiolae.ledger import Ledger
from filiolae.prime_rl_entrypoint import PrimeRLEvidenceBuilder
from filiolae.shadow_eval import (
    CandidateEvalError,
    CandidateEvalPolicy,
    CandidateEvalReceipt,
    CandidateEvalRequest,
    CPUMockShadowEvaluator,
)
from filiolae.store import ArtifactStore

NOW = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)


def _charter(
    tmp_path: Path,
    private_key: Ed25519PrivateKey,
    asset_digests: dict[str, str],
) -> Charter:
    signer = public_key_id(private_key.public_key())
    path = tmp_path / "charter.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"""version: 1
clauses:
  - id: C-IMMUTABLE
    severity: hard
    statement: Retained artifacts are immutable.
    rule: immutable_artifacts
    parameters: {{}}
  - id: C-EVIDENCE
    severity: hard
    statement: Promotions require lineage evidence.
    rule: promotion_evidence_required
    parameters:
      events: [config.resolved, batch.committed, source_eval.result, weights.published]
  - id: C-FREEZE
    severity: hard
    statement: Integrity failures freeze.
    rule: freeze_on_integrity_failure
    parameters: {{}}
  - id: C-SHADOW
    severity: hard
    statement: Candidates require signed paired shadow evaluation.
    rule: candidate_shadow_evaluation
    parameters:
      evaluator_sha256: {asset_digests["candidate_evaluator_bundle"]}
      suite_sha256: {asset_digests["candidate_eval_suite"]}
      config_sha256: {asset_digests["candidate_eval_config"]}
      source_policy_sha256: {asset_digests["source_policy_manifest"]}
      evaluator_signer_key_id: {signer}
      minimum_quality_bps: 9000
      maximum_regression_bps: 100
      maximum_receipt_age_seconds: 300
"""
    )
    return Charter.load(path)


def _integration(
    tmp_path: Path,
    *,
    candidate_quality_bps: int | None = 9500,
    source_quality_bps: int | None = 9550,
    status: str = "completed",
    evaluator_key: Ed25519PrivateKey | None = None,
    policy_key: Ed25519PrivateKey | None = None,
    gate_now: datetime = NOW,
    with_evaluator: bool = True,
    evaluator_error: bool = False,
    terminal_error: bool = False,
):
    policy_key = policy_key or Ed25519PrivateKey.generate()
    evaluator_key = evaluator_key or policy_key
    assets_root = tmp_path / "shadow-assets"
    assets_root.mkdir(parents=True)
    assets = {
        "candidate_evaluator_bundle": assets_root / "evaluator.txt",
        "candidate_eval_suite": assets_root / "suite.jsonl",
        "candidate_eval_config": assets_root / "config.json",
        "source_policy_manifest": assets_root / "source-policy.json",
    }
    assets["candidate_evaluator_bundle"].write_text("cpu-mock-shadow-evaluator-v1\n")
    assets["candidate_eval_suite"].write_text('{"case":"reverse-text"}\n')
    assets["candidate_eval_config"].write_text('{"paired_source":true}\n')
    assets["source_policy_manifest"].write_text('{"policy_version":0,"weights_sha256":"' + "d" * 64 + '"}\n')
    asset_digests = {name: sha256(path.read_bytes()).hexdigest() for name, path in assets.items()}
    charter = _charter(tmp_path, policy_key, asset_digests)
    policy = charter.candidate_eval_policy()
    assert isinstance(policy, CandidateEvalPolicy)
    output = tmp_path / "run"
    (output / "control").mkdir(parents=True)
    (output / "control" / "orch.toml").write_text("max_steps = 1\n")
    pending = output / "broadcasts" / "step_1"
    pending.mkdir(parents=True)
    (pending / "STABLE").write_text("ready\n")
    (pending / "model.bin").write_bytes(b"candidate-shadow-model")
    traces = output / "rollouts" / "step_1" / "train" / "effective" / "traces.jsonl"
    traces.parent.mkdir(parents=True)
    traces.write_text('{"reward":1}\n')
    control = output / "control" / "filiolae"
    store = ArtifactStore(control / "artifacts")
    ledger = Ledger.create(
        control / "ledger.jsonl",
        artifact_root=store.root,
        run_id="shadow-run",
        charter_sha256=charter.sha256,
        metadata={"candidate_quality_evaluated": True, "evaluator_mode": "cpu_mock"},
        clock=lambda: NOW,
    )
    evaluator = None
    if with_evaluator:
        if evaluator_error:

            class FailingEvaluator:
                def evaluate(self, request, candidate_path):
                    raise CandidateEvalError("simulated evaluator outage")

            evaluator = FailingEvaluator()
        else:
            evaluator = CPUMockShadowEvaluator(
                evaluator_key,
                candidate_quality_bps=candidate_quality_bps,
                source_quality_bps=source_quality_bps,
                status=status,
                clock=lambda: NOW,
            )
            if terminal_error:
                base_evaluator = evaluator

                class MissingTerminalEvaluator:
                    def evaluate(self, request, candidate_path):
                        return base_evaluator.evaluate(request, candidate_path)

                    def terminal_evidence_root(self, request):
                        raise CandidateEvalError("simulated missing complete terminal package")

                evaluator = MissingTerminalEvaluator()
    builder = PrimeRLEvidenceBuilder(
        output,
        ledger,
        store,
        shadow_evaluator=evaluator,
        candidate_eval_policy=policy if with_evaluator else None,
        candidate_eval_assets=assets if with_evaluator else None,
    )
    request = builder.request_for_step(1, pending)
    freezer = FreezeController(control / "freeze.json", clock=lambda: NOW)
    gate = PromotionGate(
        ledger,
        charter,
        freezer,
        candidate_eval_public_key=policy_key.public_key(),
        clock=lambda: gate_now,
    )
    return charter, ledger, pending, request, freezer, gate, policy_key


def test_cpu_mock_shadow_eval_allows_exact_digest_bound_candidate(tmp_path: Path) -> None:
    charter, ledger, pending, request, freezer, gate, key = _integration(tmp_path)

    decision = gate.authorize(request, current_policy_version=0, pending_weights_path=pending)

    assert decision.allowed
    assert not freezer.state().frozen
    approval = ledger.record(decision.ledger_seq or -1)
    configured = ledger.record(request.candidate_eval_config_seq or -1)
    control_digests = {artifact.name: artifact.sha256 for artifact in configured.artifacts}
    assert control_digests == {
        "candidate_evaluator_bundle": charter.candidate_eval_policy().evaluator_sha256,
        "candidate_eval_suite": charter.candidate_eval_policy().suite_sha256,
        "candidate_eval_config": charter.candidate_eval_policy().config_sha256,
        "source_policy_manifest": charter.candidate_eval_policy().source_policy_sha256,
    }
    receipt_artifact = ledger.record(request.candidate_eval_seq or -1).artifacts[0]
    receipt = CandidateEvalReceipt.from_bytes((ledger.artifact_root / receipt_artifact.path).read_bytes())
    assert receipt.body["source_policy_sha256"] == control_digests["source_policy_manifest"]
    assert approval.data["shadow_eval"] == {
        "candidate_quality_bps": 9500,
        "source_quality_bps": 9550,
        "regression_bps": 50,
        "receipt_sha256": ledger.record(request.candidate_eval_seq or -1).artifacts[0].sha256,
        "candidate_eval_seq": request.candidate_eval_seq,
        "evaluator_signer_key_id": public_key_id(key.public_key()),
    }
    ledger.append(
        "policy.promoted",
        actor="adapter",
        data={
            "attempt_id": request.attempt_id,
            "step": 1,
            "source_policy_version": 0,
            "gate_approval_seq": decision.ledger_seq,
        },
    )
    report = audit_governance(
        ledger,
        charter,
        verify_artifacts=True,
        candidate_eval_public_key=key.public_key(),
    )
    assert report.ok, report.summary()


def test_missing_candidate_shadow_eval_denies_and_freezes(tmp_path: Path) -> None:
    _, ledger, pending, request, freezer, gate, _ = _integration(tmp_path, with_evaluator=False)

    decision = gate.authorize(request, current_policy_version=0, pending_weights_path=pending)

    assert not decision.allowed
    assert "candidate evaluator configuration is missing" in decision.reason
    assert freezer.state().frozen
    assert "gate.approved" not in [record.event for record in ledger.records()]


@pytest.mark.parametrize(
    ("candidate", "source", "status", "reason"),
    [
        (8999, 8999, "completed", "below the Charter threshold"),
        (9500, 9601, "completed", "regression exceeds"),
        (None, None, "error", "reported failure"),
    ],
)
def test_quality_regression_and_evaluator_failure_deny(
    tmp_path: Path,
    candidate: int | None,
    source: int | None,
    status: str,
    reason: str,
) -> None:
    _, ledger, pending, request, freezer, gate, _ = _integration(
        tmp_path,
        candidate_quality_bps=candidate,
        source_quality_bps=source,
        status=status,
    )

    decision = gate.authorize(request, current_policy_version=0, pending_weights_path=pending)

    assert not decision.allowed and reason in decision.reason
    assert freezer.state().frozen
    assert "gate.approved" not in [record.event for record in ledger.records()]


def test_wrong_signer_and_stale_receipt_deny(tmp_path: Path) -> None:
    policy_key = Ed25519PrivateKey.generate()
    wrong_key = Ed25519PrivateKey.generate()
    _, _, pending, request, freezer, gate, _ = _integration(
        tmp_path / "wrong",
        policy_key=policy_key,
        evaluator_key=wrong_key,
    )
    decision = gate.authorize(request, current_policy_version=0, pending_weights_path=pending)
    assert not decision.allowed and "signer" in decision.reason
    assert freezer.state().frozen

    _, _, pending, request, freezer, gate, _ = _integration(
        tmp_path / "stale",
        gate_now=NOW + timedelta(seconds=301),
    )
    decision = gate.authorize(request, current_policy_version=0, pending_weights_path=pending)
    assert not decision.allowed and "stale" in decision.reason
    assert freezer.state().frozen


def test_candidate_receipt_parser_rejects_malformed_and_extra_fields(tmp_path: Path) -> None:
    _, ledger, _, request, _, _, _ = _integration(tmp_path)
    artifact = ledger.record(request.candidate_eval_seq or -1).artifacts[0]
    raw = (ledger.artifact_root / artifact.path).read_bytes()
    receipt = CandidateEvalReceipt.from_bytes(raw)
    malformed = {**receipt.to_dict(), "extra": True}
    from filiolae.canonical import canonical_json

    with pytest.raises(CandidateEvalError, match="fields"):
        CandidateEvalReceipt.from_bytes(canonical_json(malformed) + b"\n")
    with pytest.raises(CandidateEvalError, match="canonical"):
        CandidateEvalReceipt.from_bytes(b'{"body": {}, "signer_key_id": "x", "signature": "x"}\n')


def test_offline_audit_requires_and_reverifies_candidate_key(tmp_path: Path) -> None:
    charter, ledger, pending, request, _, gate, key = _integration(tmp_path)
    decision = gate.authorize(request, current_policy_version=0, pending_weights_path=pending)
    ledger.append(
        "policy.promoted",
        actor="adapter",
        data={
            "attempt_id": request.attempt_id,
            "step": 1,
            "source_policy_version": 0,
            "gate_approval_seq": decision.ledger_seq,
        },
    )
    assert not audit_governance(ledger, charter).ok
    assert audit_governance(ledger, charter, candidate_eval_public_key=key.public_key()).ok


def test_charter_rejects_soft_or_malformed_shadow_policy(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    _charter(
        tmp_path,
        key,
        {
            "candidate_evaluator_bundle": "a" * 64,
            "candidate_eval_suite": "b" * 64,
            "candidate_eval_config": "c" * 64,
            "source_policy_manifest": "d" * 64,
        },
    )
    path = tmp_path / "charter.yaml"
    text = path.read_text()
    path.write_text(text.replace("minimum_quality_bps: 9000", "minimum_quality_bps: true"))
    with pytest.raises(CharterError, match="minimum_quality_bps"):
        Charter.load(path)

    path.write_text(text.replace(public_key_id(key.public_key()), "sha256:" + "g" * 64))
    with pytest.raises(CharterError, match="evaluator_signer_key_id"):
        Charter.load(path)

    path.write_text(
        text.replace(
            "severity: hard\n    statement: Candidates",
            "severity: soft\n    statement: Candidates",
        )
    )
    with pytest.raises(CharterError, match="must be hard"):
        Charter.load(path)


def test_cpu_mock_refuses_candidate_bytes_that_contradict_request_digest(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    policy = CandidateEvalPolicy(
        evaluator_sha256="a" * 64,
        suite_sha256="b" * 64,
        config_sha256="c" * 64,
        source_policy_sha256="d" * 64,
        evaluator_signer_key_id=public_key_id(key.public_key()),
        minimum_quality_bps=9000,
        maximum_regression_bps=100,
        maximum_receipt_age_seconds=300,
    )
    candidate = tmp_path / "candidate.bin"
    candidate.write_bytes(b"different candidate bytes")
    evaluator = CPUMockShadowEvaluator(
        key,
        candidate_quality_bps=9500,
        source_quality_bps=9500,
        clock=lambda: NOW,
    )
    request = CandidateEvalRequest(
        run_id="run",
        attempt_id="attempt",
        step=1,
        source_policy_version=0,
        candidate_sha256="0" * 64,
        evaluated_ledger_seq=1,
        evaluated_ledger_head_sha256="e" * 64,
        policy=policy,
    )

    with pytest.raises(CandidateEvalError, match="candidate bytes contradict"):
        evaluator.evaluate(request, candidate)


def test_evaluator_exception_reaches_durable_gate_denial_and_freeze(tmp_path: Path) -> None:
    _, ledger, pending, request, freezer, gate, _ = _integration(tmp_path, evaluator_error=True)

    result = ledger.record(request.candidate_eval_seq or -1)
    unavailable = (ledger.artifact_root / result.artifacts[0].path).read_text()
    assert '"schema":"filiolae.candidate-eval-unavailable.v1"' in unavailable
    decision = gate.authorize(request, current_policy_version=0, pending_weights_path=pending)

    assert not decision.allowed
    assert "candidate shadow-evaluation failed" in decision.reason
    assert freezer.state().frozen
    assert [record.event for record in ledger.records()][-2:] == ["tripwire.fired", "gate.denied"]


def test_missing_complete_terminal_package_reaches_durable_gate_denial(tmp_path: Path) -> None:
    _, ledger, pending, request, freezer, gate, _ = _integration(tmp_path, terminal_error=True)

    result = ledger.record(request.candidate_eval_seq or -1)
    assert [artifact.name for artifact in result.artifacts] == ["candidate_eval_receipt"]
    unavailable = (ledger.artifact_root / result.artifacts[0].path).read_text()
    assert '"reason_code":"complete-terminal-evidence-unavailable"' in unavailable
    decision = gate.authorize(request, current_policy_version=0, pending_weights_path=pending)

    assert not decision.allowed
    assert freezer.state().frozen
    assert [record.event for record in ledger.records()][-2:] == ["tripwire.fired", "gate.denied"]
