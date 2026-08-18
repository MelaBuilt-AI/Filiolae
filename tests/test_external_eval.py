from __future__ import annotations

import hashlib
import shutil
import threading
import time
from pathlib import Path

from filiolae.anchor import load_public_key, public_key_id
from filiolae.audit import audit_governance
from filiolae.charter import Charter
from filiolae.external_eval import ExternalTerminalShadowEvaluator
from filiolae.freeze import FreezeController
from filiolae.gate import PromotionGate
from filiolae.ledger import Ledger
from filiolae.paired_eval import load_request, request_sha256, run_cpu_fixture_evaluator
from filiolae.prime_rl_entrypoint import PrimeRLEvidenceBuilder
from filiolae.shadow_eval import CandidateEvalPolicy
from filiolae.store import ArtifactStore
from tests.test_paired_eval import NOW, _setup


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _charter(path: Path, policy: CandidateEvalPolicy) -> Charter:
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
      evaluator_sha256: {policy.evaluator_sha256}
      suite_sha256: {policy.suite_sha256}
      config_sha256: {policy.config_sha256}
      source_policy_sha256: {policy.source_policy_sha256}
      evaluator_signer_key_id: {policy.evaluator_signer_key_id}
      minimum_quality_bps: {policy.minimum_quality_bps}
      maximum_regression_bps: {policy.maximum_regression_bps}
      maximum_receipt_age_seconds: {policy.maximum_receipt_age_seconds}
"""
    )
    return Charter.load(path)


def test_external_terminal_package_is_content_addressed_gate_verified_and_audited(
    tmp_path: Path,
) -> None:
    evaluator_root = tmp_path / "evaluator"
    evaluator_root.mkdir()
    paths = _setup(evaluator_root)
    policy = CandidateEvalPolicy(
        evaluator_sha256=_sha256(paths["evaluator_bundle"]),
        suite_sha256=_sha256(paths["suite"]),
        config_sha256=_sha256(paths["config"]),
        source_policy_sha256=_sha256(paths["source_manifest"]),
        evaluator_signer_key_id=public_key_id(load_public_key(paths["public_key"])),
        minimum_quality_bps=9000,
        maximum_regression_bps=0,
        maximum_receipt_age_seconds=300,
    )
    charter = _charter(tmp_path / "charter.yaml", policy)
    output = tmp_path / "run"
    (output / "control").mkdir(parents=True)
    (output / "control" / "orch.toml").write_text("max_steps = 1\n")
    pending = output / "broadcasts" / "step_1"
    pending.parent.mkdir(parents=True)
    shutil.copytree(paths["candidate"], pending)
    traces = output / "rollouts" / "step_1" / "train" / "effective" / "traces.jsonl"
    traces.parent.mkdir(parents=True)
    traces.write_text('{"source":"external-terminal-fixture"}\n')
    control = output / "control" / "filiolae"
    store = ArtifactStore(control / "artifacts")
    ledger = Ledger.create(
        control / "ledger.jsonl",
        artifact_root=store.root,
        run_id="external-terminal-run",
        charter_sha256=charter.sha256,
        metadata={"candidate_quality_evaluated": False, "fixture_only": True},
        clock=lambda: NOW,
    )
    request_root = tmp_path / "requests"
    terminal_root = tmp_path / "terminal"
    adapter = ExternalTerminalShadowEvaluator(
        request_root=request_root,
        terminal_root=terminal_root,
        public_key_path=paths["public_key"],
        suite_path=paths["suite"],
        timeout_seconds=2,
        poll_interval_seconds=0.01,
    )
    worker_errors: list[BaseException] = []

    def evaluator_service() -> None:
        try:
            deadline = time.monotonic() + 1
            request_files: list[Path] = []
            while time.monotonic() < deadline and not request_files:
                request_files = list(request_root.glob("*.json")) if request_root.exists() else []
                time.sleep(0.005)
            assert len(request_files) == 1
            request_path = request_files[0]
            digest = request_path.stem
            allowed_request = tmp_path / "evaluator-allow-request.sha256"
            allowed_request.write_text(digest + "\n")
            allowed_request.chmod(0o400)
            run_cpu_fixture_evaluator(
                request_path=request_path,
                source_path=paths["source"],
                candidate_path=pending,
                evaluator_bundle=paths["evaluator_bundle"],
                suite_path=paths["suite"],
                config_path=paths["config"],
                source_manifest_path=paths["source_manifest"],
                private_key_path=paths["private_key"],
                allowed_request_path=allowed_request,
                fixture_path=paths["fixture"],
                terminal_root=terminal_root,
                clock=lambda: NOW,
            )
        except BaseException as exc:
            worker_errors.append(exc)

    worker = threading.Thread(target=evaluator_service, daemon=True)
    worker.start()
    builder = PrimeRLEvidenceBuilder(
        output,
        ledger,
        store,
        shadow_evaluator=adapter,
        candidate_eval_policy=policy,
        candidate_eval_assets={
            "candidate_evaluator_bundle": paths["evaluator_bundle"],
            "candidate_eval_suite": paths["suite"],
            "candidate_eval_config": paths["config"],
            "source_policy_manifest": paths["source_manifest"],
        },
    )
    request = builder.request_for_step(1, pending)
    worker.join(2)
    assert not worker.is_alive() and not worker_errors

    result = ledger.record(request.candidate_eval_seq or -1)
    assert [artifact.name for artifact in result.artifacts] == [
        "candidate_eval_receipt",
        "candidate_eval_terminal",
    ]
    terminal_artifact = result.artifacts[1]
    terminal_package = ledger.artifact_root / terminal_artifact.path
    digest = next((terminal_package).glob("*/*")).name
    # Gate reconstructs this request; the retained package is keyed by the same digest.
    assert digest == request_sha256(load_request(next(request_root.glob("*.json"))))
    assert (terminal_package / digest[:2] / digest / "receipt.json").is_file()
    assert (terminal_package / digest[:2] / digest / "evidence.json").is_file()

    freezer = FreezeController(control / "freeze.json", clock=lambda: NOW)
    public_key = load_public_key(paths["public_key"])
    gate = PromotionGate(
        ledger,
        charter,
        freezer,
        candidate_eval_public_key=public_key,
        clock=lambda: NOW,
    )
    decision = gate.authorize(request, current_policy_version=0, pending_weights_path=pending)
    assert decision.allowed and not freezer.state().frozen
    approval = ledger.record(decision.ledger_seq or -1)
    assert approval.data["shadow_eval"]["terminal_evidence_sha256"] == terminal_artifact.sha256
    ledger.append(
        "policy.promoted",
        actor="disposable-shadow-loader",
        data={
            "attempt_id": request.attempt_id,
            "step": request.step,
            "source_policy_version": request.source_policy_version,
            "gate_approval_seq": decision.ledger_seq,
        },
    )
    report = audit_governance(
        ledger,
        charter,
        verify_artifacts=True,
        candidate_eval_public_key=public_key,
    )
    assert report.ok, report.summary()
    assert report.promotion_count == 1
