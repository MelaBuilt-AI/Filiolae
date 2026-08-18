#!/usr/bin/env python3
"""Replay retained Priority 6 GPU completions through the standard fail-closed Gate path."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from dataclasses import asdict
from pathlib import Path

from filiolae.anchor import generate_keypair, load_public_key, public_key_id
from filiolae.artifacts import digest_path
from filiolae.audit import audit_governance
from filiolae.canonical import canonical_json
from filiolae.charter import Charter
from filiolae.freeze import FreezeController
from filiolae.gate import PromotionGate
from filiolae.ledger import Ledger
from filiolae.paired_eval import request_sha256
from filiolae.paired_eval_replay import (
    REPLAY_CONFIG_SCHEMA,
    REPLAY_SCHEMA,
    ReplayFilesystemShadowEvaluator,
    replay_evaluator_bundle_body,
)
from filiolae.prime_rl_entrypoint import PrimeRLEvidenceBuilder
from filiolae.shadow_eval import CandidateEvalPolicy, CandidateEvalReceipt
from filiolae.store import ArtifactStore

SOURCE_SHA256 = "c047cbef4cca5dc09de95acd9f4a2ea884e8abd4f1e47dd34c2608165307c0c7"
CANDIDATE_SHA256 = "4bd8ca5cba086ff538f00f56fbd4ad9f241e05bc60e5307f976c63a81579473d"
ORIGINAL_CONFIG_SHA256 = "e911bb6d9f767b8baf67bba6410e77a1998f4cc18acd4cb41480b27facbae712"
ORIGINAL_RECEIPT_SHA256 = "b010d27b4ae3f1bd6645a7052d0d390a0ad2aacf5f192907bd6f2ad62c8ad179"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical(path: Path) -> dict[str, object] | list[object]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if raw != canonical_json(value) + b"\n":
        raise SystemExit(f"input is not canonical JSON: {path}")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--stage2-evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


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


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        raise SystemExit("output already exists")
    source_kind, source_digest, _ = digest_path(args.source)
    candidate_kind, candidate_digest, _ = digest_path(args.candidate)
    if (source_kind, source_digest) != ("directory", SOURCE_SHA256):
        raise SystemExit("source tree is not the preserved Priority 6 source")
    if (candidate_kind, candidate_digest) != ("directory", CANDIDATE_SHA256):
        raise SystemExit("candidate tree is not the preserved Priority 6 candidate")

    repo = Path(__file__).parents[1]
    assets = repo / "examples" / "candidate-eval"
    suite = assets / "reverse-text-held-out-v1.jsonl"
    source_manifest = assets / "r18-step1-source-manifest-v1.json"
    evidence = args.stage2_evidence.absolute()
    original_receipt_path = evidence / "terminal" / "receipt.json"
    original_public_key = evidence / "terminal" / "public.pem"
    source_results_path = evidence / "terminal" / "source-results.json"
    candidate_results_path = evidence / "terminal" / "candidate-results.json"
    original_config_path = evidence / "input" / "config.json"
    if _sha256(original_receipt_path) != ORIGINAL_RECEIPT_SHA256:
        raise SystemExit("original Stage 2 receipt digest mismatch")
    if _sha256(original_config_path) != ORIGINAL_CONFIG_SHA256:
        raise SystemExit("original Stage 2 config digest mismatch")

    output.mkdir(parents=True, mode=0o700)
    replay_package = output / "completion-replay.json"
    replay_value = {
        "candidate_results": _canonical(candidate_results_path),
        "original_public_key_pem": original_public_key.read_text(),
        "original_receipt": _canonical(original_receipt_path),
        "schema": REPLAY_SCHEMA,
        "source_results": _canonical(source_results_path),
    }
    replay_package.write_bytes(canonical_json(replay_value) + b"\n")

    original_config = _canonical(original_config_path)
    assert isinstance(original_config, dict)
    original_receipt = replay_value["original_receipt"]
    assert isinstance(original_receipt, dict)
    original_signer = original_receipt["signer_key_id"]
    replay_config_value = {
        **original_config,
        "replay": {
            "mode": "posthoc-retained-completions",
            "original_config_sha256": ORIGINAL_CONFIG_SHA256,
            "original_receipt_schema": "filiolae.priority6-stage2-gpu-eval.v1",
            "original_receipt_sha256": ORIGINAL_RECEIPT_SHA256,
            "original_signer_key_id": original_signer,
            "original_status": original_receipt["body"]["status"],
            "package_sha256": _sha256(replay_package),
        },
        "schema": REPLAY_CONFIG_SCHEMA,
    }
    replay_config = output / "replay-config.json"
    replay_config.write_bytes(canonical_json(replay_config_value) + b"\n")
    evaluator_bundle = output / "replay-evaluator-bundle.json"
    evaluator_bundle.write_bytes(canonical_json(replay_evaluator_bundle_body()) + b"\n")

    private_key = output / "replay-evaluator-private.pem"
    public_key = output / "replay-evaluator-public.pem"
    generate_keypair(private_key, public_key)
    policy = CandidateEvalPolicy(
        evaluator_sha256=_sha256(evaluator_bundle),
        suite_sha256=_sha256(suite),
        config_sha256=_sha256(replay_config),
        source_policy_sha256=_sha256(source_manifest),
        evaluator_signer_key_id=public_key_id(load_public_key(public_key)),
        minimum_quality_bps=8000,
        maximum_regression_bps=79,
        maximum_receipt_age_seconds=1800,
    )
    charter = _charter(output / "charter.yaml", policy)

    run = output / "run"
    (run / "control").mkdir(parents=True)
    (run / "control" / "orch.toml").write_text("max_steps = 2\n")
    pending = run / "broadcasts" / "step_2"
    pending.parent.mkdir(parents=True)
    shutil.copytree(args.candidate, pending, copy_function=shutil.copy2)
    traces = run / "rollouts" / "step_2" / "train" / "effective" / "traces.jsonl"
    traces.parent.mkdir(parents=True)
    traces.write_text('{"source":"posthoc-retained-completion-replay"}\n')

    control = run / "control" / "filiolae"
    store = ArtifactStore(control / "artifacts")
    ledger = Ledger.create(
        control / "ledger.jsonl",
        artifact_root=store.root,
        run_id="priority6-stage2-posthoc-replay-r1",
        charter_sha256=charter.sha256,
        metadata={
            "candidate_quality_evaluated": True,
            "evaluator_mode": "posthoc-retained-completion-replay",
            "live_inference": False,
        },
    )
    allowed_request = output / "allowed-request.sha256"

    class LocallyAuthorizedReplayEvaluator(ReplayFilesystemShadowEvaluator):
        def evaluate(self, request, candidate_path):
            allowed_request.write_text(request_sha256(request) + "\n")
            allowed_request.chmod(0o400)
            return super().evaluate(request, candidate_path)

    evaluator = LocallyAuthorizedReplayEvaluator(
        (sys.executable, "-m", "filiolae.paired_eval_replay_worker"),
        request_root=output / "requests",
        terminal_root=output / "terminal",
        source_path=args.source,
        evaluator_bundle=evaluator_bundle,
        suite_path=suite,
        config_path=replay_config,
        source_manifest_path=source_manifest,
        private_key_path=private_key,
        public_key_path=public_key,
        allowed_request_path=allowed_request,
        replay_path=replay_package,
        timeout_seconds=300,
    )
    builder = PrimeRLEvidenceBuilder(
        run,
        ledger,
        store,
        shadow_evaluator=evaluator,
        candidate_eval_policy=policy,
        candidate_eval_assets={
            "candidate_evaluator_bundle": evaluator_bundle,
            "candidate_eval_suite": suite,
            "candidate_eval_config": replay_config,
            "source_policy_manifest": source_manifest,
        },
    )
    promotion_request = builder.request_for_step(2, pending)
    freezer = FreezeController(control / "freeze.json")
    gate = PromotionGate(
        ledger,
        charter,
        freezer,
        candidate_eval_public_key=load_public_key(public_key),
    )
    decision = gate.authorize(
        promotion_request,
        current_policy_version=1,
        pending_weights_path=pending,
    )
    if decision.allowed or not freezer.state().frozen or "below the Charter threshold" not in decision.reason:
        raise SystemExit("replayed failed candidate did not fail closed at Gate")
    report = audit_governance(
        ledger,
        charter,
        verify_artifacts=True,
        candidate_eval_public_key=load_public_key(public_key),
    )
    if not report.ok:
        raise SystemExit(report.summary())

    result_record = ledger.record(promotion_request.candidate_eval_seq or -1)
    receipt_path = ledger.artifact_root / result_record.artifacts[0].path
    receipt = CandidateEvalReceipt.from_bytes(receipt_path.read_bytes())
    request_digest = next((output / "terminal").glob("*/*")).name
    terminal_evidence = _canonical(
        output / "terminal" / request_digest[:2] / request_digest / "evidence.json"
    )
    assert isinstance(terminal_evidence, dict)
    events = [record.event for record in ledger.records()]
    summary = {
        "audit": report.summary(),
        "bounded_claim": (
            "post-hoc replay of retained real completions through standard receipt, Ledger, "
            "Gate denial/freeze, and offline audit"
        ),
        "candidate_quality_bps": receipt.body["candidate_quality_bps"],
        "decision_allowed": decision.allowed,
        "decision_reason": decision.reason,
        "events": events,
        "freeze": asdict(freezer.state()),
        "gate_denial_recorded": events[-2:] == ["tripwire.fired", "gate.denied"],
        "live_inference": False,
        "non_claims": [
            "not a new or live model evaluation",
            "same-UID local replay is not a separate credential-domain claim",
            "does not repair the original GPU runner retroactively",
            "no promotion, deployment, publication, or rerun authority",
        ],
        "original_receipt_sha256": ORIGINAL_RECEIPT_SHA256,
        "replay_evaluator_signer_key_id": policy.evaluator_signer_key_id,
        "replay_package_sha256": _sha256(replay_package),
        "schema": "filiolae.priority6-stage2-posthoc-gate-replay.v1",
        "source_quality_bps": receipt.body["source_quality_bps"],
        "standard_receipt_sha256": _sha256(receipt_path),
        "terminal_provenance": {
            name: terminal_evidence["body"][name]
            for name in (
                "evaluator_mode",
                "original_receipt_sha256",
                "original_signer_key_id",
                "original_status",
                "replay_package_sha256",
            )
        },
    }
    (output / "SUMMARY.json").write_bytes(canonical_json(summary) + b"\n")
    (output / "AUDIT.txt").write_text(report.summary() + "\n")
    private_key.unlink()
    pending.chmod(pending.stat().st_mode | 0o700)
    for path in pending.rglob("*"):
        path.chmod(path.stat().st_mode | (0o700 if path.is_dir() else 0o200))
    shutil.rmtree(pending)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
