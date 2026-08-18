from __future__ import annotations

import base64
import hashlib
import json
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from filiolae.anchor import generate_keypair, load_public_key, public_key_id
from filiolae.artifacts import digest_path
from filiolae.audit import audit_governance
from filiolae.canonical import canonical_json
from filiolae.charter import Charter
from filiolae.freeze import FreezeController
from filiolae.gate import PromotionGate
from filiolae.ledger import Ledger
from filiolae.paired_eval import (
    PairedEvalProtocolError,
    _score,
    request_sha256,
    verify_terminal_evidence,
)
from filiolae.paired_eval_replay import (
    ORIGINAL_RECEIPT_SCHEMA,
    ORIGINAL_SIGNATURE_DOMAIN,
    REPLAY_CONFIG_SCHEMA,
    REPLAY_SCHEMA,
    ReplayFilesystemShadowEvaluator,
    replay_evaluator_bundle_body,
    run_completion_replay_evaluator,
)
from filiolae.prime_rl_entrypoint import PrimeRLEvidenceBuilder
from filiolae.shadow_eval import CandidateEvalPolicy, CandidateEvalRequest
from filiolae.store import ArtifactStore

NOW = datetime(2026, 8, 13, 18, 0, tzinfo=UTC)


def _write(path: Path, value: object) -> None:
    path.write_bytes(canonical_json(value) + b"\n")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _setup(tmp_path: Path, *, corrupt_original_signature: bool = False):
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = tmp_path / "source"
    candidate = tmp_path / "candidate"
    source.mkdir()
    candidate.mkdir()
    (source / "weights.bin").write_bytes(b"source")
    (candidate / "STABLE").write_text("")
    (candidate / "weights.bin").write_bytes(b"candidate")
    source_kind, source_sha, source_size = digest_path(source)
    _, candidate_sha, candidate_size = digest_path(candidate)

    cases = [
        {
            "answer": "cba",
            "case_id": "case-001",
            "prompt": "abc",
            "schema": "filiolae.reverse-text-eval-case.v1",
        },
        {
            "answer": "zyx",
            "case_id": "case-002",
            "prompt": "xyz",
            "schema": "filiolae.reverse-text-eval-case.v1",
        },
    ]
    suite = tmp_path / "suite.jsonl"
    suite.write_bytes(b"".join(canonical_json(case) + b"\n" for case in cases))
    source_manifest = tmp_path / "source-manifest.json"
    _write(
        source_manifest,
        {
            "schema": "filiolae.source-policy-manifest.v1",
            "source_policy_version": 1,
            "source_weights": {
                "artifact_kind": source_kind,
                "sha256": source_sha,
                "size": source_size,
            },
        },
    )
    core_config = {
        "charter_thresholds": {
            "maximum_receipt_age_seconds": 1800,
            "maximum_regression_bps": 79,
            "minimum_quality_bps": 8000,
        },
        "inference": {
            "case_retry_count": 0,
            "completions_per_case": 1,
            "do_sample": False,
            "max_completion_tokens": 128,
            "temperature": 0,
            "top_p": 1,
        },
        "parsing": {
            "captured_text_normalization": "strip",
            "flags": ["DOTALL"],
            "match": "first",
            "pattern": "<reversed_text>(.*?)</reversed_text>",
        },
        "prompting": {
            "renderer": "unit-test",
            "system": "Reverse the text character-by-character. Put your answer in <reversed_text> tags.",
        },
        "schema": "filiolae.reverse-text-paired-eval-config.v1",
        "scoring": {
            "diagnostic": "mean_sequence_matcher_ratio_bps",
            "incomplete_case_policy": "error_no_scores",
            "primary": "exact_match_rate_bps",
            "primary_formula": "floor(10000 * exact_matches / 2)",
        },
        "suite": {
            "case_count": 2,
            "order": "case_id_ascii_ascending",
            "sha256": _sha(suite),
        },
    }
    source_rows, source_quality, source_lcs = _score(
        cases,
        ["<reversed_text>cba</reversed_text>", "<reversed_text>zyx</reversed_text>"],
    )
    candidate_rows, candidate_quality, candidate_lcs = _score(
        cases,
        ["<reversed_text>bad</reversed_text>", "<reversed_text>zyx</reversed_text>"],
    )
    original_key = Ed25519PrivateKey.generate()
    original_public_pem = (
        original_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    original_raw = original_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    original_key_id = "sha256:" + hashlib.sha256(original_raw).hexdigest()
    original_config_sha = "f" * 64
    body = {
        "candidate": {
            "count": 2,
            "mean_lcs_bps": candidate_lcs,
            "outputs_sha256": hashlib.sha256(canonical_json(candidate_rows) + b"\n").hexdigest(),
            "quality_bps": candidate_quality,
        },
        "candidate_size": candidate_size,
        "candidate_tree_sha256": candidate_sha,
        "case_retry_count": 0,
        "config_sha256": original_config_sha,
        "device": "cuda:0",
        "do_sample": False,
        "dtype": "float16",
        "finished_at": "2026-08-13T16:57:20Z",
        "maximum_regression_bps": 79,
        "minimum_quality_bps": 8000,
        "model_repo_id": "example/model",
        "model_revision": "1" * 40,
        "network_policy": "offline-during-inference-via-library-offline-modes",
        "regression_bps": source_quality - candidate_quality,
        "schema": ORIGINAL_RECEIPT_SCHEMA,
        "signer_key_id": original_key_id,
        "source": {
            "count": 2,
            "mean_lcs_bps": source_lcs,
            "outputs_sha256": hashlib.sha256(canonical_json(source_rows) + b"\n").hexdigest(),
            "quality_bps": source_quality,
        },
        "source_manifest_sha256": _sha(source_manifest),
        "source_size": source_size,
        "source_tree_sha256": source_sha,
        "started_at": "2026-08-13T16:35:02Z",
        "status": "threshold-failed",
        "suite_sha256": _sha(suite),
        "tokenizer_json_sha256": "2" * 64,
    }
    signature = original_key.sign(ORIGINAL_SIGNATURE_DOMAIN + canonical_json(body))
    if corrupt_original_signature:
        signature = bytes([signature[0] ^ 1]) + signature[1:]
    original_receipt = {
        "body": body,
        "signature": base64.b64encode(signature).decode(),
        "signer_key_id": original_key_id,
    }
    replay = tmp_path / "replay.json"
    _write(
        replay,
        {
            "candidate_results": candidate_rows,
            "original_public_key_pem": original_public_pem,
            "original_receipt": original_receipt,
            "schema": REPLAY_SCHEMA,
            "source_results": source_rows,
        },
    )
    replay_config = tmp_path / "replay-config.json"
    _write(
        replay_config,
        {
            **core_config,
            "replay": {
                "mode": "posthoc-retained-completions",
                "original_config_sha256": original_config_sha,
                "original_receipt_schema": ORIGINAL_RECEIPT_SCHEMA,
                "original_receipt_sha256": hashlib.sha256(
                    canonical_json(original_receipt) + b"\n"
                ).hexdigest(),
                "original_signer_key_id": original_key_id,
                "original_status": "threshold-failed",
                "package_sha256": _sha(replay),
            },
            "schema": REPLAY_CONFIG_SCHEMA,
        },
    )
    bundle = tmp_path / "bundle.json"
    _write(bundle, replay_evaluator_bundle_body())
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    generate_keypair(private_key, public_key)
    policy = CandidateEvalPolicy(
        evaluator_sha256=_sha(bundle),
        suite_sha256=_sha(suite),
        config_sha256=_sha(replay_config),
        source_policy_sha256=_sha(source_manifest),
        evaluator_signer_key_id=public_key_id(load_public_key(public_key)),
        minimum_quality_bps=8000,
        maximum_regression_bps=79,
        maximum_receipt_age_seconds=1800,
    )
    request = CandidateEvalRequest(
        run_id="replay-run",
        attempt_id="replay-attempt",
        step=2,
        source_policy_version=1,
        candidate_sha256=candidate_sha,
        evaluated_ledger_seq=4,
        evaluated_ledger_head_sha256="e" * 64,
        policy=policy,
    )
    request_path = tmp_path / "request.json"
    request_path.write_bytes(
        canonical_json(
            {
                "attempt_id": request.attempt_id,
                "candidate_sha256": request.candidate_sha256,
                "evaluated_ledger_head_sha256": request.evaluated_ledger_head_sha256,
                "evaluated_ledger_seq": request.evaluated_ledger_seq,
                "policy": {
                    "config_sha256": policy.config_sha256,
                    "evaluator_sha256": policy.evaluator_sha256,
                    "evaluator_signer_key_id": policy.evaluator_signer_key_id,
                    "maximum_receipt_age_seconds": policy.maximum_receipt_age_seconds,
                    "maximum_regression_bps": policy.maximum_regression_bps,
                    "minimum_quality_bps": policy.minimum_quality_bps,
                    "source_policy_sha256": policy.source_policy_sha256,
                    "suite_sha256": policy.suite_sha256,
                },
                "run_id": request.run_id,
                "schema": "filiolae.paired-eval-request.v1",
                "source_policy_version": request.source_policy_version,
                "step": request.step,
            }
        )
        + b"\n"
    )
    allowlist = tmp_path / "allowed.sha256"
    allowlist.write_text(request_sha256(request) + "\n")
    allowlist.chmod(0o400)
    return {
        "allowlist": allowlist,
        "bundle": bundle,
        "candidate": candidate,
        "config": replay_config,
        "policy": policy,
        "private_key": private_key,
        "public_key": public_key,
        "replay": replay,
        "request": request,
        "request_path": request_path,
        "source": source,
        "source_manifest": source_manifest,
        "suite": suite,
        "terminal": tmp_path / "terminal",
    }


def test_posthoc_replay_emits_standard_complete_terminal_receipt(tmp_path: Path) -> None:
    values = _setup(tmp_path)
    receipt = run_completion_replay_evaluator(
        request_path=values["request_path"],
        source_path=values["source"],
        candidate_path=values["candidate"],
        evaluator_bundle=values["bundle"],
        suite_path=values["suite"],
        config_path=values["config"],
        source_manifest_path=values["source_manifest"],
        private_key_path=values["private_key"],
        allowed_request_path=values["allowlist"],
        replay_path=values["replay"],
        terminal_root=values["terminal"],
        clock=lambda: NOW,
    )
    assert receipt.body["status"] == "completed"
    assert receipt.body["source_quality_bps"] == 10_000
    assert receipt.body["candidate_quality_bps"] == 5_000
    verified = verify_terminal_evidence(
        values["terminal"],
        values["request"],
        load_public_key(values["public_key"]),
        values["suite"],
    )
    assert verified == receipt
    digest = request_sha256(values["request"])
    evidence = json.loads((values["terminal"] / digest[:2] / digest / "evidence.json").read_text())["body"]
    assert evidence["evaluator_mode"] == "posthoc-completion-replay-no-live-inference"
    assert evidence["original_status"] == "threshold-failed"


def test_posthoc_replay_rejects_invalid_original_signature_even_when_package_is_pinned(
    tmp_path: Path,
) -> None:
    values = _setup(tmp_path, corrupt_original_signature=True)
    with pytest.raises(PairedEvalProtocolError, match="original replay receipt signature"):
        run_completion_replay_evaluator(
            request_path=values["request_path"],
            source_path=values["source"],
            candidate_path=values["candidate"],
            evaluator_bundle=values["bundle"],
            suite_path=values["suite"],
            config_path=values["config"],
            source_manifest_path=values["source_manifest"],
            private_key_path=values["private_key"],
            allowed_request_path=values["allowlist"],
            replay_path=values["replay"],
            terminal_root=values["terminal"],
            clock=lambda: NOW,
        )


def test_posthoc_replay_drives_standard_ledger_gate_denial_freeze_and_audit(
    tmp_path: Path,
) -> None:
    values = _setup(tmp_path / "assets")
    policy = values["policy"]
    assert isinstance(policy, CandidateEvalPolicy)
    charter_path = tmp_path / "charter.yaml"
    charter_path.write_text(
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
    charter = Charter.load(charter_path)
    run = tmp_path / "run"
    (run / "control").mkdir(parents=True)
    (run / "control" / "orch.toml").write_text("max_steps = 2\n")
    pending = run / "broadcasts" / "step_2"
    pending.parent.mkdir(parents=True)
    shutil.copytree(values["candidate"], pending)
    traces = run / "rollouts" / "step_2" / "train" / "effective" / "traces.jsonl"
    traces.parent.mkdir(parents=True)
    traces.write_text('{"source":"test-replay"}\n')
    store = ArtifactStore(run / "control" / "filiolae" / "artifacts")
    ledger = Ledger.create(
        run / "control" / "filiolae" / "ledger.jsonl",
        artifact_root=store.root,
        run_id="posthoc-test",
        charter_sha256=charter.sha256,
        metadata={"evaluator_mode": "posthoc-retained-completion-replay"},
        clock=lambda: NOW,
    )
    allowlist = values["allowlist"]

    class LocallyAuthorizedReplayEvaluator(ReplayFilesystemShadowEvaluator):
        def evaluate(self, request, candidate_path):
            allowlist.chmod(0o600)
            allowlist.write_text(request_sha256(request) + "\n")
            allowlist.chmod(0o400)
            return super().evaluate(request, candidate_path)

    evaluator = LocallyAuthorizedReplayEvaluator(
        (sys.executable, "-m", "filiolae.paired_eval_replay_worker"),
        request_root=tmp_path / "requests",
        terminal_root=tmp_path / "terminal",
        source_path=values["source"],
        evaluator_bundle=values["bundle"],
        suite_path=values["suite"],
        config_path=values["config"],
        source_manifest_path=values["source_manifest"],
        private_key_path=values["private_key"],
        public_key_path=values["public_key"],
        allowed_request_path=allowlist,
        replay_path=values["replay"],
        timeout_seconds=30,
    )
    builder = PrimeRLEvidenceBuilder(
        run,
        ledger,
        store,
        shadow_evaluator=evaluator,
        candidate_eval_policy=policy,
        candidate_eval_assets={
            "candidate_evaluator_bundle": values["bundle"],
            "candidate_eval_suite": values["suite"],
            "candidate_eval_config": values["config"],
            "source_policy_manifest": values["source_manifest"],
        },
    )
    request = builder.request_for_step(2, pending)
    freezer = FreezeController(run / "control" / "filiolae" / "freeze.json", clock=lambda: NOW)
    gate = PromotionGate(
        ledger,
        charter,
        freezer,
        candidate_eval_public_key=load_public_key(values["public_key"]),
    )
    decision = gate.authorize(request, current_policy_version=1, pending_weights_path=pending)
    assert not decision.allowed and "below the Charter threshold" in decision.reason
    assert freezer.state().frozen
    assert [record.event for record in ledger.records()][-2:] == ["tripwire.fired", "gate.denied"]
    report = audit_governance(
        ledger,
        charter,
        verify_artifacts=True,
        candidate_eval_public_key=load_public_key(values["public_key"]),
    )
    assert report.ok, report.summary()
