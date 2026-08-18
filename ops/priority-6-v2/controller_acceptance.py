#!/usr/bin/env python3
"""Controller-side bounded distinct-UID Priority 6 v2 fixture acceptance."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import pwd
import shutil
import time
from pathlib import Path

from filiolae.anchor import load_public_key, public_key_id
from filiolae.artifacts import digest_path
from filiolae.audit import audit_governance
from filiolae.canonical import canonical_json
from filiolae.charter import Charter
from filiolae.external_eval import ExternalTerminalShadowEvaluator
from filiolae.freeze import FreezeController
from filiolae.gate import PromotionGate
from filiolae.ledger import Ledger
from filiolae.paired_eval import evaluator_bundle_body, load_request, request_sha256
from filiolae.prime_rl import PrimeRLPromotionBarrier
from filiolae.prime_rl_entrypoint import PrimeRLEvidenceBuilder
from filiolae.shadow_eval import CandidateEvalPolicy
from filiolae.store import ArtifactStore
from filiolae.update_control import WeightUpdateController


def _write_json(path: Path, value: object, *, mode: int = 0o640) -> Path:
    path.write_bytes(canonical_json(value) + b"\n")
    path.chmod(mode)
    return path


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
    path.chmod(0o640)
    return Charter.load(path)


def _prepare_inputs(work: Path, public_key_path: Path) -> tuple[dict[str, Path], CandidateEvalPolicy]:
    inputs = work / "inputs"
    inputs.mkdir(mode=0o2750)
    source = inputs / "source"
    source.mkdir(mode=0o750)
    (source / "STABLE").write_text("ready\n")
    (source / "model.bin").write_bytes(b"source-fixture")
    for child in source.iterdir():
        child.chmod(0o640)
    source_kind, source_sha256, source_size = digest_path(source)

    cases = [
        {
            "answer": prompt[::-1],
            "case_id": f"p6-v2-{index:02d}",
            "prompt": prompt,
            "schema": "filiolae.reverse-text-eval-case.v1",
        }
        for index, prompt in enumerate(("Alpha 17.", "Bravo 29?", "Case (31)!", 'Delta "43".'))
    ]
    suite = inputs / "suite.jsonl"
    suite.write_bytes(b"".join(canonical_json(case) + b"\n" for case in cases))
    suite.chmod(0o640)
    source_manifest = _write_json(
        inputs / "source-manifest.json",
        {
            "schema": "filiolae.source-policy-manifest.v1",
            "source_policy_version": 0,
            "source_weights": {
                "artifact_kind": source_kind,
                "sha256": source_sha256,
                "size": source_size,
            },
        },
    )
    config = _write_json(
        inputs / "config.json",
        {
            "charter_thresholds": {
                "maximum_receipt_age_seconds": 300,
                "maximum_regression_bps": 0,
                "minimum_quality_bps": 9000,
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
                "renderer": "cpu-fixture",
                "system": (
                    "Reverse the text character-by-character. Put your answer in <reversed_text> tags."
                ),
            },
            "schema": "filiolae.reverse-text-paired-eval-config.v1",
            "scoring": {
                "diagnostic": "mean_sequence_matcher_ratio_bps",
                "incomplete_case_policy": "error_no_scores",
                "primary": "exact_match_rate_bps",
                "primary_formula": f"floor(10000 * exact_matches / {len(cases)})",
            },
            "suite": {
                "case_count": len(cases),
                "order": "case_id_ascii_ascending",
                "sha256": _sha256(suite),
            },
        },
    )
    bundle = _write_json(inputs / "evaluator-bundle.json", evaluator_bundle_body())
    complete = [
        {"case_id": case["case_id"], "completion": f"<reversed_text>{case['answer']}</reversed_text>"}
        for case in cases
    ]
    fixture = _write_json(
        inputs / "fixture.json",
        {
            "candidate": complete,
            "schema": "filiolae.paired-eval-cpu-fixture.v1",
            "source": complete,
        },
    )
    public_key = load_public_key(public_key_path)
    policy = CandidateEvalPolicy(
        evaluator_sha256=_sha256(bundle),
        suite_sha256=_sha256(suite),
        config_sha256=_sha256(config),
        source_policy_sha256=_sha256(source_manifest),
        evaluator_signer_key_id=public_key_id(public_key),
        minimum_quality_bps=9000,
        maximum_regression_bps=0,
        maximum_receipt_age_seconds=300,
    )
    return {
        "bundle": bundle,
        "config": config,
        "fixture": fixture,
        "source": source,
        "source_manifest": source_manifest,
        "suite": suite,
    }, policy


def _copy_evidence(
    package: Path,
    *,
    work: Path,
    output: Path,
    charter_path: Path,
    contract: Path,
    public_key: Path,
    request_path: Path,
) -> None:
    package.mkdir(mode=0o750)
    shutil.copy2(charter_path, package / "charter.yaml")
    shutil.copy2(contract, package / "acceptance-contract-v1.json")
    shutil.copy2(public_key, package / "evaluator-public.pem")
    shutil.copy2(request_path, package / "request.json")
    shutil.copy2(work / "evaluator-proof" / "service.json", package / "EVALUATOR-SERVICE.json")
    shutil.copytree(work / "inputs", package / "inputs")
    shutil.copytree(work / "terminal", package / "terminal")
    shutil.copytree(output / "control" / "filiolae", package / "governance")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--evaluator-user", required=True)
    args = parser.parse_args()
    work = args.work
    inputs, policy = _prepare_inputs(work, args.public_key)
    contract_digest = _sha256(args.contract)
    expected_contract = "4bbb86cd2e0d3312a0f1794a57b53970a1dd67e2bd6e4a0604b28cb2af2d3c6c"
    if contract_digest != expected_contract:
        raise RuntimeError("Priority 6 v2 acceptance contract digest changed")

    output = work / "run"
    (output / "control").mkdir(parents=True)
    (output / "control" / "orch.toml").write_text("max_steps = 1\n")
    pending = output / "broadcasts" / "step_1"
    pending.mkdir(parents=True)
    (pending / "STABLE").write_text("ready\n")
    (pending / "model.bin").write_bytes(b"candidate-fixture")
    for child in pending.iterdir():
        child.chmod(0o640)
    traces = output / "rollouts" / "step_1" / "train" / "effective" / "traces.jsonl"
    traces.parent.mkdir(parents=True)
    traces.write_text('{"source":"priority6-v2-distinct-uid-cpu-fixture"}\n')
    charter_path = work / "charter.yaml"
    charter = _charter(charter_path, policy)
    control = output / "control" / "filiolae"
    store = ArtifactStore(control / "artifacts")
    ledger = Ledger.create(
        control / "ledger.jsonl",
        artifact_root=store.root,
        run_id="priority6-v2-distinct-uid-fixture",
        charter_sha256=charter.sha256,
        metadata={
            "candidate_quality_evaluated": False,
            "fixture_only": True,
            "separate_credential_required": True,
        },
    )
    adapter = ExternalTerminalShadowEvaluator(
        request_root=work / "requests",
        terminal_root=work / "terminal",
        public_key_path=args.public_key,
        suite_path=inputs["suite"],
        timeout_seconds=60,
        poll_interval_seconds=0.02,
    )
    builder = PrimeRLEvidenceBuilder(
        output,
        ledger,
        store,
        shadow_evaluator=adapter,
        candidate_eval_policy=policy,
        candidate_eval_assets={
            "candidate_evaluator_bundle": inputs["bundle"],
            "candidate_eval_suite": inputs["suite"],
            "candidate_eval_config": inputs["config"],
            "source_policy_manifest": inputs["source_manifest"],
        },
    )
    freezer = FreezeController(control / "freeze.json")
    public_key = load_public_key(args.public_key)
    gate = PromotionGate(
        ledger,
        charter,
        freezer,
        candidate_eval_public_key=public_key,
    )
    barrier = PrimeRLPromotionBarrier(gate, builder.request_for_step)
    loaded: list[dict[str, object]] = []

    async def disposable_load(path: Path) -> None:
        kind, digest, size = digest_path(path)
        loaded.append({"artifact_kind": kind, "sha256": digest, "size": size})

    asyncio.run(
        WeightUpdateController(barrier, authorization_timeout=90, outcome_timeout=30).apply(
            step=1,
            current_policy_version=0,
            trainer_weights_path=pending,
            update_weights=disposable_load,
        )
    )
    if len(loaded) != 1 or freezer.state().frozen:
        raise RuntimeError("fixture did not complete exactly one disposable shadow load")
    records = ledger.records()
    events = [record.event for record in records]
    if events.count("gate.approved") != 1 or events.count("policy.promoted") != 1:
        raise RuntimeError("fixture did not record exactly one approval and promotion")
    request_path = next((work / "requests").glob("*.json"))
    request = load_request(request_path)
    digest = request_sha256(request)
    terminal = work / "terminal" / digest[:2] / digest
    evidence = json.loads((terminal / "evidence.json").read_text())["body"]
    expected_evaluator_uid = pwd.getpwnam(args.evaluator_user).pw_uid
    if (
        evidence["evaluator_uid"] != expected_evaluator_uid
        or evidence["evaluator_uid"] == os.getuid()
        or evidence["evaluator_pid"] == os.getpid()
    ):
        raise RuntimeError("external evaluator did not use the expected distinct UID and process")
    if evidence["request_allowlist_owner_uid"] != evidence["evaluator_uid"]:
        raise RuntimeError("request allowlist was not evaluator-owned")
    try:
        args.private_key.read_bytes()
    except PermissionError:
        private_key_unreadable = True
    else:
        private_key_unreadable = False
    if not private_key_unreadable:
        raise RuntimeError("controller unexpectedly read evaluator private key")
    if os.access(terminal / "evidence.json", os.W_OK):
        raise RuntimeError("controller unexpectedly has terminal write authority")
    service_proof = work / "evaluator-proof" / "service.json"
    deadline = time.monotonic() + 10
    while not service_proof.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    if not service_proof.exists():
        raise RuntimeError("evaluator service proof was not committed")
    service = json.loads(service_proof.read_text())
    if service.get("evaluator_uid") != evidence["evaluator_uid"]:
        raise RuntimeError("evaluator service proof UID differs from signed evidence")

    report = audit_governance(
        ledger,
        charter,
        verify_artifacts=True,
        candidate_eval_public_key=public_key,
    )
    if not report.ok or report.promotion_count != 1:
        raise RuntimeError(report.summary())
    candidate_record = next(record for record in records if record.event == "candidate_eval.result")
    terminal_artifact = next(
        artifact for artifact in candidate_record.artifacts if artifact.name == "candidate_eval_terminal"
    )
    summary = {
        "audit": report.summary(),
        "bounded_claim": (
            "distinct-UID CPU fixture of external request/terminal, complete-evidence Gate, "
            "one disposable shadow promotion, and offline audit"
        ),
        "candidate_eval_terminal_sha256": terminal_artifact.sha256,
        "contract_sha256": contract_digest,
        "controller_uid": os.getuid(),
        "evaluator_uid": evidence["evaluator_uid"],
        "events": events,
        "exact_approvals": events.count("gate.approved"),
        "exact_promotions": events.count("policy.promoted"),
        "loaded": loaded,
        "non_claims": [
            "CPU completions are fixtures, not model inference or quality evidence",
            "not candidate-development or final-acceptance execution",
            "not production isolation, deployment, or publication authority",
        ],
        "private_key_unreadable_to_controller": private_key_unreadable,
        "request_allowlist_mode": evidence["request_allowlist_mode"],
        "request_allowlist_owner_uid": evidence["request_allowlist_owner_uid"],
        "request_sha256": digest,
        "schema": "filiolae.priority6-v2-distinct-uid-fixture-acceptance.v1",
        "separate_os_credential": evidence["evaluator_uid"] != os.getuid(),
        "terminal_unwritable_by_controller": not os.access(terminal / "evidence.json", os.W_OK),
    }
    package = work / "acceptance-package"
    _copy_evidence(
        package,
        work=work,
        output=output,
        charter_path=charter_path,
        contract=args.contract,
        public_key=args.public_key,
        request_path=request_path,
    )
    _write_json(package / "SUMMARY.json", summary, mode=0o644)
    (package / "AUDIT.txt").write_text(report.summary() + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
