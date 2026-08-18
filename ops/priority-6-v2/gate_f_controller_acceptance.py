#!/usr/bin/env python3
"""Controller-side distinct-UID real-model acceptance for Priority 6 v2 Gate F."""

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
from filiolae.paired_eval import load_request, request_sha256
from filiolae.prime_rl import PrimeRLPromotionBarrier
from filiolae.prime_rl_entrypoint import PrimeRLEvidenceBuilder
from filiolae.shadow_eval import CandidateEvalPolicy
from filiolae.store import ArtifactStore
from filiolae.update_control import WeightUpdateController

EXPECTED_CONTRACT_SHA256 = "4bbb86cd2e0d3312a0f1794a57b53970a1dd67e2bd6e4a0604b28cb2af2d3c6c"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: object, *, mode: int = 0o640) -> Path:
    path.write_bytes(canonical_json(value) + b"\n")
    path.chmod(mode)
    return path


def charter(path: Path, policy: CandidateEvalPolicy) -> Charter:
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


def copy_evidence(
    package: Path,
    *,
    work: Path,
    output: Path,
    charter_path: Path,
    contract: Path,
    public_key: Path,
    request_path: Path,
    evaluator_bundle: Path,
    suite: Path,
    config: Path,
    source_manifest: Path,
) -> None:
    package.mkdir(mode=0o750)
    shutil.copy2(charter_path, package / "charter.yaml")
    shutil.copy2(contract, package / "acceptance-contract-v1.json")
    shutil.copy2(public_key, package / "evaluator-public.pem")
    shutil.copy2(request_path, package / "request.json")
    shutil.copy2(work / "evaluator-proof" / "service.json", package / "EVALUATOR-SERVICE.json")
    shutil.copy2(work / "evaluator-proof" / "model-outputs.json", package / "MODEL-OUTPUTS.json")
    inputs = package / "inputs"
    inputs.mkdir(mode=0o750)
    shutil.copy2(evaluator_bundle, inputs / "evaluator-bundle.json")
    shutil.copy2(suite, inputs / "final.jsonl")
    shutil.copy2(config, inputs / "config.json")
    shutil.copy2(source_manifest, inputs / "source-manifest.json")
    shutil.copytree(work / "terminal", package / "terminal")
    shutil.copytree(output / "control" / "filiolae", package / "governance")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--evaluator-user", required=True)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--suite", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--source-manifest", required=True, type=Path)
    parser.add_argument("--evaluator-bundle", required=True, type=Path)
    parser.add_argument("--expected-candidate-sha256", required=True)
    args = parser.parse_args()
    work = args.work
    contract_digest = sha256(args.contract)
    if contract_digest != EXPECTED_CONTRACT_SHA256:
        raise RuntimeError("Priority 6 v2 acceptance contract digest changed")
    source_manifest = json.loads(args.source_manifest.read_text())
    source_policy_version = source_manifest["source_policy_version"]
    _, candidate_sha256, _ = digest_path(args.candidate)
    if candidate_sha256 != args.expected_candidate_sha256:
        raise RuntimeError("frozen candidate digest changed before Gate F")
    source_kind, source_sha256, source_size = digest_path(args.source)
    if source_manifest["source_weights"] != {
        "artifact_kind": source_kind,
        "sha256": source_sha256,
        "size": source_size,
    }:
        raise RuntimeError("source tree contradicts source-policy manifest")
    public_key = load_public_key(args.public_key)
    policy = CandidateEvalPolicy(
        evaluator_sha256=sha256(args.evaluator_bundle),
        suite_sha256=sha256(args.suite),
        config_sha256=sha256(args.config),
        source_policy_sha256=sha256(args.source_manifest),
        evaluator_signer_key_id=public_key_id(public_key),
        minimum_quality_bps=8000,
        maximum_regression_bps=79,
        maximum_receipt_age_seconds=900,
    )
    output = work / "run"
    control_dir = output / "control"
    control_dir.mkdir(exist_ok=True)
    (control_dir / "orch.toml").write_text("max_steps = 1\n")
    pending = output / "broadcasts" / "step_1"
    if digest_path(pending)[1] != candidate_sha256:
        raise RuntimeError("pending candidate differs from frozen candidate")
    traces = output / "rollouts" / "step_1" / "train" / "effective" / "traces.jsonl"
    traces.parent.mkdir(parents=True)
    traces.write_text('{"source":"priority6-v2-gate-f-real-model-acceptance"}\n')
    charter_path = work / "charter.yaml"
    loaded_charter = charter(charter_path, policy)
    governance = control_dir / "filiolae"
    store = ArtifactStore(governance / "artifacts")
    ledger = Ledger.create(
        governance / "ledger.jsonl",
        artifact_root=store.root,
        run_id="priority6-v2-gate-f-final-acceptance",
        charter_sha256=loaded_charter.sha256,
        metadata={
            "candidate_development_forbidden": True,
            "candidate_frozen_before_final_release": True,
            "final_acceptance_real_model_inference": True,
            "separate_credential_required": True,
        },
    )
    adapter = ExternalTerminalShadowEvaluator(
        request_root=work / "requests",
        terminal_root=work / "terminal",
        public_key_path=args.public_key,
        suite_path=args.suite,
        timeout_seconds=600,
        poll_interval_seconds=0.02,
    )
    builder = PrimeRLEvidenceBuilder(
        output,
        ledger,
        store,
        shadow_evaluator=adapter,
        candidate_eval_policy=policy,
        candidate_eval_assets={
            "candidate_evaluator_bundle": args.evaluator_bundle,
            "candidate_eval_suite": args.suite,
            "candidate_eval_config": args.config,
            "source_policy_manifest": args.source_manifest,
        },
    )
    freezer = FreezeController(governance / "freeze.json")
    gate = PromotionGate(
        ledger,
        loaded_charter,
        freezer,
        candidate_eval_public_key=public_key,
    )
    barrier = PrimeRLPromotionBarrier(gate, builder.request_for_step)
    loaded: list[dict[str, object]] = []

    async def disposable_load(path: Path) -> None:
        kind, digest, size = digest_path(path)
        loaded.append({"artifact_kind": kind, "sha256": digest, "size": size})

    asyncio.run(
        WeightUpdateController(barrier, authorization_timeout=600, outcome_timeout=60).apply(
            step=1,
            current_policy_version=source_policy_version,
            trainer_weights_path=pending,
            update_weights=disposable_load,
        )
    )
    if len(loaded) != 1 or freezer.state().frozen:
        raise RuntimeError("Gate F did not complete exactly one disposable shadow load")
    records = ledger.records()
    events = [record.event for record in records]
    if events.count("gate.approved") != 1 or events.count("policy.promoted") != 1:
        raise RuntimeError("Gate F did not record exactly one approval and promotion")
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
        loaded_charter,
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
            "fresh-GPU distinct-UID final-suite real-model paired evaluation, complete signed "
            "terminal evidence, one disposable shadow promotion, and offline audit"
        ),
        "candidate_eval_terminal_sha256": terminal_artifact.sha256,
        "candidate_quality_bps": service["candidate_quality_bps"],
        "candidate_tree_sha256": candidate_sha256,
        "contract_sha256": contract_digest,
        "controller_uid": os.getuid(),
        "evaluator_uid": evidence["evaluator_uid"],
        "events": events,
        "exact_approvals": events.count("gate.approved"),
        "exact_promotions": events.count("policy.promoted"),
        "final_suite_sha256": policy.suite_sha256,
        "loaded": loaded,
        "model_outputs_sha256": service["model_outputs_sha256"],
        "private_key_unreadable_to_controller": private_key_unreadable,
        "request_allowlist_mode": evidence["request_allowlist_mode"],
        "request_allowlist_owner_uid": evidence["request_allowlist_owner_uid"],
        "request_sha256": digest,
        "schema": "filiolae.priority6-v2-gate-f-final-acceptance.v1",
        "separate_os_credential": evidence["evaluator_uid"] != os.getuid(),
        "source_quality_bps": service["source_quality_bps"],
        "source_tree_sha256": source_sha256,
        "terminal_unwritable_by_controller": not os.access(terminal / "evidence.json", os.W_OK),
    }
    package = work / "acceptance-package"
    copy_evidence(
        package,
        work=work,
        output=output,
        charter_path=charter_path,
        contract=args.contract,
        public_key=args.public_key,
        request_path=request_path,
        evaluator_bundle=args.evaluator_bundle,
        suite=args.suite,
        config=args.config,
        source_manifest=args.source_manifest,
    )
    write_json(package / "SUMMARY.json", summary, mode=0o644)
    (package / "AUDIT.txt").write_text(report.summary() + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
