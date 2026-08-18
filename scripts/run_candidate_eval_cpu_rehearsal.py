#!/usr/bin/env python3
"""Run the bounded same-UID/process-separated Priority 6 CPU protocol rehearsal."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

from filiolae.anchor import generate_keypair, load_public_key, public_key_id
from filiolae.canonical import canonical_json
from filiolae.paired_eval import FilesystemShadowEvaluator, request_sha256
from filiolae.shadow_eval import (
    CandidateEvalPolicy,
    CandidateEvalRequest,
    verify_candidate_eval_receipt,
)

SOURCE_SHA256 = "c047cbef4cca5dc09de95acd9f4a2ea884e8abd4f1e47dd34c2608165307c0c7"
CANDIDATE_SHA256 = "4bd8ca5cba086ff538f00f56fbd4ad9f241e05bc60e5307f976c63a81579473d"
EVALUATED_LEDGER_HEAD = "8c5c7cd5df7d280a9f7b6be271f90e6ebb11d41366c26150cb8c3548c4a78d22"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        raise SystemExit("output already exists")
    output.mkdir(parents=True, mode=0o700)
    repo = Path(__file__).parents[1]
    assets = repo / "examples" / "candidate-eval"
    suite = assets / "reverse-text-held-out-v1.jsonl"
    config = assets / "reverse-text-paired-config-v1.json"
    source_manifest = assets / "r18-step1-source-manifest-v1.json"
    evaluator_bundle = assets / "cpu-evaluator-bundle-v1.json"
    private_key = output / "evaluator-private.pem"
    public_key = output / "evaluator-public.pem"
    generate_keypair(private_key, public_key)
    cases = [json.loads(line) for line in suite.read_text().splitlines()]
    completions = [
        {
            "case_id": case["case_id"],
            "completion": f"<reversed_text>{case['answer']}</reversed_text>",
        }
        for case in cases
    ]
    fixture = output / "cpu-fixture.json"
    fixture.write_bytes(
        canonical_json(
            {
                "candidate": completions,
                "schema": "filiolae.paired-eval-cpu-fixture.v1",
                "source": completions,
            }
        )
        + b"\n"
    )
    policy = CandidateEvalPolicy(
        evaluator_sha256=_sha256(evaluator_bundle),
        suite_sha256=_sha256(suite),
        config_sha256=_sha256(config),
        source_policy_sha256=_sha256(source_manifest),
        evaluator_signer_key_id=public_key_id(load_public_key(public_key)),
        minimum_quality_bps=8000,
        maximum_regression_bps=79,
        maximum_receipt_age_seconds=1800,
    )
    request = CandidateEvalRequest(
        run_id="priority6-stage1-r1",
        attempt_id="r18-step2-cpu-protocol-rehearsal",
        step=2,
        source_policy_version=1,
        candidate_sha256=CANDIDATE_SHA256,
        evaluated_ledger_seq=9,
        evaluated_ledger_head_sha256=EVALUATED_LEDGER_HEAD,
        policy=policy,
    )
    allowed_request = output / "allowed-request.sha256"
    allowed_request.write_text(request_sha256(request) + "\n")
    allowed_request.chmod(0o400)
    adapter = FilesystemShadowEvaluator(
        (sys.executable, "-m", "filiolae.paired_eval_worker"),
        request_root=output / "requests",
        terminal_root=output / "terminal",
        source_path=args.source,
        evaluator_bundle=evaluator_bundle,
        suite_path=suite,
        config_path=config,
        source_manifest_path=source_manifest,
        private_key_path=private_key,
        public_key_path=public_key,
        allowed_request_path=allowed_request,
        fixture_path=fixture,
        timeout_seconds=300,
        simulation="lost-response",
    )
    started = datetime.now(UTC)
    receipt = adapter.evaluate(request, args.candidate)
    finished = datetime.now(UTC)
    metrics = verify_candidate_eval_receipt(receipt, request, load_public_key(public_key), now=finished)
    digest = request_sha256(request)
    terminal = output / "terminal" / digest[:2] / digest
    evidence = json.loads((terminal / "evidence.json").read_text())["body"]
    summary = {
        "bounded_claim": (
            "process-separated CPU protocol rehearsal only; fixture scores are not model quality"
        ),
        "candidate_sha256": request.candidate_sha256,
        "case_count": len(cases),
        "config_sha256": policy.config_sha256,
        "controller_pid": os.getpid(),
        "controller_uid": os.getuid(),
        "evaluator_bundle_sha256": policy.evaluator_sha256,
        "evaluator_pid": evidence["evaluator_pid"],
        "evaluator_uid": evidence["evaluator_uid"],
        "finished_at": finished.isoformat().replace("+00:00", "Z"),
        "lost_response_recovered": True,
        "metrics": metrics,
        "request_allowlist_mode": evidence["request_allowlist_mode"],
        "request_allowlist_owner_uid": evidence["request_allowlist_owner_uid"],
        "non_claims": [
            "CPU outputs are deterministic fixtures, not inference",
            "same-UID process rehearsal is not separate-credential acceptance",
            "no paid compute or network service",
            "no promotion authority or original-r18 quality claim",
        ],
        "receipt_sha256": _sha256(terminal / "receipt.json"),
        "request_sha256": digest,
        "run_id": request.run_id,
        "schema": "filiolae.priority6-stage1-cpu-rehearsal.v1",
        "separate_os_credential": evidence["evaluator_uid"] != os.getuid(),
        "separate_process": evidence["evaluator_pid"] != os.getpid(),
        "signer_key_id": policy.evaluator_signer_key_id,
        "source_manifest_sha256": policy.source_policy_sha256,
        "source_sha256": SOURCE_SHA256,
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "suite_sha256": policy.suite_sha256,
    }
    (output / "controller-summary.json").write_bytes(canonical_json(summary) + b"\n")
    for path in (evaluator_bundle, suite, config, source_manifest):
        shutil.copy2(path, output / path.name)
    private_key.unlink()
    files = sorted(path for path in output.rglob("*") if path.is_file() and path.name != "SHA256SUMS")
    (output / "SHA256SUMS").write_text(
        "".join(f"{_sha256(path)}  {path.relative_to(output).as_posix()}\n" for path in files)
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
