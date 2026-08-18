#!/usr/bin/env python3
"""Controller-side acceptance harness for the privileged separate-UID CPU rehearsal."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from pathlib import Path

from filiolae.anchor import load_public_key, public_key_id
from filiolae.artifacts import digest_path
from filiolae.canonical import canonical_json
from filiolae.paired_eval import (
    FilesystemShadowEvaluator,
    PairedEvalProtocolError,
    evaluator_bundle_body,
    request_sha256,
)
from filiolae.shadow_eval import CandidateEvalPolicy, CandidateEvalRequest


def _write(path: Path, value: object, mode: int = 0o640) -> Path:
    path.write_bytes(canonical_json(value) + b"\n")
    path.chmod(mode)
    return path


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--allowed-request-file", required=True, type=Path)
    parser.add_argument("--evaluator-user", required=True)
    parser.add_argument("--evaluator-python", required=True, type=Path)
    parser.add_argument("--shared-group", required=True)
    args = parser.parse_args()
    work = args.work
    source = work / "source"
    candidate = work / "candidate"
    for path, model in ((source, b"source"), (candidate, b"candidate")):
        path.mkdir(mode=0o750)
        (path / "STABLE").write_text("ready\n")
        (path / "model.bin").write_bytes(model)
        for child in path.iterdir():
            child.chmod(0o640)
    source_kind, source_sha, source_size = digest_path(source)
    _, candidate_sha, _ = digest_path(candidate)
    cases = [
        {
            "answer": prompt[::-1],
            "case_id": f"separate-uid-{index:02d}",
            "prompt": prompt,
            "schema": "filiolae.reverse-text-eval-case.v1",
        }
        for index, prompt in enumerate(("Alpha 17.", "Bravo 29?", "Case (31)!", 'Delta "43".'))
    ]
    suite = work / "suite.jsonl"
    suite.write_bytes(b"".join(canonical_json(case) + b"\n" for case in cases))
    suite.chmod(0o640)
    source_manifest = _write(
        work / "source-manifest.json",
        {
            "schema": "filiolae.source-policy-manifest.v1",
            "source_policy_version": 0,
            "source_weights": {
                "artifact_kind": source_kind,
                "sha256": source_sha,
                "size": source_size,
            },
        },
    )
    config = _write(
        work / "config.json",
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
                "system": "Reverse the text character-by-character. Put your answer in <reversed_text> tags.",
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
                "sha256": _sha(suite),
            },
        },
    )
    bundle = _write(work / "evaluator-bundle.json", evaluator_bundle_body())
    complete = [
        {"case_id": case["case_id"], "completion": f"<reversed_text>{case['answer']}</reversed_text>"}
        for case in cases
    ]
    fixture = _write(
        work / "fixture.json",
        {"candidate": complete, "schema": "filiolae.paired-eval-cpu-fixture.v1", "source": complete},
    )
    public = load_public_key(args.public_key)
    policy = CandidateEvalPolicy(
        evaluator_sha256=_sha(bundle),
        suite_sha256=_sha(suite),
        config_sha256=_sha(config),
        source_policy_sha256=_sha(source_manifest),
        evaluator_signer_key_id=public_key_id(public),
        minimum_quality_bps=9000,
        maximum_regression_bps=0,
        maximum_receipt_age_seconds=300,
    )
    request = CandidateEvalRequest(
        run_id="priority6-stage1-separate-uid",
        attempt_id="happy-lost-response",
        step=1,
        source_policy_version=0,
        candidate_sha256=candidate_sha,
        evaluated_ledger_seq=4,
        evaluated_ledger_head_sha256="e" * 64,
        policy=policy,
    )
    prepared_digest = request_sha256(request)
    prepared = work / "prepared-request.sha256"
    prepared.write_text(prepared_digest + "\n")
    prepared.chmod(0o640)
    deadline = time.monotonic() + 30
    while not args.allowed_request_file.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    if not args.allowed_request_file.exists():
        raise RuntimeError("evaluator operator did not provision the request allowlist")
    command = (
        "sudo",
        "-n",
        "-u",
        args.evaluator_user,
        "-g",
        args.shared_group,
        "--",
        str(args.evaluator_python),
        "-m",
        "filiolae.paired_eval_worker",
    )
    request_root = work / "requests"
    request_root.mkdir(mode=0o2750)
    terminal_root = work / "terminal"
    adapter = FilesystemShadowEvaluator(
        command,
        request_root=request_root,
        terminal_root=terminal_root,
        source_path=source,
        evaluator_bundle=bundle,
        suite_path=suite,
        config_path=config,
        source_manifest_path=source_manifest,
        private_key_path=args.private_key,
        public_key_path=args.public_key,
        allowed_request_path=args.allowed_request_file,
        fixture_path=fixture,
        timeout_seconds=30,
        simulation="lost-response",
    )
    try:
        args.private_key.read_bytes()
    except PermissionError:
        private_key_unreadable = True
    else:
        private_key_unreadable = False
    if not private_key_unreadable:
        raise RuntimeError("controller unexpectedly read evaluator private key")
    receipt = adapter.evaluate(request, candidate)
    digest = request_sha256(request)
    terminal = terminal_root / digest[:2] / digest
    evidence = json.loads((terminal / "evidence.json").read_text())["body"]
    if evidence["evaluator_uid"] == os.getuid() or evidence["evaluator_pid"] == os.getpid():
        raise RuntimeError("evaluator did not run under a distinct process and UID")
    if (
        evidence["request_allowlist_owner_uid"] != evidence["evaluator_uid"]
        or evidence["request_allowlist_mode"] != "0400"
    ):
        raise RuntimeError("signed evidence does not prove an evaluator-owned request allowlist")
    if os.access(terminal / "evidence.json", os.W_OK):
        raise RuntimeError("controller unexpectedly has terminal-result write authority")
    crash_request = CandidateEvalRequest(**{**request.__dict__, "attempt_id": "crash-before-terminal"})
    crash = FilesystemShadowEvaluator(
        command,
        request_root=request_root,
        terminal_root=terminal_root,
        source_path=source,
        evaluator_bundle=bundle,
        suite_path=suite,
        config_path=config,
        source_manifest_path=source_manifest,
        private_key_path=args.private_key,
        public_key_path=args.public_key,
        allowed_request_path=args.allowed_request_file,
        fixture_path=fixture,
        timeout_seconds=30,
        simulation="crash-before-terminal",
    )
    try:
        crash.evaluate(crash_request, candidate)
    except PairedEvalProtocolError:
        pass
    else:
        raise RuntimeError("crash-before-terminal unexpectedly produced success")
    summary = {
        "controller_uid": os.getuid(),
        "evaluator_uid": evidence["evaluator_uid"],
        "lost_response_recovered": receipt.body["status"] == "completed",
        "private_key_unreadable_to_controller": private_key_unreadable,
        "request_allowlist_mode": evidence["request_allowlist_mode"],
        "request_allowlist_owner_uid": evidence["request_allowlist_owner_uid"],
        "request_sha256": digest,
        "schema": "filiolae.priority6-stage1-separate-uid-rehearsal.v1",
        "terminal_unwritable_by_controller": not os.access(terminal / "evidence.json", os.W_OK),
    }
    (work / "separate-uid-summary.json").write_bytes(canonical_json(summary) + b"\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
