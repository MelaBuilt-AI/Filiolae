from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from filiolae.anchor import generate_keypair, load_public_key, public_key_id
from filiolae.artifacts import digest_path
from filiolae.canonical import canonical_json
from filiolae.external_eval import ExternalTerminalShadowEvaluator
from filiolae.paired_eval import (
    FilesystemShadowEvaluator,
    PairedEvalProtocolError,
    evaluator_bundle_body,
    load_terminal_receipt,
    request_bytes,
    request_sha256,
    run_cpu_fixture_evaluator,
    run_model_outputs_evaluator,
    verify_terminal_evidence,
)
from filiolae.shadow_eval import (
    CandidateEvalError,
    CandidateEvalPolicy,
    CandidateEvalRequest,
    verify_candidate_eval_receipt,
)

NOW = datetime(2026, 8, 13, 15, 0, tzinfo=UTC)


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(value) + b"\n")
    return path


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _setup(tmp_path: Path):
    source = tmp_path / "source"
    candidate = tmp_path / "candidate"
    for path, model in ((source, b"source"), (candidate, b"candidate")):
        path.mkdir()
        (path / "STABLE").write_text("ready\n")
        (path / "model.bin").write_bytes(model)
    source_kind, source_sha, source_size = digest_path(source)
    _, candidate_sha, _ = digest_path(candidate)
    suite_cases = [
        {
            "answer": prompt[::-1],
            "case_id": f"case-{index:02d}",
            "prompt": prompt,
            "schema": "filiolae.reverse-text-eval-case.v1",
        }
        for index, prompt in enumerate(("Alpha 17.", "Bravo 29?", "Case (31)!", 'Delta "43".'))
    ]
    suite = tmp_path / "suite.jsonl"
    suite.write_bytes(b"".join(canonical_json(case) + b"\n" for case in suite_cases))
    evaluator_bundle = _write(tmp_path / "evaluator-bundle.json", evaluator_bundle_body())
    source_manifest = _write(
        tmp_path / "source.json",
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
        tmp_path / "config.json",
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
                "primary_formula": f"floor(10000 * exact_matches / {len(suite_cases)})",
            },
            "suite": {
                "case_count": len(suite_cases),
                "order": "case_id_ascii_ascending",
                "sha256": _sha(suite),
            },
        },
    )
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    generate_keypair(private_key, public_key)
    policy = CandidateEvalPolicy(
        evaluator_sha256=_sha(evaluator_bundle),
        suite_sha256=_sha(suite),
        config_sha256=_sha(config),
        source_policy_sha256=_sha(source_manifest),
        evaluator_signer_key_id=public_key_id(load_public_key(public_key)),
        minimum_quality_bps=9000,
        maximum_regression_bps=0,
        maximum_receipt_age_seconds=300,
    )
    request = CandidateEvalRequest(
        run_id="paired-rehearsal",
        attempt_id="attempt-1",
        step=1,
        source_policy_version=0,
        candidate_sha256=candidate_sha,
        evaluated_ledger_seq=4,
        evaluated_ledger_head_sha256="e" * 64,
        policy=policy,
    )
    request_path = tmp_path / "request.json"
    request_path.write_bytes(request_bytes(request))
    allowed_request = tmp_path / "allowed-request.sha256"
    allowed_request.write_text(request_sha256(request) + "\n")
    allowed_request.chmod(0o444)
    complete = [
        {"case_id": case["case_id"], "completion": f"<reversed_text>{case['answer']}</reversed_text>"}
        for case in suite_cases
    ]
    fixture = _write(
        tmp_path / "fixture.json",
        {"candidate": complete, "schema": "filiolae.paired-eval-cpu-fixture.v1", "source": complete},
    )
    return {
        "allowed_request": allowed_request,
        "candidate": candidate,
        "config": config,
        "evaluator_bundle": evaluator_bundle,
        "fixture": fixture,
        "private_key": private_key,
        "public_key": public_key,
        "request": request,
        "request_path": request_path,
        "source": source,
        "source_manifest": source_manifest,
        "suite": suite,
        "suite_cases": suite_cases,
        "terminal": tmp_path / "terminal",
    }


def _run(paths):
    return run_cpu_fixture_evaluator(
        request_path=paths["request_path"],
        source_path=paths["source"],
        candidate_path=paths["candidate"],
        evaluator_bundle=paths["evaluator_bundle"],
        suite_path=paths["suite"],
        config_path=paths["config"],
        source_manifest_path=paths["source_manifest"],
        private_key_path=paths["private_key"],
        allowed_request_path=paths["allowed_request"],
        fixture_path=paths["fixture"],
        terminal_root=paths["terminal"],
        clock=lambda: NOW,
    )


def _adapter(paths, *, simulation=None, timeout=10):
    return FilesystemShadowEvaluator(
        (sys.executable, "-m", "filiolae.paired_eval_worker"),
        request_root=paths["request_path"].parent / "requests",
        terminal_root=paths["terminal"],
        source_path=paths["source"],
        evaluator_bundle=paths["evaluator_bundle"],
        suite_path=paths["suite"],
        config_path=paths["config"],
        source_manifest_path=paths["source_manifest"],
        private_key_path=paths["private_key"],
        public_key_path=paths["public_key"],
        allowed_request_path=paths["allowed_request"],
        fixture_path=paths["fixture"],
        timeout_seconds=timeout,
        simulation=simulation,
    )


def test_cpu_paired_rehearsal_retains_complete_outputs_and_signed_scores(tmp_path: Path) -> None:
    paths = _setup(tmp_path)
    receipt = _run(paths)

    assert receipt.body["candidate_quality_bps"] == 10_000
    assert receipt.body["source_quality_bps"] == 10_000
    assert verify_candidate_eval_receipt(
        receipt, paths["request"], load_public_key(paths["public_key"]), now=NOW
    ) == {"candidate_quality_bps": 10_000, "source_quality_bps": 10_000, "regression_bps": 0}
    terminal = paths["terminal"] / request_sha256(paths["request"])[:2] / request_sha256(paths["request"])
    evidence = json.loads((terminal / "evidence.json").read_text())["body"]
    assert evidence["status"] == "completed"
    assert len(evidence["source_results"]) == len(paths["suite_cases"])
    assert len(evidence["candidate_results"]) == len(paths["suite_cases"])
    assert all(result["exact"] for result in evidence["source_results"])
    assert load_terminal_receipt(paths["terminal"], paths["request"]).to_bytes() == receipt.to_bytes()


def test_lost_response_recovers_byte_identical_terminal_without_reevaluation(tmp_path: Path) -> None:
    paths = _setup(tmp_path)
    adapter = _adapter(paths, simulation="lost-response")

    first = adapter.evaluate(paths["request"], paths["candidate"])
    paths["fixture"].write_text("not the original fixture\n")
    second = adapter.evaluate(paths["request"], paths["candidate"])

    assert first.to_bytes() == second.to_bytes()
    assert first.body["status"] == "completed"
    terminal = paths["terminal"] / request_sha256(paths["request"])[:2] / request_sha256(paths["request"])
    evidence = json.loads((terminal / "evidence.json").read_text())["body"]
    assert evidence["evaluator_pid"] != os.getpid()


@pytest.mark.parametrize("simulation", ["crash-before-terminal", "hang"])
def test_crash_or_timeout_without_terminal_fails_closed(tmp_path: Path, simulation: str) -> None:
    paths = _setup(tmp_path)
    adapter = _adapter(paths, simulation=simulation, timeout=0.1)

    with pytest.raises(PairedEvalProtocolError, match="without a terminal|timed out"):
        adapter.evaluate(paths["request"], paths["candidate"])
    assert load_terminal_receipt(paths["terminal"], paths["request"]) is None


def test_source_substitution_fails_before_a_terminal_result(tmp_path: Path) -> None:
    paths = _setup(tmp_path)
    (paths["source"] / "model.bin").write_bytes(b"substituted source")

    with pytest.raises(PairedEvalProtocolError, match="source weights contradict"):
        _run(paths)
    assert load_terminal_receipt(paths["terminal"], paths["request"]) is None


def test_partial_case_output_commits_signed_error_without_scores(tmp_path: Path) -> None:
    paths = _setup(tmp_path)
    fixture = json.loads(paths["fixture"].read_text())
    fixture["candidate"].pop()
    _write(paths["fixture"], fixture)

    receipt = _run(paths)

    assert receipt.body["status"] == "error"
    assert receipt.body["candidate_quality_bps"] is None
    assert receipt.body["source_quality_bps"] is None
    with pytest.raises(CandidateEvalError, match="reported failure"):
        verify_candidate_eval_receipt(
            receipt, paths["request"], load_public_key(paths["public_key"]), now=NOW
        )


def test_signed_complete_output_evidence_rejects_post_result_tampering(tmp_path: Path) -> None:
    paths = _setup(tmp_path)
    _run(paths)
    digest = request_sha256(paths["request"])
    evidence_path = paths["terminal"] / digest[:2] / digest / "evidence.json"
    envelope = json.loads(evidence_path.read_text())
    envelope["body"]["candidate_results"][0]["completion"] = "tampered after signing"
    evidence_path.write_bytes(canonical_json(envelope) + b"\n")

    with pytest.raises(PairedEvalProtocolError, match="signature is invalid"):
        verify_terminal_evidence(
            paths["terminal"],
            paths["request"],
            load_public_key(paths["public_key"]),
            paths["suite"],
        )


def test_request_must_be_evaluator_owned_and_allowlisted(tmp_path: Path) -> None:
    paths = _setup(tmp_path)
    paths["allowed_request"].chmod(0o600)
    paths["allowed_request"].write_text("0" * 64 + "\n")
    paths["allowed_request"].chmod(0o400)

    with pytest.raises(PairedEvalProtocolError, match="allowlisted"):
        _run(paths)
    assert load_terminal_receipt(paths["terminal"], paths["request"]) is None


def test_external_terminal_adapter_uses_only_request_inbox_and_verified_terminal(
    tmp_path: Path,
) -> None:
    paths = _setup(tmp_path)
    expected = _run(paths)
    request_root = tmp_path / "external-requests"
    adapter = ExternalTerminalShadowEvaluator(
        request_root=request_root,
        terminal_root=paths["terminal"],
        public_key_path=paths["public_key"],
        suite_path=paths["suite"],
        timeout_seconds=1,
        poll_interval_seconds=0.01,
    )

    actual = adapter.evaluate(paths["request"], paths["candidate"])

    digest = request_sha256(paths["request"])
    published = request_root / f"{digest}.json"
    assert published.read_bytes() == request_bytes(paths["request"])
    assert actual.to_bytes() == expected.to_bytes()
    assert adapter.terminal_evidence_path(paths["request"]) == paths["terminal"] / digest[:2] / digest


def test_external_terminal_adapter_publishes_then_fails_closed_without_result(
    tmp_path: Path,
) -> None:
    paths = _setup(tmp_path)
    request_root = tmp_path / "external-requests"
    adapter = ExternalTerminalShadowEvaluator(
        request_root=request_root,
        terminal_root=paths["terminal"],
        public_key_path=paths["public_key"],
        suite_path=paths["suite"],
        timeout_seconds=0.02,
        poll_interval_seconds=0.005,
    )

    with pytest.raises(PairedEvalProtocolError, match="deadline expired"):
        adapter.evaluate(paths["request"], paths["candidate"])

    digest = request_sha256(paths["request"])
    assert (request_root / f"{digest}.json").read_bytes() == request_bytes(paths["request"])
    assert load_terminal_receipt(paths["terminal"], paths["request"]) is None


def test_external_terminal_adapter_rejects_candidate_substitution_before_publication(
    tmp_path: Path,
) -> None:
    paths = _setup(tmp_path)
    (paths["candidate"] / "model.bin").write_bytes(b"substituted candidate")
    request_root = tmp_path / "external-requests"
    adapter = ExternalTerminalShadowEvaluator(
        request_root=request_root,
        terminal_root=paths["terminal"],
        public_key_path=paths["public_key"],
        suite_path=paths["suite"],
        timeout_seconds=1,
        poll_interval_seconds=0.01,
    )

    with pytest.raises(PairedEvalProtocolError, match="candidate bytes contradict"):
        adapter.evaluate(paths["request"], paths["candidate"])
    assert not request_root.exists()


def test_external_terminal_retention_rejects_extra_unbound_files(tmp_path: Path) -> None:
    paths = _setup(tmp_path)
    _run(paths)
    (paths["terminal"] / "unbound.txt").write_text("not request-bound\n")
    adapter = ExternalTerminalShadowEvaluator(
        request_root=tmp_path / "external-requests",
        terminal_root=paths["terminal"],
        public_key_path=paths["public_key"],
        suite_path=paths["suite"],
        timeout_seconds=1,
        poll_interval_seconds=0.01,
    )

    adapter.evaluate(paths["request"], paths["candidate"])
    with pytest.raises(PairedEvalProtocolError, match="exact one-request package"):
        adapter.terminal_evidence_root(paths["request"])


def test_real_model_output_path_accepts_priority6_v2_suite_and_signed_outputs(
    tmp_path: Path,
) -> None:
    paths = _setup(tmp_path)
    cases = []
    for case in paths["suite_cases"]:
        cases.append({**case, "schema": "filiolae.priority6-v2-reversal-case.v1"})
    paths["suite"].write_bytes(b"".join(canonical_json(case) + b"\n" for case in cases))
    config = json.loads(paths["config"].read_text())
    config["suite"]["sha256"] = _sha(paths["suite"])
    _write(paths["config"], config)
    _write(
        paths["evaluator_bundle"],
        {
            "files": {"worker.py": "a" * 64},
            "purpose": "final-acceptance-real-model-paired-inference",
            "runtime": {"python": "3.12"},
            "schema": "filiolae.priority6-v2-model-evaluator-bundle.v1",
        },
    )
    _, candidate_sha, _ = digest_path(paths["candidate"])
    policy = CandidateEvalPolicy(
        evaluator_sha256=_sha(paths["evaluator_bundle"]),
        suite_sha256=_sha(paths["suite"]),
        config_sha256=_sha(paths["config"]),
        source_policy_sha256=_sha(paths["source_manifest"]),
        evaluator_signer_key_id=public_key_id(load_public_key(paths["public_key"])),
        minimum_quality_bps=9000,
        maximum_regression_bps=0,
        maximum_receipt_age_seconds=300,
    )
    request = CandidateEvalRequest(
        run_id="real-model-paired-eval",
        attempt_id="attempt-1",
        step=1,
        source_policy_version=0,
        candidate_sha256=candidate_sha,
        evaluated_ledger_seq=4,
        evaluated_ledger_head_sha256="e" * 64,
        policy=policy,
    )
    paths["request_path"].write_bytes(request_bytes(request))
    paths["allowed_request"].chmod(0o600)
    paths["allowed_request"].write_text(request_sha256(request) + "\n")
    paths["allowed_request"].chmod(0o400)
    complete = [
        {"case_id": case["case_id"], "completion": f"<reversed_text>{case['answer']}</reversed_text>"}
        for case in cases
    ]
    _, source_sha, _ = digest_path(paths["source"])
    outputs = _write(
        tmp_path / "model-outputs.json",
        {
            "bindings": {
                "candidate_sha256": candidate_sha,
                "config_sha256": _sha(paths["config"]),
                "evaluator_sha256": _sha(paths["evaluator_bundle"]),
                "source_policy_sha256": _sha(paths["source_manifest"]),
                "source_sha256": source_sha,
                "suite_sha256": _sha(paths["suite"]),
            },
            "candidate": complete,
            "inference": {"backend": "test-real-model-runner"},
            "schema": "filiolae.paired-eval-model-outputs.v1",
            "source": complete,
        },
    )

    receipt = run_model_outputs_evaluator(
        request_path=paths["request_path"],
        source_path=paths["source"],
        candidate_path=paths["candidate"],
        evaluator_bundle=paths["evaluator_bundle"],
        suite_path=paths["suite"],
        config_path=paths["config"],
        source_manifest_path=paths["source_manifest"],
        private_key_path=paths["private_key"],
        allowed_request_path=paths["allowed_request"],
        outputs_path=outputs,
        terminal_root=paths["terminal"],
        clock=lambda: NOW,
    )

    assert receipt.body["candidate_quality_bps"] == 10_000
    assert receipt.body["source_quality_bps"] == 10_000
    verified = verify_terminal_evidence(
        paths["terminal"], request, load_public_key(paths["public_key"]), paths["suite"]
    )
    assert verified.to_bytes() == receipt.to_bytes()
