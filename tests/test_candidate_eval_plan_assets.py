from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

from filiolae.canonical import canonical_json

ROOT = Path(__file__).parents[1]
ASSETS = ROOT / "examples" / "candidate-eval"
SUITE = ASSETS / "reverse-text-held-out-v1.jsonl"
CONFIG = ASSETS / "reverse-text-paired-config-v1.json"
SOURCE = ASSETS / "r18-step1-source-manifest-v1.json"
PAIR = ASSETS / "r18-step2-pair-selection-v1.json"
EVALUATOR_BUNDLE = ASSETS / "cpu-evaluator-bundle-v1.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    value = json.loads(raw)
    assert raw == canonical_json(value) + b"\n"
    return value


def test_frozen_reverse_text_suite_is_reproducible_and_self_consistent() -> None:
    spec = importlib.util.spec_from_file_location(
        "generate_candidate_eval_suite", ROOT / "scripts" / "generate_candidate_eval_suite.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert SUITE.read_bytes() == module.render()
    assert _sha256(SUITE) == "7d2a3c9edd04d6e75f5784ae7b686788ae515d524056a0d2895df354e3afc03d"
    cases = [json.loads(line) for line in SUITE.read_text().splitlines()]
    assert len(cases) == 128
    assert len({case["case_id"] for case in cases}) == 128
    assert len({case["prompt"] for case in cases}) == 128
    assert [case["case_id"] for case in cases] == sorted(case["case_id"] for case in cases)
    assert all(case["answer"] == case["prompt"][::-1] for case in cases)
    assert all("<reversed_text>" not in case["prompt"] for case in cases)


def test_paired_eval_assets_bind_the_precommitted_r18_pair_suite_and_thresholds() -> None:
    config = _canonical(CONFIG)
    source = _canonical(SOURCE)
    pair = _canonical(PAIR)

    assert _sha256(CONFIG) == "e911bb6d9f767b8baf67bba6410e77a1998f4cc18acd4cb41480b27facbae712"
    assert _sha256(SOURCE) == "3d70ada0ce838365e0f53692ec61349d844ede5cb7ac44fe1e802f26f6bb822e"
    assert _sha256(PAIR) == "f6be24ccd30c78e53ef75e4d0479521c90097b4c8ce129c2f584c8caaef26a88"
    assert config["suite"]["sha256"] == _sha256(SUITE)
    assert config["suite"]["case_count"] == 128
    assert config["suite"]["training_dataset_overlap_count"] == 0
    assert config["charter_thresholds"] == {
        "maximum_receipt_age_seconds": 1800,
        "maximum_regression_bps": 79,
        "minimum_quality_bps": 8000,
    }
    assert source["source_weights"] == {
        "artifact_kind": pair["source"]["artifact_kind"],
        "sha256": pair["source"]["sha256"],
        "size": pair["source"]["size"],
    }
    assert pair["source"]["policy_version"] == source["source_policy_version"]
    assert pair["candidate"] == {
        "artifact_kind": "directory",
        "attempt_id": "4a1dd5e3706343dfbd0db09265182f2c",
        "sha256": "4bd8ca5cba086ff538f00f56fbd4ad9f241e05bc60e5307f976c63a81579473d",
        "size": 1503300328,
        "target_step": 2,
        "weights_ledger_seq": 9,
    }


def test_cpu_evaluator_bundle_is_exactly_reproducible() -> None:
    from filiolae.paired_eval import evaluator_bundle_body

    assert EVALUATOR_BUNDLE.read_bytes() == canonical_json(evaluator_bundle_body()) + b"\n"
    assert _sha256(EVALUATOR_BUNDLE) == "9ae8ac7506a8d55b7c2243973eb58c70e10020f81a27f72eeb37ab741d2b5760"


V2_CONTRACT = ROOT / "examples" / "priority-6-v2" / "acceptance-contract-v1.json"


def test_priority6_v2_contract_preserves_data_and_acceptance_boundaries() -> None:
    contract = _canonical(V2_CONTRACT)

    assert _sha256(V2_CONTRACT) == "4bbb86cd2e0d3312a0f1794a57b53970a1dd67e2bd6e4a0604b28cb2af2d3c6c"
    assert contract["schema"] == "filiolae.priority6-v2-acceptance-contract.v1"
    assert contract["integrity_boundaries"] == {
        "original_r18_experiment": "permanently-threshold-failed-and-closed",
        "threshold_changes_after_results": False,
        "v1_observed_suite_allowed_for_v2_tuning": False,
    }
    data = contract["data_controls"]
    assert set(data["required_pairwise_disjointness"]) == {
        "training-vs-development",
        "training-vs-final",
        "development-vs-final",
    }
    assert data["final"] == {
        "case_count": 128,
        "commitment_visible_during_development": True,
        "custodian": "separate-final-evaluator-domain",
        "plaintext_available_before_candidate_freeze": False,
        "reuse_after_terminal_result": False,
    }
    readiness = contract["development_readiness_gate"]
    assert readiness["case_count"] == 256
    assert readiness["candidate_minimum_exact_matches"] == 244
    assert readiness["candidate_minimum_quality_bps"] == 9500
    final = contract["final_acceptance"]
    assert final["candidate_minimum_exact_matches"] == 103
    assert final["candidate_minimum_quality_bps"] == 8000
    assert final["maximum_regression_bps"] == 79
    assert final["exact_disposable_shadow_promotions"] == 1
    assert final["one_shot"] is True
    assert "answer-computing-wrapper" in contract["candidate_development"]["forbidden_runtime_aids"]
    assert set(contract["authorization"]["separate_owner_decisions_required"]) == {
        "development-compute",
        "one-shot-final-acceptance",
    }
