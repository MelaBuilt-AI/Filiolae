from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).parents[1]
ASSETS = ROOT / "examples" / "priority-6-v2" / "gate-f-v1"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(path: Path) -> dict:
    raw = path.read_bytes()
    value = json.loads(raw)
    assert raw == json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    return value


def test_gate_f_assets_are_content_addressed_and_cross_bound() -> None:
    expected = {}
    for line in (ASSETS / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        expected[name] = digest
    actual = {
        path.name: sha256(path) for path in ASSETS.iterdir() if path.is_file() and path.name != "SHA256SUMS"
    }
    assert actual == expected

    inputs = canonical(ASSETS / "execution-inputs-v1.json")
    config = canonical(ASSETS / "paired-eval-config-v1.json")
    source = canonical(ASSETS / "source-manifest-v1.json")
    result = canonical(ASSETS / "gate-f-result-v1.json")
    assert inputs["candidate"]["tree_sha256"] == (
        "741fda92eada7ff04d5e10882af9c253d3a0d4cb80bb7c7d530c600004826b57"
    )
    assert inputs["final_suite"]["sha256"] == config["suite"]["sha256"]
    assert inputs["final_suite"]["case_count"] == config["suite"]["case_count"] == 128
    assert source["source_policy_version"] == 0
    assert source["upstream"]["source_policy_version"] == 1
    assert source["source_weights"]["sha256"] == inputs["source"]["tree_sha256"]
    assert source["source_weights"]["size"] == inputs["source"]["size"]
    assert result["status"] == "passed"
    assert result["candidate_tree_sha256"] == inputs["candidate"]["tree_sha256"]
    assert result["final_suite_sha256"] == inputs["final_suite"]["sha256"]
    assert result["candidate_exact_matches"] == 127
    assert result["candidate_quality_bps"] == 9921
    assert result["source_quality_bps"] == 0
    assert result["exact_approvals"] == result["exact_promotions"] == 1
    assert result["execution"]["normalized_total_cost_usd"] <= result["execution"]["hard_cost_cap_usd"]
    assert result["execution"]["zero_resources_after_termination"] is True


def test_gate_f_evaluator_bundle_pins_exact_executing_sources() -> None:
    bundle = canonical(ASSETS / "evaluator-bundle-v1.json")
    expected_paths = {
        "filiolae/anchor.py": ROOT / "src" / "filiolae" / "anchor.py",
        "filiolae/artifacts.py": ROOT / "src" / "filiolae" / "artifacts.py",
        "filiolae/canonical.py": ROOT / "src" / "filiolae" / "canonical.py",
        "filiolae/paired_eval.py": ROOT / "src" / "filiolae" / "paired_eval.py",
        "filiolae/shadow_eval.py": ROOT / "src" / "filiolae" / "shadow_eval.py",
        "ops/gate_d_runtime.py": ROOT / "ops" / "priority-6-v2" / "gate_d_runtime.py",
        "ops/gate_f_evaluator_service.py": (ROOT / "ops" / "priority-6-v2" / "gate_f_evaluator_service.py"),
    }
    assert bundle["purpose"] == "final-acceptance-real-model-paired-inference"
    assert bundle["files"] == {name: sha256(path) for name, path in expected_paths.items()}
    assert bundle["runtime"] == {
        "cryptography": "46.0.5",
        "python": "3.12",
        "safetensors": "0.5.3",
        "torch": "2.7.0",
        "transformers": "4.52.4",
    }


def test_gate_f_orchestration_is_one_shot_and_uses_run_local_step_one() -> None:
    controller = (ROOT / "ops" / "priority-6-v2" / "gate_f_controller_acceptance.py").read_text()
    runner = (ROOT / "ops" / "priority-6-v2" / "run_gate_f_acceptance.sh").read_text()
    creator = (ROOT / "ops" / "priority-6-v2" / "create_and_arm_gate_f_pod.py").read_text()
    assert 'broadcasts" / "step_1"' in controller
    assert "step=1" in controller
    assert "step_2" not in controller
    assert runner.count("741fda92eada7ff04d5e10882af9c253d3a0d4cb80bb7c7d530c600004826b57") == 1
    assert "--maximum-hours 1.5" not in runner
    assert "default=1.5" in creator
    assert "requires exactly 1.5 maximum hours" in creator
