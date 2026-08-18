from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).parents[1] / "ops" / "priority-6-v2" / "gate_d_runtime.py"
SPEC = importlib.util.spec_from_file_location("priority_6_v2_gate_d_runtime", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNTIME = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNTIME
SPEC.loader.exec_module(RUNTIME)


def case(case_id: str, prompt: str) -> dict[str, str]:
    return {
        "answer": prompt[::-1],
        "case_id": case_id,
        "prompt": prompt,
        "schema": RUNTIME.CASE_SCHEMA,
    }


def test_load_cases_requires_exact_labels_sorted_ids_and_unique_prompts(tmp_path: Path) -> None:
    path = tmp_path / "cases.jsonl"
    rows = [case("case-000", "a b c d e f"), case("case-001", "2 3 4 5 6 7")]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    assert RUNTIME.load_cases(path, 2) == rows

    rows[1]["answer"] = "wrong"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    with pytest.raises(RuntimeError, match="incorrect label"):
        RUNTIME.load_cases(path, 2)


def test_manifest_verifies_exact_regular_files(tmp_path: Path) -> None:
    (tmp_path / "training.jsonl").write_text("content\n")
    digest = RUNTIME.sha256_file(tmp_path / "training.jsonl")
    manifest = {
        "schema": "filiolae.priority6-v2-gate-d-execution.v1",
        "staged_files": {"training.jsonl": digest},
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(RUNTIME.canonical_json(manifest) + b"\n")
    result = RUNTIME.verify_manifest(tmp_path, manifest_path)
    assert result["observed"] == {"training.jsonl": digest}

    (tmp_path / "training.jsonl").write_text("tampered\n")
    with pytest.raises(RuntimeError, match="digest mismatch"):
        RUNTIME.verify_manifest(tmp_path, manifest_path)


def test_tree_digest_rejects_symlink(tmp_path: Path) -> None:
    (tmp_path / "model.safetensors").write_bytes(b"weights")
    first = RUNTIME.tree_digest(tmp_path)
    assert first == RUNTIME.tree_digest(tmp_path)
    (tmp_path / "link").symlink_to("model.safetensors")
    with pytest.raises(RuntimeError, match="symlink forbidden"):
        RUNTIME.tree_digest(tmp_path)
