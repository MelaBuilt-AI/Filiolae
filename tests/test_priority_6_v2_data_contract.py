from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).parents[1] / "ops" / "priority-6-v2" / "data_contract.py"
SPEC = importlib.util.spec_from_file_location("priority_6_v2_data_contract", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
DATA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DATA)


def test_generation_is_deterministic_unique_and_exact() -> None:
    seed = bytes.fromhex("11" * 32)
    first = DATA.generate_cases(seed=seed, count=1000, prefix="train", forbidden=set())
    second = DATA.generate_cases(seed=seed, count=1000, prefix="train", forbidden=set())
    assert first == second
    assert len({row["prompt"] for row in first}) == 1000
    assert all(row["answer"] == row["prompt"][::-1] for row in first)
    assert all(DATA.PROMPT_RE.fullmatch(row["prompt"]) for row in first)
    assert first[0]["case_id"] == "train-000000"
    assert first[-1]["case_id"] == "train-000999"


def test_forbidden_inventory_forces_disjoint_generation(tmp_path: Path) -> None:
    seed = bytes.fromhex("22" * 32)
    first = DATA.generate_cases(seed=seed, count=20, prefix="first", forbidden=set())
    inventory = DATA.inventory(first)
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_bytes(DATA.canonical_json(inventory) + b"\n")
    forbidden = DATA.read_forbidden([inventory_path])
    second = DATA.generate_cases(seed=seed, count=20, prefix="second", forbidden=forbidden)
    first_hashes = set(inventory["prompt_hashes"])
    second_hashes = set(DATA.inventory(second)["prompt_hashes"])
    assert first_hashes.isdisjoint(second_hashes)
    assert first[0]["prompt"] != second[0]["prompt"]


def test_inventory_rejects_invalid_schema(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"schema": "wrong", "prompt_hashes": []}))
    with pytest.raises(ValueError, match="unexpected inventory schema"):
        DATA.read_forbidden([path])


def test_seed_must_be_at_least_256_bits() -> None:
    with pytest.raises(ValueError, match="256 bits"):
        DATA.generate_cases(seed=b"short", count=1, prefix="x", forbidden=set())
