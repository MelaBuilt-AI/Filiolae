from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from filiolae.transparency import parse_receipt_transparency_leaf

ROOT = Path(__file__).parents[1]
S2 = ROOT / "interop" / "s2"
EVIDENCE = ROOT / "evidence" / "acceptance" / "transparency-s2-20260813"


def test_s2_synthetic_fixture_is_valid_chained_public_test_material(tmp_path: Path) -> None:
    output = tmp_path / "fixture"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "generate_transparency_s2_fixture.py"),
            "--output",
            str(output),
            "--count",
            "12",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    manifest = json.loads((output / "manifest.json").read_bytes())
    assert manifest["schema"] == "filiolae.transparency-s2-synthetic-fixture.v1"
    assert manifest["count"] == 12
    previous = "0" * 64
    for index, item in enumerate(manifest["leaves"]):
        raw = (output / item["filename"]).read_bytes()
        parsed = parse_receipt_transparency_leaf(raw)
        assert parsed.receipt.anchor_seq == index
        assert parsed.receipt.run_id.startswith("synthetic-s2-")
        assert parsed.receipt.previous_receipt_sha256 == previous
        assert item["sha256"] == hashlib.sha256(raw).hexdigest()
        assert item["receipt_sha256"] == parsed.receipt.receipt_sha256()
        previous = parsed.receipt.receipt_sha256()


def test_s2_sources_pin_loopback_and_no_key_argument() -> None:
    go_mod = (S2 / "go.mod").read_text()
    assert "github.com/transparency-dev/tessera v1.0.4" in go_mod
    assert "github.com/transparency-dev/merkle v0.0.2" in go_mod
    personality = (S2 / "cmd" / "personality" / "main.go").read_text()
    assert 'net.Listen("tcp4", "127.0.0.1:0")' in personality
    assert "http.MaxBytesReader" in personality
    assert "netutil.LimitListener" in personality
    assert "checkpoint key descriptor" in personality
    assert "private-key" not in personality
    plan = (ROOT / "docs" / "tessera-loopback-shadow-plan.md").read_text()
    acceptance = (ROOT / "docs" / "tessera-loopback-shadow-acceptance.md").read_text()
    assert "bounded S2 acceptance passed" in plan
    assert "passed bounded local acceptance" in acceptance


def test_s2_canonical_evidence_inventory_and_monitor_agreement() -> None:
    if not EVIDENCE.is_dir():
        pytest.skip("canonical private-checkout S2 evidence is not present in this source distribution")
    result = json.loads((EVIDENCE / "RESULT.json").read_bytes())
    assert result["schema"] == "filiolae.transparency-s2-acceptance.v1"
    assert result["status"] == "passed"
    assert [case["case"] for case in result["cases"]] == [f"S2.{index}" for index in range(7)]
    assert all(case["status"] == "passed" for case in result["cases"])
    assert result["final_tree_size"] == 16
    assert result["isolation"].startswith("separate-process/")

    inventory = (EVIDENCE / "SHA256SUMS").read_bytes()
    assert hashlib.sha256(inventory).hexdigest() == (
        "09f275d3f02f645228a30bebba95c5c63403b77f18ff1be1a518ef8a2340eafc"
    )
    lines = inventory.decode().splitlines()
    assert len(lines) == 204
    for line in lines:
        digest, relative = line.split("  ", 1)
        path = EVIDENCE / relative
        assert path.is_file(), relative
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
        assert "private" not in path.name.lower()
        assert "/.state/" not in f"/{relative}/"

    python_state = json.loads((EVIDENCE / "mirror-main-python" / "state.json").read_bytes())
    go_state = json.loads((EVIDENCE / "mirror-main-go" / "state.json").read_bytes())
    assert python_state["tree_size"] == go_state["tree_size"] == 16
    assert python_state["root_hex"] == go_state["root_hex"] == result["final_root_hex"]
    assert python_state["leaves_b64"] == go_state["leaves_b64"]
    assert not any("private" in path.name.lower() or path.name == ".state" for path in EVIDENCE.rglob("*"))
