from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from filiolae.canonical import canonical_json

ROOT = Path(__file__).parents[1]
OPS = ROOT / "ops" / "priority-6-v2"
WORKFLOW = ROOT / ".github" / "workflows" / "quality.yml"


def test_priority6_v2_distinct_uid_assets_are_bounded_and_syntax_valid() -> None:
    scripts = [
        OPS / "controller_acceptance.py",
        OPS / "evaluator_service.py",
        OPS / "finalize_evidence.py",
    ]
    for path in scripts:
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", str(path)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
    shell = OPS / "run_distinct_uid_acceptance.sh"
    result = subprocess.run(["bash", "-n", str(shell)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    text = shell.read_text()
    assert "pkill -KILL -u" in text
    assert 'test ! -e "$work/key/private.pem"' in text
    assert 'pgrep -u "$evaluator"' in text
    assert "SHA256SUMS" in text
    assert not any(token in text for token in ("prime pods", "curl ", "wget ", "ssh "))


def test_priority6_v2_private_ci_runs_and_retains_exact_fixture_package() -> None:
    workflow = WORKFLOW.read_text()
    assert "priority-6-v2-distinct-uid:" in workflow
    assert "sudo ops/priority-6-v2/run_distinct_uid_acceptance.sh" in workflow
    assert "priority-6-v2-distinct-uid-fixture-evidence" in workflow
    assert "path: /tmp/filiolae-p6-v2-separate-uid-evidence" in workflow
    controller = (OPS / "controller_acceptance.py").read_text()
    assert "ExternalTerminalShadowEvaluator" in controller
    assert 'events.count("gate.approved") != 1' in controller
    assert 'events.count("policy.promoted") != 1' in controller
    assert "private_key_unreadable_to_controller" in controller
    assert "terminal_unwritable_by_controller" in controller
    assert "audit_governance" in controller
    assert "candidate_eval_terminal" in controller


def test_priority6_v2_finalizer_builds_closed_inventory_without_private_key(tmp_path: Path) -> None:
    package = tmp_path / "package"
    package.mkdir()
    (package / "SUMMARY.json").write_bytes(canonical_json({"status": "fixture"}) + b"\n")
    result = subprocess.run(
        [
            sys.executable,
            str(OPS / "finalize_evidence.py"),
            str(package),
            "--controller-uid",
            "1001",
            "--evaluator-uid",
            "1002",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    cleanup = json.loads((package / "CLEANUP.json").read_text())
    manifest = json.loads((package / "PACKAGE.json").read_text())
    assert cleanup["evaluator_private_key_absent"] is True
    assert cleanup["evaluator_processes_remaining"] == 0
    assert manifest["bounded_claim"].endswith("no model inference")
    checks = (package / "SHA256SUMS").read_text().splitlines()
    assert any(line.endswith("  CLEANUP.json") for line in checks)
    assert any(line.endswith("  PACKAGE.json") for line in checks)
    assert not any("private" in line.lower() for line in checks)
