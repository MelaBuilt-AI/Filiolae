from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
OPS = ROOT / "ops" / "systemd-containment"
PROBE_WORKFLOW = ROOT / ".github" / "workflows" / "systemd-host-probe.yml"
GAME_DAY_WORKFLOW = ROOT / ".github" / "workflows" / "systemd-containment-game-day.yml"
PLAN = ROOT / "docs" / "native-systemd-containment-game-day.md"


def test_host_probe_is_bounded_and_fail_closed() -> None:
    path = OPS / "host_probe.py"
    assert path.stat().st_mode & 0o111
    source = path.read_text()
    for required in (
        'pid1 == "systemd"',
        'fs_value == "cgroup2fs"',
        'systemd-detect-virt", "--container"',
        'sudo", "-n", "true"',
        '"observable-service-cgroup"',
        '"journald-evidence"',
        '"exact-source-commit"',
        '"filiolae.systemd-host-probe.v1"',
        '"transient-stop"',
    ):
        assert required in source
    assert "os.environ" in source
    assert "selected_environment" in source
    assert "TOKEN" not in source and "SECRET" not in source


def test_probe_workflow_is_manual_single_job_and_read_only() -> None:
    workflow = PROBE_WORKFLOW.read_text()
    assert re.search(r"(?m)^  workflow_dispatch:\s*$", workflow)
    assert re.search(r"(?m)^permissions:\n  contents: read$", workflow)
    assert workflow.count("runs-on:") == 1
    assert "runs-on: ubuntu-24.04" in workflow
    assert "timeout-minutes: 5" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "if: always()" in workflow
    assert "retention-days: 14" in workflow
    for uses in re.findall(r"(?m)^\s*- uses: ([^\s]+)", workflow):
        _, separator, revision = uses.partition("@")
        assert separator and re.fullmatch(r"[0-9a-f]{40}", revision)


def test_game_day_plan_has_explicit_scenarios_limits_and_non_claims() -> None:
    plan = PLAN.read_text()
    for heading in (
        "### S0 — host, installation, identity, and path contract",
        "### S1 — baseline witnessed promotion",
        "### S2 — witness crash and cgroup containment",
        "### S3 — hung witness, denial/freeze, and reconciliation",
        "### S4 — startup failures",
        "### S5 — lost response",
        "### S6 — cleanup and retained evidence",
    ):
        assert heading in plan
    for boundary in (
        "100 billed minutes",
        "maximum two hours",
        "$0.10",
        "boot persistence",
        "does not authorize publication",
    ):
        assert boundary in plan


def test_game_day_harness_uses_real_gate_and_hostile_setsid_child() -> None:
    path = OPS / "orchestrator_harness.py"
    assert path.stat().st_mode & 0o111
    source = path.read_text()
    for required in (
        "_build_barrier",
        "WeightUpdateController",
        "start_new_session=True",
        "signal.SIG_IGN",
        '"load-called.json"',
        'action == "reconcile"',
        '"filiolae.systemd-orchestrator-harness.v1"',
    ):
        assert required in source
    assert "from prime_rl" not in source


def test_game_day_driver_covers_live_scenarios_and_cleans_private_key() -> None:
    path = OPS / "run_game_day.py"
    assert path.stat().st_mode & 0o111
    source = path.read_text()
    for required in (
        'self.permission_checks(run_id, "S0")',
        "assert_cgroup_gone_or_empty",
        '"kill-witness"',
        '"SIGSTOP"',
        '"SIGCONT"',
        '"gate.approved" not in events_after',
        '("key", "lock", "enrollment", "socket", "config")',
        "PRIVATE_KEY.unlink(missing_ok=True)",
        '"actual boot persistence"',
        '"deterministic lost-response relay not yet implemented',
        'self.evidence / "MANIFEST.json"',
    ):
        assert required in source
    assert "PRIVATE_KEY" not in re.search(r"for name, source in \((.*?)\):\n", source, re.DOTALL).group(1)


def test_full_game_day_workflow_is_manual_bounded_and_fail_closed() -> None:
    workflow = GAME_DAY_WORKFLOW.read_text()
    assert re.search(r"(?m)^  workflow_dispatch:\s*$", workflow)
    assert re.search(r"(?m)^permissions:\n  contents: read$", workflow)
    assert workflow.count("runs-on:") == 1
    assert "runs-on: ubuntu-24.04" in workflow
    assert "timeout-minutes: 25" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "Emergency fail-closed cleanup" in workflow
    assert "ed25519-private.pem" in workflow
    assert "if: always()" in workflow
    assert "retention-days: 14" in workflow
    assert "systemd-containment/run_game_day.py" in workflow
    for uses in re.findall(r"(?m)^\s*- uses: ([^\s]+)", workflow):
        _, separator, revision = uses.partition("@")
        assert separator and re.fullmatch(r"[0-9a-f]{40}", revision)
