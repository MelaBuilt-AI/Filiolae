from __future__ import annotations

import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "ops" / "priority-6-v2" / "run_gate_d_remote.sh"


def test_remote_driver_is_valid_shell_and_does_not_precreate_runtime_output():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
    text = SCRIPT.read_text()
    assert 'test ! -e "$output"' in text
    assert 'mkdir -m 0700 "$lifecycle"' in text
    assert 'mkdir -m 0700 "$output"' not in text
    assert "--output /opt/filiolae-p6-v2-gate-d/run-output" in text


def test_remote_driver_keeps_lifecycle_records_outside_runtime_output():
    text = SCRIPT.read_text()
    assert 'tee -a "$lifecycle/remote-driver.log"' in text
    assert '"$lifecycle/REMOTE-DRIVER-TERMINAL.json.tmp"' in text
    assert '"$lifecycle/REMOTE-DRIVER-TERMINAL.json"' in text
    assert "/opt/filiolae-p6-v2-gate-d/lifecycle/training.log" in text
    assert "/opt/filiolae-p6-v2-gate-d/run-output/training.log" not in text
