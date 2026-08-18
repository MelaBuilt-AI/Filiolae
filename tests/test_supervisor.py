from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

from filiolae.freeze import FreezeController
from filiolae.supervisor import ProcessGroupSupervisor, SupervisorError


def _freeze_when_ready(freezer: FreezeController, ready: Path) -> threading.Thread:
    def worker() -> None:
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        freezer.freeze("test tripwire")

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return thread


def _non_zombie_exists(pid: int) -> bool:
    stat = Path(f"/proc/{pid}/stat")
    if not stat.exists():
        return False
    try:
        state = stat.read_text().split()[2]
    except (OSError, IndexError):
        return False
    return state != "Z"


def test_refuses_to_start_when_already_frozen(tmp_path: Path) -> None:
    freezer = FreezeController(tmp_path / "freeze.json")
    freezer.freeze("preexisting")
    supervisor = ProcessGroupSupervisor(freezer)
    with pytest.raises(SupervisorError, match="refusing to start"):
        supervisor.run([sys.executable, "-c", "raise SystemExit(0)"])


def test_normal_zero_exit_does_not_freeze(tmp_path: Path) -> None:
    freezer = FreezeController(tmp_path / "freeze.json")
    result = ProcessGroupSupervisor(freezer).run([sys.executable, "-c", "raise SystemExit(0)"])
    assert result.returncode == 0
    assert not freezer.state().frozen


def test_nonzero_exit_freezes(tmp_path: Path) -> None:
    freezer = FreezeController(tmp_path / "freeze.json")
    result = ProcessGroupSupervisor(freezer).run([sys.executable, "-c", "raise SystemExit(7)"])
    assert result.returncode == 7
    assert freezer.state().frozen


def test_freeze_terminates_process_group_tree(tmp_path: Path) -> None:
    freezer = FreezeController(tmp_path / "freeze.json")
    ready = tmp_path / "ready"
    child_pid_path = tmp_path / "child.pid"
    child_code = "import time; time.sleep(60)"
    leader_code = (
        "import subprocess,sys,time,pathlib,os;"
        f"child=subprocess.Popen([sys.executable,'-c',{child_code!r}]);"
        f"pathlib.Path({str(child_pid_path)!r}).write_text(str(child.pid));"
        f"pathlib.Path({str(ready)!r}).write_text(str(os.getpid()));"
        "time.sleep(60)"
    )
    thread = _freeze_when_ready(freezer, ready)
    result = ProcessGroupSupervisor(freezer, term_grace_seconds=0.5).run([sys.executable, "-c", leader_code])
    thread.join(timeout=1)
    assert result.term_sent
    assert result.reason.startswith("freeze:")
    child_pid = int(child_pid_path.read_text())
    deadline = time.monotonic() + 2
    while _non_zombie_exists(child_pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not _non_zombie_exists(child_pid)


def test_stubborn_process_receives_sigkill(tmp_path: Path) -> None:
    freezer = FreezeController(tmp_path / "freeze.json")
    ready = tmp_path / "ready"
    code = (
        "import signal,time,pathlib,os;"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
        f"pathlib.Path({str(ready)!r}).write_text(str(os.getpid()));"
        "time.sleep(60)"
    )
    thread = _freeze_when_ready(freezer, ready)
    result = ProcessGroupSupervisor(
        freezer,
        poll_interval=0.01,
        term_grace_seconds=0.05,
    ).run([sys.executable, "-c", code])
    thread.join(timeout=1)
    assert result.term_sent
    assert result.kill_sent
    assert result.returncode == -9


def test_freeze_after_ready_before_go_prevents_target_exec(tmp_path: Path) -> None:
    freezer = FreezeController(tmp_path / "freeze.json")
    side_effect = tmp_path / "target-ran"
    supervisor = ProcessGroupSupervisor(freezer, term_grace_seconds=0.1)

    def trip_before_release() -> None:
        freezer.freeze("deterministic pre-exec race")

    with pytest.raises(SupervisorError, match="froze before target exec"):
        supervisor.run(
            [sys.executable, "-c", f"from pathlib import Path; Path({str(side_effect)!r}).touch()"],
            before_release=trip_before_release,
        )
    assert not side_effect.exists()


def test_nonzero_leader_exit_cleans_residual_roles(tmp_path: Path) -> None:
    freezer = FreezeController(tmp_path / "freeze.json")
    role_pid_path = tmp_path / "role.pid"
    role_code = "import time; time.sleep(60)"
    launcher_code = (
        "import subprocess,sys,pathlib;"
        f"p=subprocess.Popen([sys.executable,'-c',{role_code!r}]);"
        f"pathlib.Path({str(role_pid_path)!r}).write_text(str(p.pid));"
        "raise SystemExit(9)"
    )
    result = ProcessGroupSupervisor(freezer, term_grace_seconds=0.2).run(
        [sys.executable, "-c", launcher_code]
    )
    assert result.returncode == 9
    assert result.term_sent
    assert freezer.state().frozen
    role_pid = int(role_pid_path.read_text())
    deadline = time.monotonic() + 2
    while _non_zombie_exists(role_pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not _non_zombie_exists(role_pid)
