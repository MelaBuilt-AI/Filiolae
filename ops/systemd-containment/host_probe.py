#!/usr/bin/env python3
"""Fail-fast admission probe for a disposable native systemd/cgroup-v2 host."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class Probe:
    def __init__(self, evidence_dir: Path) -> None:
        self.evidence_dir = evidence_dir
        self.evidence_dir.mkdir(parents=True, exist_ok=False)
        self.commands_dir = self.evidence_dir / "commands"
        self.commands_dir.mkdir()
        self.commands: list[dict[str, object]] = []
        self.checks: list[dict[str, object]] = []
        self._counter = 0

    def run(self, name: str, command: list[str], *, timeout: float = 30) -> subprocess.CompletedProcess[str]:
        self._counter += 1
        started = utc_now()
        before = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            completed = subprocess.CompletedProcess(
                command,
                124,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
            )
            timed_out = True
        elapsed = time.monotonic() - before
        stem = f"{self._counter:02d}-{name}"
        (self.commands_dir / f"{stem}.stdout.txt").write_text(completed.stdout)
        (self.commands_dir / f"{stem}.stderr.txt").write_text(completed.stderr)
        record = {
            "name": name,
            "argv": command,
            "started_at": started,
            "elapsed_seconds": round(elapsed, 6),
            "returncode": completed.returncode,
            "timed_out": timed_out,
            "stdout_file": f"commands/{stem}.stdout.txt",
            "stderr_file": f"commands/{stem}.stderr.txt",
        }
        self.commands.append(record)
        return completed

    def check(self, name: str, passed: bool, detail: str) -> None:
        self.checks.append({"name": name, "passed": bool(passed), "detail": detail})

    def report(self, *, started_at: str, error: str | None = None) -> dict[str, object]:
        passed = error is None and all(bool(check["passed"]) for check in self.checks)
        return {
            "schema": "filiolae.systemd-host-probe.v1",
            "started_at": started_at,
            "completed_at": utc_now(),
            "passed": passed,
            "error": error,
            "checks": self.checks,
            "commands": self.commands,
            "selected_environment": {
                key: os.environ[key]
                for key in (
                    "CI",
                    "GITHUB_ACTION",
                    "GITHUB_ACTOR",
                    "GITHUB_EVENT_NAME",
                    "GITHUB_JOB",
                    "GITHUB_REPOSITORY",
                    "GITHUB_RUN_ATTEMPT",
                    "GITHUB_RUN_ID",
                    "GITHUB_SHA",
                    "ImageOS",
                    "ImageVersion",
                    "RUNNER_ARCH",
                    "RUNNER_ENVIRONMENT",
                    "RUNNER_NAME",
                    "RUNNER_OS",
                )
                if key in os.environ
            },
            "python": sys.version,
            "platform": platform.platform(),
        }


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} EVIDENCE_DIR", file=sys.stderr)
        return 64
    evidence_dir = Path(sys.argv[1]).absolute()
    started_at = utc_now()
    probe = Probe(evidence_dir)
    unit = f"filiolae-host-probe-{os.getpid()}.service"
    error: str | None = None
    try:
        pid1 = Path("/proc/1/comm").read_text().strip()
        probe.check("systemd-pid-1", pid1 == "systemd", f"/proc/1/comm={pid1!r}")

        fs_type = probe.run("cgroup-filesystem", ["stat", "-fc", "%T", "/sys/fs/cgroup"])
        fs_value = fs_type.stdout.strip()
        probe.check(
            "unified-cgroup-v2-filesystem",
            fs_type.returncode == 0 and fs_value == "cgroup2fs",
            f"returncode={fs_type.returncode}, type={fs_value!r}",
        )
        controllers_path = Path("/sys/fs/cgroup/cgroup.controllers")
        controllers = controllers_path.read_text().strip() if controllers_path.is_file() else ""
        probe.check("cgroup-v2-controllers", bool(controllers), controllers or "missing/empty")

        container = probe.run("container-virtualization", ["systemd-detect-virt", "--container"])
        container_name = container.stdout.strip()
        probe.check(
            "not-a-container",
            container.returncode != 0 and container_name in {"", "none"},
            f"returncode={container.returncode}, result={container_name!r}",
        )
        vm = probe.run("vm-virtualization", ["systemd-detect-virt", "--vm"])
        probe.check(
            "virtual-machine",
            vm.returncode == 0 and bool(vm.stdout.strip()),
            f"returncode={vm.returncode}, result={vm.stdout.strip()!r}",
        )

        sudo = probe.run("passwordless-sudo", ["sudo", "-n", "true"])
        probe.check("passwordless-root", sudo.returncode == 0, f"returncode={sudo.returncode}")

        for name, command in (
            ("uname", ["uname", "-a"]),
            ("os-release", ["cat", "/etc/os-release"]),
            ("systemd-version", ["systemctl", "--version"]),
            ("mounts", ["findmnt", "--output", "TARGET,SOURCE,FSTYPE,OPTIONS"]),
            ("cgroup-tree-before", ["systemd-cgls", "--all", "--no-pager"]),
            ("disk", ["df", "-hT", "/", "/tmp"]),
            ("memory", ["cat", "/proc/meminfo"]),
        ):
            result = probe.run(name, command)
            probe.check(f"metadata-{name}", result.returncode == 0, f"returncode={result.returncode}")

        available_memory_kib = 0
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                available_memory_kib = int(line.split()[1])
                break
        free_disk = shutil.disk_usage("/").free
        probe.check(
            "minimum-memory",
            available_memory_kib >= 1_536 * 1024,
            f"MemAvailable={available_memory_kib} KiB",
        )
        probe.check("minimum-disk", free_disk >= 5 * 1024**3, f"free_bytes={free_disk}")

        expected_sha = os.environ.get("GITHUB_SHA")
        head = probe.run("git-head", ["git", "rev-parse", "HEAD"])
        actual_sha = head.stdout.strip()
        probe.check(
            "exact-source-commit",
            head.returncode == 0 and (not expected_sha or actual_sha == expected_sha),
            f"actual={actual_sha!r}, expected={expected_sha!r}",
        )

        start = probe.run(
            "transient-start",
            [
                "sudo",
                "systemd-run",
                f"--unit={unit}",
                "--property=Type=simple",
                "--collect",
                "/usr/bin/sleep",
                "30",
            ],
        )
        probe.check("transient-start-command", start.returncode == 0, f"returncode={start.returncode}")
        active = probe.run("transient-active", ["sudo", "systemctl", "is-active", unit])
        probe.check(
            "transient-service-active",
            active.returncode == 0 and active.stdout.strip() == "active",
            f"returncode={active.returncode}, state={active.stdout.strip()!r}",
        )
        properties = probe.run(
            "transient-properties",
            [
                "sudo",
                "systemctl",
                "show",
                unit,
                "-p",
                "MainPID",
                "-p",
                "ControlGroup",
                "-p",
                "ActiveState",
                "-p",
                "SubState",
                "-p",
                "Result",
                "--no-pager",
            ],
        )
        parsed = {}
        for line in properties.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                parsed[key] = value
        control_group = parsed.get("ControlGroup", "")
        main_pid = parsed.get("MainPID", "")
        cgroup_dir = Path("/sys/fs/cgroup") / control_group.lstrip("/")
        cgroup_procs = cgroup_dir / "cgroup.procs"
        pids = cgroup_procs.read_text().split() if cgroup_procs.is_file() else []
        probe.check(
            "observable-service-cgroup",
            bool(control_group) and cgroup_dir.is_dir() and main_pid in pids,
            f"ControlGroup={control_group!r}, MainPID={main_pid!r}, pids={pids!r}",
        )
        journal = probe.run(
            "transient-journal",
            ["sudo", "journalctl", "-u", unit, "--no-pager", "--output=short-iso-precise"],
        )
        probe.check(
            "journald-evidence",
            journal.returncode == 0 and bool(journal.stdout.strip()),
            f"returncode={journal.returncode}, bytes={len(journal.stdout)}",
        )
    except BaseException as exc:  # preserve partial evidence before reporting failure
        error = f"{type(exc).__name__}: {exc}"
    finally:
        probe.run("transient-stop", ["sudo", "systemctl", "stop", unit], timeout=15)
        probe.run("transient-reset-failed", ["sudo", "systemctl", "reset-failed", unit], timeout=15)
        probe.run("cgroup-tree-after", ["systemd-cgls", "--all", "--no-pager"])
        report = probe.report(started_at=started_at, error=error)
        (evidence_dir / "probe-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
