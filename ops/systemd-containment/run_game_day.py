#!/usr/bin/env python3
"""Execute and collect the bounded native-systemd containment game day as root."""

from __future__ import annotations

import grp
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn

RUN_ROOT = Path("/srv/filiolae/runs")
ANCHOR_ROOT = Path("/var/lib/filiolae-witness")
MIRROR_ROOT = Path("/var/lib/filiolae-gate-mirrors")
PRIVATE_KEY = Path("/etc/filiolae-witness/ed25519-private.pem")
PUBLIC_KEY = Path("/etc/filiolae/ed25519-public.pem")
DROPIN = Path("/etc/systemd/system/filiolae-orchestrator@.service.d/50-game-day.conf")
HARNESS_TARGET = Path("/usr/libexec/filiolae-containment-harness")
PROVISIONER = Path("/usr/local/sbin/provision-unix-witness")
FILIOLAE = Path("/usr/local/bin/filiolae")


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def atomic_json(path: Path, body: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


class GameDayFailure(RuntimeError):
    pass


class GameDay:
    def __init__(self, evidence: Path, source: Path, venv: Path) -> None:
        self.evidence = evidence
        self.source = source
        self.venv = venv
        self.started_at = utc_now()
        self.commands: list[dict[str, object]] = []
        self.scenarios: dict[str, dict[str, object]] = {}
        self.run_ids: list[str] = []
        self._counter = 0
        self.evidence.mkdir(parents=True, exist_ok=False)
        (self.evidence / "commands").mkdir()
        (self.evidence / "scenarios").mkdir()

    def run(
        self,
        name: str,
        command: list[str],
        *,
        scenario: str = "install",
        timeout: float = 60,
        check: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        self._counter += 1
        started = utc_now()
        before = time.monotonic()
        timed_out = False
        try:
            completed = subprocess.run(
                command,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            completed = subprocess.CompletedProcess(
                command,
                124,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
            )
            timed_out = True
        elapsed = time.monotonic() - before
        safe_name = "".join(
            character if character.isalnum() or character in "-_" else "-" for character in name
        )
        stem = f"{self._counter:03d}-{scenario}-{safe_name}"
        stdout_file = self.evidence / "commands" / f"{stem}.stdout.txt"
        stderr_file = self.evidence / "commands" / f"{stem}.stderr.txt"
        stdout_file.write_text(completed.stdout)
        stderr_file.write_text(completed.stderr)
        self.commands.append(
            {
                "name": name,
                "scenario": scenario,
                "argv": command,
                "started_at": started,
                "elapsed_seconds": round(elapsed, 6),
                "returncode": completed.returncode,
                "timed_out": timed_out,
                "stdout_file": str(stdout_file.relative_to(self.evidence)),
                "stderr_file": str(stderr_file.relative_to(self.evidence)),
            }
        )
        if check and completed.returncode != 0:
            raise GameDayFailure(
                f"command {name!r} failed with {completed.returncode}: {completed.stderr.strip()}"
            )
        return completed

    def require(self, condition: bool, message: str) -> None:
        if not condition:
            raise GameDayFailure(message)

    def wait_path(self, path: Path, *, timeout: float = 20) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return
            time.sleep(0.05)
        raise GameDayFailure(f"timed out waiting for {path}")

    def wait_not_active(self, unit: str, *, timeout: float = 45) -> str:
        deadline = time.monotonic() + timeout
        last = "unknown"
        while time.monotonic() < deadline:
            completed = subprocess.run(
                ["systemctl", "is-active", unit],
                text=True,
                capture_output=True,
                check=False,
            )
            last = completed.stdout.strip()
            if last not in {"active", "activating", "deactivating", "reloading"}:
                return last
            time.sleep(0.1)
        raise GameDayFailure(f"{unit} remained {last!r} past deadline")

    def wait_result(self, path: Path, *, timeout: float = 30) -> dict[str, object]:
        self.wait_path(path, timeout=timeout)
        return json.loads(path.read_text())

    @staticmethod
    def service(name: str, run_id: str) -> str:
        return f"filiolae-{name}@{run_id}.service"

    @staticmethod
    def ledger_events(run_id: str) -> list[str]:
        ledger = RUN_ROOT / run_id / "control" / "filiolae" / "ledger.jsonl"
        if not ledger.is_file():
            return []
        return [json.loads(line)["event"] for line in ledger.read_text().splitlines() if line]

    def install(self) -> None:
        self.require(os.getuid() == 0, "game-day driver must run as root")
        expected = os.environ.get("GITHUB_SHA")
        head = self.run("git-head", ["git", "-C", str(self.source), "rev-parse", "HEAD"], check=True)
        self.require(not expected or head.stdout.strip() == expected, "source commit differs from GITHUB_SHA")
        self.require((self.venv / "bin" / "filiolae").is_file(), "isolated Filiolae executable missing")
        service_python = (self.venv / "bin" / "python").resolve(strict=True)
        self.require(
            not service_python.is_relative_to(Path("/home")),
            f"service Python is hidden by ProtectHome: {service_python}",
        )

        deploy = self.source / "deploy" / "systemd"
        installs = (
            (deploy / "filiolae.sysusers", Path("/usr/lib/sysusers.d/filiolae.conf"), 0o644),
            (deploy / "filiolae.tmpfiles", Path("/usr/lib/tmpfiles.d/filiolae.conf"), 0o644),
            (deploy / "filiolae-governed.slice", Path("/etc/systemd/system/filiolae-governed.slice"), 0o644),
            (
                deploy / "filiolae-witness@.service",
                Path("/etc/systemd/system/filiolae-witness@.service"),
                0o644,
            ),
            (
                deploy / "filiolae-orchestrator@.service",
                Path("/etc/systemd/system/filiolae-orchestrator@.service"),
                0o644,
            ),
            (deploy / "filiolae-witness-ready", Path("/usr/libexec/filiolae-witness-ready"), 0o755),
            (deploy / "provision-unix-witness", PROVISIONER, 0o755),
            (self.source / "ops/systemd-containment/orchestrator_harness.py", HARNESS_TARGET, 0o755),
        )
        for source, target, mode in installs:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            os.chown(target, 0, 0)
            os.chmod(target, mode)

        Path("/usr/local/bin").mkdir(parents=True, exist_ok=True)
        for name in ("filiolae",):
            target = Path("/usr/local/bin") / name
            target.unlink(missing_ok=True)
            target.symlink_to(self.venv / "bin" / name)

        self.run(
            "systemd-sysusers",
            ["systemd-sysusers", "/usr/lib/sysusers.d/filiolae.conf"],
            check=True,
        )
        self.run(
            "systemd-tmpfiles",
            ["systemd-tmpfiles", "--create", "/usr/lib/tmpfiles.d/filiolae.conf"],
            check=True,
        )
        witness = pwd.getpwnam("filiolae-witness")
        orchestrator = pwd.getpwnam("filiolae-orchestrator")
        shared = grp.getgrnam("filiolae-ledger")
        self.require(witness.pw_uid != orchestrator.pw_uid, "service UIDs are equal")
        witness_groups = set(os.getgrouplist(witness.pw_name, witness.pw_gid))
        orchestrator_groups = set(os.getgrouplist(orchestrator.pw_name, orchestrator.pw_gid))
        self.require(
            witness_groups == {witness.pw_gid, shared.gr_gid},
            f"unexpected witness groups: {sorted(witness_groups)}",
        )
        self.require(
            orchestrator_groups == {orchestrator.pw_gid, shared.gr_gid},
            f"unexpected orchestrator groups: {sorted(orchestrator_groups)}",
        )
        identity = {
            "witness": {"uid": witness.pw_uid, "gid": witness.pw_gid},
            "orchestrator": {"uid": orchestrator.pw_uid, "gid": orchestrator.pw_gid},
            "shared_group": {"gid": shared.gr_gid, "members": sorted(shared.gr_mem)},
        }
        atomic_json(self.evidence / "install" / "identities.json", identity)

        private_source = Path("/root/filiolae-game-day-private.pem")
        public_source = Path("/root/filiolae-game-day-public.pem")
        private_source.unlink(missing_ok=True)
        public_source.unlink(missing_ok=True)
        self.run(
            "keygen",
            [
                str(FILIOLAE),
                "anchor-keygen",
                "--private-key",
                str(private_source),
                "--public-key",
                str(public_source),
            ],
            check=True,
        )
        shutil.copyfile(private_source, PRIVATE_KEY)
        os.chown(PRIVATE_KEY, witness.pw_uid, witness.pw_gid)
        os.chmod(PRIVATE_KEY, 0o600)
        shutil.copyfile(public_source, PUBLIC_KEY)
        os.chown(PUBLIC_KEY, 0, 0)
        os.chmod(PUBLIC_KEY, 0o644)
        private_source.unlink()
        public_source.unlink()

        DROPIN.parent.mkdir(parents=True, exist_ok=True)
        DROPIN.write_text(
            "[Service]\n"
            "ExecStart=\n"
            f"ExecStart={self.venv / 'bin/python'} {HARNESS_TARGET} %i\n"
            "Environment=FILIOLAE_ANCHOR_WITNESS_TIMEOUT_SECONDS=2\n"
        )
        os.chown(DROPIN, 0, 0)
        os.chmod(DROPIN, 0o644)
        self.run("daemon-reload", ["systemctl", "daemon-reload"], check=True)
        self.run(
            "systemd-verify",
            [
                "systemd-analyze",
                "verify",
                "/etc/systemd/system/filiolae-governed.slice",
                "/etc/systemd/system/filiolae-witness@.service",
                "/etc/systemd/system/filiolae-orchestrator@.service",
            ],
            check=True,
        )
        self.run(
            "systemd-security-witness",
            ["systemd-analyze", "security", "filiolae-witness@dummy.service", "--no-pager"],
        )
        self.run(
            "systemd-security-orchestrator",
            ["systemd-analyze", "security", "filiolae-orchestrator@dummy.service", "--no-pager"],
        )
        install_dir = self.evidence / "install"
        install_dir.mkdir(exist_ok=True)
        shutil.copy2(PUBLIC_KEY, install_dir / "ed25519-public.pem")
        for _, target, _ in installs:
            shutil.copy2(target, install_dir / target.name)
        shutil.copy2(DROPIN, install_dir / "50-game-day.conf")
        self.run(
            "install-sha256",
            [
                "sha256sum",
                *[str(path) for _, path, _ in installs],
                str(DROPIN),
                str(PUBLIC_KEY),
            ],
            check=True,
        )

    def setup_run(self, run_id: str, scenario: str) -> None:
        self.run_ids.append(run_id)
        self.run("provision", [str(PROVISIONER), "provision", run_id], scenario=scenario, check=True)
        orchestrator = pwd.getpwnam("filiolae-orchestrator")
        config = Path("/etc/filiolae/orchestrator") / f"{run_id}.toml"
        config.write_text("# game-day harness condition file\n")
        os.chown(config, 0, orchestrator.pw_gid)
        os.chmod(config, 0o640)
        charter = self.source / "examples" / "charter.demo.yaml"
        self.run(
            "enroll",
            [str(PROVISIONER), "enroll", run_id, str(charter)],
            scenario=scenario,
            check=True,
        )
        self.run(
            "validate-before-start",
            [str(PROVISIONER), "validate", run_id],
            scenario=scenario,
            check=True,
        )

    def start_run(self, run_id: str, scenario: str) -> dict[str, object]:
        orchestrator = self.service("orchestrator", run_id)
        started = self.run(
            "start-orchestrator",
            ["systemctl", "start", orchestrator],
            scenario=scenario,
        )
        if started.returncode != 0:
            self.capture_units(run_id, scenario, "start-failed")
            for role in ("witness", "orchestrator"):
                self.run(
                    f"start-failed-{role}-journal",
                    [
                        "journalctl",
                        "-u",
                        self.service(role, run_id),
                        "--no-pager",
                        "--output=short-iso-precise",
                    ],
                    scenario=scenario,
                )
            raise GameDayFailure(
                f"orchestrator start failed with {started.returncode}: {started.stderr.strip()}"
            )
        ready = RUN_ROOT / run_id / "game-day" / "ready.json"
        self.wait_path(ready)
        witness_uid = pwd.getpwnam("filiolae-witness").pw_uid
        orchestrator_uid = pwd.getpwnam("filiolae-orchestrator").pw_uid
        body = json.loads(ready.read_text())
        self.require(body["identity"]["uid"] == orchestrator_uid, "orchestrator harness UID mismatch")
        self.require(body["hostile_child"]["uid"] == orchestrator_uid, "hostile child UID mismatch")
        self.require(body["identity"]["sid"] != body["hostile_child"]["sid"], "hostile child did not setsid")
        self.require(witness_uid != orchestrator_uid, "witness/orchestrator UIDs equal")
        self.capture_units(run_id, scenario, "active")
        return body

    def command(self, run_id: str, sequence: int, action: str) -> None:
        path = RUN_ROOT / run_id / "game-day" / "commands" / f"{sequence:02d}.command"
        path.write_text(action + "\n")
        os.chown(path, pwd.getpwnam("filiolae-orchestrator").pw_uid, -1)

    def capture_units(self, run_id: str, scenario: str, label: str) -> None:
        for role in ("witness", "orchestrator"):
            unit = self.service(role, run_id)
            self.run(
                f"{label}-{role}-show",
                [
                    "systemctl",
                    "show",
                    unit,
                    "-p",
                    "Id",
                    "-p",
                    "User",
                    "-p",
                    "Group",
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
                    "-p",
                    "ExecMainStatus",
                    "-p",
                    "KillMode",
                    "-p",
                    "BindsTo",
                    "--no-pager",
                ],
                scenario=scenario,
            )

    def permission_checks(self, run_id: str, scenario: str) -> None:
        checks = (
            (
                "orchestrator-private-key-unreadable",
                ["runuser", "-u", "filiolae-orchestrator", "--", "test", "!", "-r", str(PRIVATE_KEY)],
            ),
            (
                "orchestrator-authoritative-unreadable",
                [
                    "runuser",
                    "-u",
                    "filiolae-orchestrator",
                    "--",
                    "test",
                    "!",
                    "-r",
                    str(ANCHOR_ROOT / run_id),
                ],
            ),
            (
                "orchestrator-witness-env-unreadable",
                [
                    "runuser",
                    "-u",
                    "filiolae-orchestrator",
                    "--",
                    "test",
                    "!",
                    "-r",
                    f"/etc/filiolae-witness/runs/{run_id}.env",
                ],
            ),
            (
                "witness-run-not-writable",
                ["runuser", "-u", "filiolae-witness", "--", "test", "!", "-w", str(RUN_ROOT / run_id)],
            ),
            (
                "witness-mirror-not-writable",
                [
                    "runuser",
                    "-u",
                    "filiolae-witness",
                    "--",
                    "test",
                    "!",
                    "-w",
                    str(MIRROR_ROOT / run_id),
                ],
            ),
        )
        for name, command in checks:
            self.run(name, command, scenario=scenario, check=True)
        self.run(
            "path-metadata",
            [
                "stat",
                "-Lc",
                "%n|%F|%a|%u|%g|%i",
                str(PRIVATE_KEY),
                str(PUBLIC_KEY),
                f"/run/filiolae-locks/{run_id}",
                f"/run/filiolae-locks/{run_id}/ledger.lock",
                str(RUN_ROOT / run_id),
                str(ANCHOR_ROOT / run_id),
                str(MIRROR_ROOT / run_id),
            ],
            scenario=scenario,
            check=True,
        )

    def assert_child_in_cgroup(self, ready: dict[str, object], run_id: str) -> tuple[int, str]:
        child_pid = int(ready["hostile_child"]["pid"])
        self.require(Path(f"/proc/{child_pid}").is_dir(), "hostile child missing while service active")
        show = subprocess.run(
            ["systemctl", "show", self.service("orchestrator", run_id), "-p", "ControlGroup", "--value"],
            text=True,
            capture_output=True,
            check=True,
        )
        control_group = show.stdout.strip()
        child_cgroup = Path(f"/proc/{child_pid}/cgroup").read_text()
        self.require(control_group in child_cgroup, "hostile child is outside orchestrator cgroup")
        return child_pid, control_group

    def assert_cgroup_gone_or_empty(self, control_group: str) -> None:
        directory = Path("/sys/fs/cgroup") / control_group.lstrip("/")
        processes = directory / "cgroup.procs"
        remaining = processes.read_text().split() if processes.is_file() else []
        self.require(not remaining, f"service cgroup retained processes: {remaining}")

    def baseline(self) -> None:
        scenario = "S1"
        run_id = "gd-baseline"
        self.setup_run(run_id, scenario)
        self.permission_checks(run_id, "S0")
        ready = self.start_run(run_id, scenario)
        child_pid, control_group = self.assert_child_in_cgroup(ready, run_id)
        self.command(run_id, 1, "approve")
        result = self.wait_result(RUN_ROOT / run_id / "game-day" / "approve-1-result.json")
        self.require(result.get("ok") is True, f"baseline promotion failed: {result}")
        self.require((RUN_ROOT / run_id / "game-day" / "load-called.json").is_file(), "load callback absent")
        events = self.ledger_events(run_id)
        self.require(events.count("gate.approved") == 1, f"unexpected approvals: {events}")
        self.require(events.count("policy.promoted") == 1, f"unexpected promotions: {events}")
        self.verify_run(run_id, scenario, require_current=True)
        self.capture_units(run_id, scenario, "before-stop")
        self.run(
            "stop-baseline",
            ["systemctl", "stop", self.service("orchestrator", run_id), self.service("witness", run_id)],
            scenario=scenario,
            timeout=40,
            check=True,
        )
        self.require(not Path(f"/proc/{child_pid}").exists(), "setsid child survived normal cgroup stop")
        self.assert_cgroup_gone_or_empty(control_group)
        self.scenarios[scenario] = {"passed": True, "run_id": run_id, "events": events}
        self.collect_run(run_id, scenario)

    def witness_crash(self) -> None:
        scenario = "S2"
        run_id = "gd-witness-crash"
        self.setup_run(run_id, scenario)
        ready = self.start_run(run_id, scenario)
        child_pid, control_group = self.assert_child_in_cgroup(ready, run_id)
        failure_at = utc_now()
        self.run(
            "kill-witness",
            ["systemctl", "kill", "-s", "SIGKILL", self.service("witness", run_id)],
            scenario=scenario,
            check=True,
        )
        orchestrator_state = self.wait_not_active(self.service("orchestrator", run_id))
        witness_state = self.wait_not_active(self.service("witness", run_id))
        self.require(not Path(f"/proc/{child_pid}").exists(), "setsid child survived witness crash")
        self.assert_cgroup_gone_or_empty(control_group)
        events = self.ledger_events(run_id)
        self.require(
            "gate.approved" not in events and "policy.promoted" not in events,
            f"post-crash authority: {events}",
        )
        self.require(
            not (RUN_ROOT / run_id / "game-day" / "load-called.json").exists(),
            "load callback ran after witness crash",
        )
        self.capture_units(run_id, scenario, "after-crash")
        self.scenarios[scenario] = {
            "passed": True,
            "run_id": run_id,
            "failure_at": failure_at,
            "orchestrator_state": orchestrator_state,
            "witness_state": witness_state,
            "events": events,
        }
        self.collect_run(run_id, scenario)

    def hung_witness(self) -> None:
        scenario = "S3"
        run_id = "gd-witness-hang"
        self.setup_run(run_id, scenario)
        ready = self.start_run(run_id, scenario)
        child_pid, control_group = self.assert_child_in_cgroup(ready, run_id)
        self.run(
            "stop-witness-process",
            ["systemctl", "kill", "-s", "SIGSTOP", self.service("witness", run_id)],
            scenario=scenario,
            check=True,
        )
        self.command(run_id, 1, "approve")
        first = self.wait_result(
            RUN_ROOT / run_id / "game-day" / "approve-1-result.json",
            timeout=30,
        )
        self.require(first.get("ok") is False, f"hung witness unexpectedly approved: {first}")
        self.require((RUN_ROOT / run_id / "control" / "filiolae" / "freeze.json").is_file(), "freeze absent")
        self.require(
            not (RUN_ROOT / run_id / "game-day" / "load-called.json").exists(),
            "load callback ran while witness hung",
        )
        events_before = self.ledger_events(run_id)
        self.require(
            "tripwire.fired" in events_before and "gate.denied" in events_before,
            f"denial absent: {events_before}",
        )
        self.verify_run(run_id, scenario, require_current=False)

        self.run(
            "continue-witness-process",
            ["systemctl", "kill", "-s", "SIGCONT", self.service("witness", run_id)],
            scenario=scenario,
            check=True,
        )
        time.sleep(0.25)
        self.command(run_id, 2, "reconcile")
        reconcile_result = self.wait_result(
            RUN_ROOT / run_id / "game-day" / "reconcile-1-result.json",
            timeout=15,
        )
        self.require(reconcile_result.get("ok") is True, f"reconciliation failed: {reconcile_result}")
        self.verify_run(run_id, scenario, require_current=True)
        self.command(run_id, 3, "approve")
        second = self.wait_result(
            RUN_ROOT / run_id / "game-day" / "approve-2-result.json",
            timeout=20,
        )
        self.require(second.get("ok") is False, f"permanently frozen run approved: {second}")
        self.require(
            not (RUN_ROOT / run_id / "game-day" / "load-called.json").exists(),
            "load callback ran after permanent freeze",
        )
        events_after = self.ledger_events(run_id)
        self.require(
            "gate.approved" not in events_after and "policy.promoted" not in events_after,
            f"authority after freeze: {events_after}",
        )
        self.run(
            "stop-hang-run",
            ["systemctl", "stop", self.service("orchestrator", run_id), self.service("witness", run_id)],
            scenario=scenario,
            timeout=40,
            check=True,
        )
        self.require(not Path(f"/proc/{child_pid}").exists(), "setsid child survived hang cleanup")
        self.assert_cgroup_gone_or_empty(control_group)
        self.scenarios[scenario] = {
            "passed": True,
            "run_id": run_id,
            "first_result": first,
            "reconcile_result": reconcile_result,
            "second_result": second,
            "events_before_reconcile": events_before,
            "events_after": events_after,
        }
        self.collect_run(run_id, scenario)

    def startup_failure_case(self, case: str) -> dict[str, object]:
        scenario = "S4"
        run_id = f"gd-startup-{case}"
        self.setup_run(run_id, scenario)
        restore: tuple[Path, Path] | None = None
        instance_dropin: Path | None = None
        if case == "key":
            missing = PRIVATE_KEY.with_suffix(".pem.missing")
            PRIVATE_KEY.rename(missing)
            restore = (missing, PRIVATE_KEY)
        elif case == "lock":
            lock = Path(f"/run/filiolae-locks/{run_id}/ledger.lock")
            missing = lock.with_suffix(".lock.missing")
            lock.rename(missing)
            restore = (missing, lock)
        elif case == "enrollment":
            enrollment = ANCHOR_ROOT / run_id / "enrollment.json"
            missing = enrollment.with_suffix(".json.missing")
            enrollment.rename(missing)
            restore = (missing, enrollment)
        elif case == "socket":
            instance_dropin = Path(
                f"/etc/systemd/system/{self.service('witness', run_id)}.d/50-no-socket.conf"
            )
            instance_dropin.parent.mkdir(parents=True)
            instance_dropin.write_text("[Service]\nExecStart=\nExecStart=/usr/bin/sleep 30\n")
            os.chmod(instance_dropin, 0o644)
            self.run(
                "socket-fault-daemon-reload",
                ["systemctl", "daemon-reload"],
                scenario=scenario,
                check=True,
            )
        elif case == "config":
            config = Path(f"/etc/filiolae/orchestrator/{run_id}.toml")
            missing = config.with_suffix(".toml.missing")
            config.rename(missing)
            restore = (missing, config)
        else:
            raise AssertionError(case)

        start = self.run(
            f"start-missing-{case}",
            ["systemctl", "start", self.service("orchestrator", run_id)],
            scenario=scenario,
            timeout=20,
        )
        orchestrator_state = self.wait_not_active(self.service("orchestrator", run_id), timeout=25)
        witness_status = self.run(
            f"state-missing-{case}-witness",
            ["systemctl", "is-active", self.service("witness", run_id)],
            scenario=scenario,
        )
        witness_state = witness_status.stdout.strip()
        events = self.ledger_events(run_id)
        self.require(
            "gate.approved" not in events and "policy.promoted" not in events,
            f"startup failure {case} granted authority: {events}",
        )
        self.require(
            not (RUN_ROOT / run_id / "game-day" / "load-called.json").exists(),
            f"startup failure {case} ran load callback",
        )
        self.capture_units(run_id, scenario, f"missing-{case}")
        self.collect_run(run_id, scenario, suffix=case)
        self.run(
            f"stop-missing-{case}",
            ["systemctl", "stop", self.service("orchestrator", run_id), self.service("witness", run_id)],
            scenario=scenario,
        )
        if restore is not None:
            restore[0].rename(restore[1])
        if instance_dropin is not None:
            shutil.rmtree(instance_dropin.parent)
            self.run(
                "restore-socket-daemon-reload",
                ["systemctl", "daemon-reload"],
                scenario=scenario,
                check=True,
            )
        return {
            "case": case,
            "passed": True,
            "run_id": run_id,
            "start_returncode": start.returncode,
            "orchestrator_state": orchestrator_state,
            "witness_state": witness_state,
            "events": events,
        }

    def startup_failures(self) -> None:
        cases = [
            self.startup_failure_case(case) for case in ("key", "lock", "enrollment", "socket", "config")
        ]
        self.scenarios["S4"] = {"passed": True, "cases": cases}

    def verify_run(self, run_id: str, scenario: str, *, require_current: bool) -> None:
        ledger = RUN_ROOT / run_id / "control" / "filiolae" / "ledger.jsonl"
        artifacts = RUN_ROOT / run_id / "control" / "filiolae" / "artifacts"
        charter = Path(f"/etc/filiolae/orchestrator/{run_id}.charter.yaml")
        anchors = ANCHOR_ROOT / run_id
        enrollment = anchors / "enrollment.json"
        anchor_command = [
            str(FILIOLAE),
            "verify-anchors",
            str(ledger),
            "--artifact-root",
            str(artifacts),
            "--anchor-dir",
            str(anchors),
            "--public-key",
            str(PUBLIC_KEY),
        ]
        if not require_current:
            anchor_command.append("--allow-stale")
        self.run(
            f"verify-anchors-{'current' if require_current else 'allow-stale'}",
            anchor_command,
            scenario=scenario,
            check=True,
        )
        self.run(
            "audit",
            [
                str(FILIOLAE),
                "audit",
                str(ledger),
                "--artifact-root",
                str(artifacts),
                "--charter",
                str(charter),
                "--anchor-dir",
                str(anchors),
                "--anchor-public-key",
                str(PUBLIC_KEY),
                "--witness-enrollment",
                str(enrollment),
            ],
            scenario=scenario,
            check=require_current,
        )
        self.run(
            "explain-json",
            [
                str(FILIOLAE),
                "explain",
                str(RUN_ROOT / run_id),
                "--anchor-dir",
                str(anchors),
                "--anchor-public-key",
                str(PUBLIC_KEY),
                "--witness-enrollment",
                str(enrollment),
                "--json",
            ],
            scenario=scenario,
        )

    @staticmethod
    def reject_unsafe_tree(source: Path) -> None:
        for path in source.rglob("*"):
            info = path.lstat()
            if path.is_symlink() or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise GameDayFailure(f"unsafe evidence member: {path}")

    def collect_run(self, run_id: str, scenario: str, *, suffix: str | None = None) -> None:
        label = suffix or run_id
        destination = self.evidence / "scenarios" / scenario / label
        destination.mkdir(parents=True, exist_ok=True)
        for role in ("witness", "orchestrator"):
            unit = self.service(role, run_id)
            journal = self.run(
                f"collect-{label}-{role}-journal",
                ["journalctl", "-u", unit, "--no-pager", "--output=short-iso-precise"],
                scenario=scenario,
            )
            (destination / f"{role}.journal.txt").write_text(journal.stdout)
            cat = self.run(
                f"collect-{label}-{role}-unit",
                ["systemctl", "cat", unit, "--no-pager"],
                scenario=scenario,
            )
            (destination / f"{role}.unit.txt").write_text(cat.stdout)
        for name, source in (
            ("run", RUN_ROOT / run_id),
            ("authoritative", ANCHOR_ROOT / run_id),
            ("mirror", MIRROR_ROOT / run_id),
        ):
            if source.exists():
                self.reject_unsafe_tree(source)
                shutil.copytree(source, destination / name)
        atomic_json(destination / "ledger-events.json", self.ledger_events(run_id))

    def cleanup(self) -> dict[str, object]:
        cleanup_started = utc_now()
        for run_id in self.run_ids:
            self.run(
                f"cleanup-stop-{run_id}",
                [
                    "systemctl",
                    "stop",
                    self.service("orchestrator", run_id),
                    self.service("witness", run_id),
                ],
                scenario="S6",
                timeout=45,
            )
        for run_id in self.run_ids:
            for role in ("orchestrator", "witness"):
                self.run(
                    f"cleanup-{run_id}-{role}-journal",
                    [
                        "journalctl",
                        "-u",
                        self.service(role, run_id),
                        "--no-pager",
                        "--output=short-iso-precise",
                    ],
                    scenario="S6",
                )
        active = []
        for run_id in self.run_ids:
            for role in ("orchestrator", "witness"):
                unit = self.service(role, run_id)
                state = subprocess.run(
                    ["systemctl", "is-active", unit],
                    text=True,
                    capture_output=True,
                    check=False,
                ).stdout.strip()
                if state in {"active", "activating", "deactivating", "reloading"}:
                    active.append({"unit": unit, "state": state})
        PRIVATE_KEY.unlink(missing_ok=True)
        cgroup_scan = self.run(
            "cleanup-cgroup-tree",
            ["systemd-cgls", "--unit", "filiolae-governed.slice", "--all", "--no-pager"],
            scenario="S6",
        )
        cgroup_root = Path("/sys/fs/cgroup/filiolae-governed.slice")
        cgroup_processes = (
            {
                str(path.parent): path.read_text().split()
                for path in cgroup_root.rglob("cgroup.procs")
                if path.read_text().split()
            }
            if cgroup_root.is_dir()
            else {}
        )
        process_scan = self.run(
            "cleanup-process-scan",
            ["pgrep", "-a", "-f", "filiolae-containment-harness"],
            scenario="S6",
        )
        # pgrep can briefly see only itself; retain raw evidence and require no harness Python process.
        survivors = [
            line
            for line in process_scan.stdout.splitlines()
            if str(HARNESS_TARGET) in line and "python" in line
        ]
        result = {
            "started_at": cleanup_started,
            "completed_at": utc_now(),
            "active_units": active,
            "harness_survivors": survivors,
            "cgroup_scan_returncode": cgroup_scan.returncode,
            "cgroup_processes": cgroup_processes,
            "private_key_present": PRIVATE_KEY.exists(),
            "passed": not active and not survivors and not cgroup_processes and not PRIVATE_KEY.exists(),
        }
        atomic_json(self.evidence / "cleanup" / "cleanup-report.json", result)
        return result

    def execute(self) -> None:
        self.install()
        self.baseline()
        self.witness_crash()
        self.hung_witness()
        self.startup_failures()
        self.scenarios["S5"] = {
            "passed": None,
            "excluded": True,
            "reason": "deterministic lost-response relay not yet implemented; no timing-race claim",
        }

    def finalize(self, *, error: str | None, cleanup: dict[str, object]) -> bool:
        required = ("S1", "S2", "S3", "S4")
        passed = (
            error is None
            and cleanup.get("passed") is True
            and all(self.scenarios.get(name, {}).get("passed") is True for name in required)
        )
        self.scenarios["S0"] = {
            "passed": error is None and bool(self.scenarios.get("S1", {}).get("passed")),
            "note": "identity and permission checks executed during baseline setup",
        }
        self.scenarios["S6"] = cleanup
        report = {
            "schema": "filiolae.native-systemd-containment-game-day.v1",
            "started_at": self.started_at,
            "completed_at": utc_now(),
            "source_commit": self.run(
                "final-git-head",
                ["git", "-C", str(self.source), "rev-parse", "HEAD"],
                scenario="S6",
            ).stdout.strip(),
            "passed": passed,
            "error": error,
            "scenarios": self.scenarios,
            "commands": self.commands,
            "non_claims": [
                "production security",
                "actual boot persistence",
                "remote or WORM receipt retention",
                "trusted time",
                "evaluator isolation or candidate quality",
                "GPU device containment",
                "public release readiness",
            ],
        }
        atomic_json(self.evidence / "GAME-DAY-REPORT.json", report)
        # Keep the descriptive filename for compatibility and satisfy the evidence-package
        # contract with an identical canonical manifest.
        atomic_json(self.evidence / "MANIFEST.json", report)
        return passed


def usage() -> NoReturn:
    print(f"usage: {Path(sys.argv[0]).name} EVIDENCE_DIR SOURCE_ROOT VENV", file=sys.stderr)
    raise SystemExit(64)


def main() -> int:
    if len(sys.argv) != 4:
        usage()
    game = GameDay(Path(sys.argv[1]).absolute(), Path(sys.argv[2]).resolve(), Path(sys.argv[3]).resolve())
    error: str | None = None
    try:
        game.execute()
    except BaseException as exc:
        error = f"{type(exc).__name__}: {exc}"
    try:
        cleanup = game.cleanup()
    except BaseException as exc:
        cleanup = {"passed": False, "error": f"{type(exc).__name__}: {exc}"}
        if error is None:
            error = f"cleanup failed: {type(exc).__name__}: {exc}"
    passed = game.finalize(error=error, cleanup=cleanup)
    shutil.chown(game.evidence, user=os.environ.get("SUDO_USER") or "root", group=None)
    for path in game.evidence.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
        elif path.is_file():
            path.chmod(0o644)
    print(json.dumps(json.loads((game.evidence / "GAME-DAY-REPORT.json").read_text()), indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
