from __future__ import annotations

import datetime as dt
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).parents[1] / "ops" / "two-gpu-smoke" / "pod_controller.py"
SPEC = importlib.util.spec_from_file_location("two_gpu_smoke_pod_controller", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
pod_controller = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pod_controller
SPEC.loader.exec_module(pod_controller)


def completed(argv, stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


class ScriptedRun:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        if not self.responses:
            raise AssertionError(f"unexpected subprocess: {argv}")
        response = self.responses.pop(0)
        if callable(response):
            return response(argv, kwargs)
        if isinstance(response, subprocess.CompletedProcess):
            return response
        return completed(argv, stdout=json.dumps(response))


def test_status_uses_plain_json_and_requires_exact_id():
    pod_id = "2c92f9b8-5876-46b5-b783-8bf2c7a19bee"
    run = ScriptedRun(
        [
            {"pods": [{"id": pod_id, "status": "ACTIVE"}], "total_count": 1},
            {"id": pod_id, "status": "ACTIVE", "ssh": "root@203.0.113.8 -p 2222"},
        ]
    )
    client = pod_controller.PrimeClient(run=run)

    status = client.status_exact(pod_id)

    assert status["id"] == pod_id
    assert run.calls[0][0] == [
        "prime",
        "--plain",
        "pods",
        "list",
        "--limit",
        "100",
        "--offset",
        "0",
        "--output",
        "json",
    ]
    assert run.calls[1][0] == [
        "prime",
        "--plain",
        "pods",
        "status",
        pod_id,
        "--output",
        "json",
    ]
    assert all("create" not in argv for argv, _ in run.calls)
    assert all("api" not in " ".join(argv).lower() for argv, _ in run.calls)


def test_status_fails_closed_on_mismatched_response_id():
    requested = "2c92f9b8-5876-46b5-b783-8bf2c7a19bee"
    run = ScriptedRun(
        [
            {"pods": [{"id": requested}], "total_count": 1},
            {"id": "different-id", "status": "ACTIVE"},
        ]
    )
    client = pod_controller.PrimeClient(run=run)

    with pytest.raises(pod_controller.ControllerError, match="exactly match"):
        client.status_exact(requested)


def test_exact_lookup_paginates_without_accepting_prefix():
    exact = "abcdef00"
    run = ScriptedRun(
        [
            {"pods": [{"id": "abcdef00-extra"}], "total_count": 2},
            {"pods": [{"id": exact}], "total_count": 2},
        ]
    )
    client = pod_controller.PrimeClient(run=run, page_limit=1)

    assert client.active_exact(exact)["id"] == exact
    assert run.calls[1][0][run.calls[1][0].index("--offset") + 1] == "1"


def test_invalid_json_diagnostic_does_not_echo_stdout():
    secretish = "Bearer should-not-be-printed"
    run = ScriptedRun([completed([], stdout=secretish)])
    client = pod_controller.PrimeClient(run=run)

    with pytest.raises(pod_controller.ControllerError) as raised:
        client.active_exact("exact")
    assert "should-not-be-printed" not in str(raised.value)


@pytest.mark.parametrize(
    "value",
    [
        "root@host;touch /tmp/pwn -p 22",
        "root@host -p 70000",
        "-oProxyCommand=bad@host -p 22",
        None,
    ],
)
def test_ssh_connection_parser_rejects_unsafe_values(value):
    with pytest.raises(pod_controller.ControllerError):
        pod_controller.parse_connections(value)


def test_ssh_connection_parser_handles_single_and_multiple_nodes():
    single = pod_controller.parse_connections("root@203.0.113.9 -p 2200")
    assert single == [pod_controller.SSHConnection("root", "203.0.113.9", 2200)]
    multiple = pod_controller.parse_connections(["ubuntu@node-a.example -p 22", "root@[2001:db8::1] -p 2222"])
    assert len(multiple) == 2
    assert multiple[1].destination == "root@[2001:db8::1]"


class StatusClient:
    def __init__(self, pod_id, ssh_value):
        self.pod_id = pod_id
        self.ssh_value = ssh_value

    def status_exact(self, pod_id):
        assert pod_id == self.pod_id
        return {"id": pod_id, "ssh": self.ssh_value}


class SequencedStatusClient:
    def __init__(self, pod_id, ssh_values):
        self.pod_id = pod_id
        self.ssh_values = list(ssh_values)
        self.calls = 0

    def status_exact(self, pod_id):
        assert pod_id == self.pod_id
        self.calls += 1
        value = self.ssh_values.pop(0) if len(self.ssh_values) > 1 else self.ssh_values[0]
        return {"id": pod_id, "ssh": value}


def option_value(argv, prefix):
    return next(item for item in argv if item.startswith(prefix)).split("=", 1)[1]


def test_transport_waits_boundedly_for_new_pod_ssh_endpoint(tmp_path):
    pod_id = "pod-provisioning"
    identity = tmp_path / "id"
    identity.write_text("key")
    client = SequencedStatusClient(pod_id, ["N/A", "root@203.0.113.9 -p 2200"])
    sleeps = []
    transport = pod_controller.SSHTransport(
        client,
        identity,
        tmp_path / "known",
        ready_timeout=10,
        ready_poll_seconds=2,
        run=lambda argv, **kwargs: completed(argv),
        monotonic=lambda: 0,
        sleep=sleeps.append,
    )

    assert transport.ssh(pod_id, ["true"], None) == 0
    assert client.calls == 2
    assert sleeps == [2]


def test_transport_fails_closed_when_ssh_never_becomes_ready(tmp_path):
    pod_id = "pod-provisioning"
    identity = tmp_path / "id"
    identity.write_text("key")
    client = StatusClient(pod_id, "N/A")
    times = iter([0.0, 2.0])
    transport = pod_controller.SSHTransport(
        client,
        identity,
        tmp_path / "known",
        ready_timeout=1,
        ready_poll_seconds=0.1,
        monotonic=lambda: next(times),
        sleep=lambda _: None,
    )

    with pytest.raises(pod_controller.ControllerError, match="did not become ready within 1s"):
        transport.ssh(pod_id, ["true"], None)


def test_transport_accepts_first_key_then_requires_strict_pin(tmp_path):
    pod_id = "pod-exact-123"
    identity = tmp_path / "id"
    identity.write_text("not-a-real-private-key")
    known_hosts = tmp_path / "state" / "known_hosts"
    calls = []

    def fake_transport_run(argv, **kwargs):
        calls.append(list(argv))
        return completed(argv)

    transport = pod_controller.SSHTransport(
        StatusClient(pod_id, "root@203.0.113.9 -p 2200"),
        identity,
        known_hosts,
        run=fake_transport_run,
    )
    assert transport.ssh(pod_id, ["true"], None) == 0
    assert option_value(calls[-1], "StrictHostKeyChecking=") == "accept-new"
    alias = option_value(calls[-1], "HostKeyAlias=")
    assert option_value(calls[-1], "UserKnownHostsFile=") == str(known_hosts)
    assert "GlobalKnownHostsFile=/dev/null" in calls[-1]
    assert calls[-1][-1] == "true"
    assert known_hosts.stat().st_mode & 0o777 == 0o600

    known_hosts.write_text(f"{alias} ssh-ed25519 AAAATEST\n")
    assert transport.ssh(pod_id, ["hostname"], None) == 0
    assert option_value(calls[-1], "StrictHostKeyChecking=") == "yes"


def test_transport_rejects_ambiguous_multi_node_without_index(tmp_path):
    identity = tmp_path / "id"
    identity.write_text("key")
    client = StatusClient("pod", "root@node-a -p 22, root@node-b -p 22")
    transport = pod_controller.SSHTransport(client, identity, tmp_path / "known")

    with pytest.raises(pod_controller.ControllerError, match="multiple SSH"):
        transport.ssh("pod", [], None)


def test_multi_node_transport_uses_stable_distinct_alias_per_endpoint_slot(tmp_path):
    pod_id = "pod-multi"
    identity = tmp_path / "id"
    identity.write_text("key")
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        return completed(argv)

    client = StatusClient(pod_id, ["root@node-a -p 22", "root@node-b -p 22"])
    transport = pod_controller.SSHTransport(client, identity, tmp_path / "known", run=fake_run)
    assert transport.ssh(pod_id, ["true"], 0) == 0
    assert transport.ssh(pod_id, ["true"], 1) == 0
    aliases = [option_value(argv, "HostKeyAlias=") for argv in calls]
    assert aliases[0] != aliases[1]


@pytest.mark.parametrize("path", ["relative/file", "/root/../etc/passwd", "/root/a b", "/tmp/*"])
def test_transfer_rejects_ambiguous_remote_paths(path):
    with pytest.raises(pod_controller.ControllerError):
        pod_controller._validate_remote_path(path)


def test_upload_and_download_use_scp_argv_and_pinned_file(tmp_path):
    pod_id = "pod-transfer"
    identity = tmp_path / "id"
    identity.write_text("key")
    known = tmp_path / "known"
    local_source = tmp_path / "payload.json"
    local_source.write_text("{}")
    local_download = tmp_path / "result.json"
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        return completed(argv)

    transport = pod_controller.SSHTransport(
        StatusClient(pod_id, "root@host.example -p 2222"), identity, known, run=fake_run
    )
    assert transport.upload(pod_id, local_source, "/root/payload.json", False, None) == 0
    assert calls[-1][0] == "scp"
    assert calls[-1][-3:] == ["--", str(local_source), "root@host.example:/root/payload.json"]
    assert transport.download(pod_id, "/root/result.json", local_download, False, None) == 0
    assert calls[-1][-3:] == ["--", "root@host.example:/root/result.json", str(local_download)]
    assert all("shell" not in kwargs for _, kwargs in [])


class TerminationClient:
    def __init__(self, active, history_sequence):
        self.active = active
        self.history_sequence = list(history_sequence)
        self.terminate_calls = []

    def active_exact(self, pod_id):
        return self.active

    def history_exact(self, pod_id):
        if self.history_sequence:
            return self.history_sequence.pop(0)
        return None

    def request_terminate(self, pod_id):
        self.terminate_calls.append(pod_id)


def test_terminate_requires_yes_before_any_destructive_call():
    client = TerminationClient({"id": "pod", "status": "ACTIVE"}, [])
    with pytest.raises(pod_controller.ControllerError, match="--yes"):
        pod_controller.terminate_exact(client, "pod", False, 1, 0.1)
    assert client.terminate_calls == []


def test_terminate_is_idempotent_for_history_exact_match():
    client = TerminationClient(None, [{"id": "pod"}])
    result = pod_controller.terminate_exact(client, "pod", True, 1, 0.1)
    assert result == "already-terminated"
    assert client.terminate_calls == []


def test_terminate_refuses_unknown_exact_id():
    client = TerminationClient(None, [None])
    with pytest.raises(pod_controller.ControllerError, match="refusing"):
        pod_controller.terminate_exact(client, "typo", True, 1, 0.1)
    assert client.terminate_calls == []


def test_terminate_passes_yes_and_confirms_with_bounded_poll():
    pod_id = "pod"
    run = ScriptedRun(
        [
            {"pods": [{"id": pod_id, "status": "ACTIVE"}], "total_count": 1},
            "terminate-ok",
            {"history": [{"id": pod_id}], "total_count": 1},
        ]
    )

    def normalize(argv, kwargs):
        return completed(argv, stdout="terminated")

    run.responses[1] = normalize
    client = pod_controller.PrimeClient(run=run)
    result = pod_controller.terminate_exact(client, pod_id, True, 10, 1)

    assert result == "terminated"
    assert run.calls[1][0] == ["prime", "--plain", "pods", "terminate", pod_id, "--yes"]


def test_termination_confirmation_times_out_bounded():
    client = TerminationClient({"id": "pod", "status": "DELETING"}, [None, None, None])
    ticks = iter([0.0, 0.0, 1.0, 1.0, 2.0])
    sleeps = []
    with pytest.raises(pod_controller.ControllerError, match="not confirmed"):
        pod_controller.terminate_exact(
            client,
            "pod",
            True,
            wait_seconds=1,
            poll_seconds=0.5,
            sleep=sleeps.append,
            monotonic=lambda: next(ticks),
        )
    assert client.terminate_calls == []
    assert sleeps and max(sleeps) <= 0.5


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-08-13 21:44:46 UTC", dt.datetime(2026, 8, 13, 21, 44, 46, tzinfo=dt.UTC)),
        ("2026-08-13T21:44:46Z", dt.datetime(2026, 8, 13, 21, 44, 46, tzinfo=dt.UTC)),
        (
            "2026-08-13T17:44:46-04:00",
            dt.datetime(2026, 8, 13, 21, 44, 46, tzinfo=dt.UTC),
        ),
    ],
)
def test_parse_created_at_accepts_prime_cli_and_iso_formats(raw, expected):
    assert pod_controller._parse_created_at(raw) == expected


def test_ttl_guard_does_not_terminate_before_expiry():
    now = dt.datetime(2026, 8, 11, 12, 0, tzinfo=dt.UTC)
    created = (now - dt.timedelta(minutes=5)).isoformat()
    client = TerminationClient({"id": "pod", "status": "ACTIVE", "created_at": created}, [])

    result = pod_controller.ttl_terminate(
        client,
        "pod",
        ttl_seconds=600,
        confirmed=False,
        wait_seconds=10,
        poll_seconds=1,
        now=now,
    )

    assert result["result"] == "not-expired"
    assert result["remaining_seconds"] == 300
    assert client.terminate_calls == []


def test_atomic_state_is_owner_only_and_replaces_complete_json(tmp_path):
    state_dir = tmp_path / "state"
    target = pod_controller.write_state_atomic(
        state_dir, "pod-exact", "deadline", "scheduled", deadline="2026-08-11T12:00:00Z"
    )
    first = json.loads(target.read_text())
    assert first["pod_id"] == "pod-exact"
    assert target.stat().st_mode & 0o777 == 0o600
    assert state_dir.stat().st_mode & 0o777 == 0o700

    same = pod_controller.write_state_atomic(state_dir, "pod-exact", "deadline", "terminated")
    assert same == target
    assert json.loads(target.read_text())["state"] == "terminated"
    assert list(state_dir.glob("*.tmp")) == []


def test_deadline_reaper_waits_then_terminates_and_records_state(tmp_path):
    pod_id = "pod-deadline"
    client = TerminationClient(
        {"id": pod_id, "status": "ACTIVE"},
        [{"id": pod_id}],
    )
    current = dt.datetime(2026, 8, 11, 12, 0, tzinfo=dt.UTC)
    deadline = current + dt.timedelta(seconds=10)
    clock = iter([current, deadline])
    sleeps = []

    result = pod_controller.deadline_reap(
        client,
        pod_id,
        deadline,
        True,
        10,
        1,
        tmp_path / "state",
        now=lambda: next(clock),
        sleep=sleeps.append,
    )

    assert result == "terminated"
    assert sleeps == [10.0]
    assert client.terminate_calls == [pod_id]
    state_path = pod_controller._state_path(tmp_path / "state", pod_id, "deadline")
    assert json.loads(state_path.read_text())["state"] == "terminated"


def test_guard_runs_local_argv_and_terminates_in_finally(tmp_path):
    pod_id = "pod-guard"
    client = TerminationClient(
        {"id": pod_id, "status": "ACTIVE"},
        [{"id": pod_id}],
    )
    result = pod_controller.guard_command(
        client,
        pod_id,
        [sys.executable, "-c", "raise SystemExit(7)"],
        max_seconds=10,
        confirmed=True,
        wait_seconds=10,
        poll_seconds=1,
        state_dir=tmp_path / "state",
    )
    assert result == 7
    assert client.terminate_calls == [pod_id]
    state_path = pod_controller._state_path(tmp_path / "state", pod_id, "guard")
    state = json.loads(state_path.read_text())
    assert state["state"] == "terminated"
    assert state["command_exit"] == 7
    assert "command" not in state  # commands may themselves contain secrets


def test_guard_launch_failure_still_terminates_exact_pod(tmp_path, monkeypatch: pytest.MonkeyPatch):
    pod_id = "pod-launch-failure"
    client = TerminationClient({"id": pod_id, "status": "ACTIVE"}, [{"id": pod_id}])

    def fail_launch(*args, **kwargs):
        raise OSError("expected test launch failure")

    monkeypatch.setattr(pod_controller.subprocess, "Popen", fail_launch)
    with pytest.raises(pod_controller.ControllerError, match="could not be launched"):
        pod_controller.guard_command(client, pod_id, ["missing-command"], 10, True, 10, 1, tmp_path / "state")
    assert client.terminate_calls == [pod_id]


def test_guard_signal_before_spawn_skips_command_and_terminates(tmp_path, monkeypatch: pytest.MonkeyPatch):
    pod_id = "pod-prelaunch-signal"
    client = TerminationClient({"id": pod_id, "status": "ACTIVE"}, [{"id": pod_id}])
    triggered = False

    def fake_signal(_signum, handler):
        nonlocal triggered
        if callable(handler) and not triggered:
            triggered = True
            handler(pod_controller.signal.SIGTERM, None)

    monkeypatch.setattr(pod_controller.signal, "signal", fake_signal)
    monkeypatch.setattr(
        pod_controller.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("command must not launch after a prelaunch signal"),
    )
    result = pod_controller.guard_command(client, pod_id, ["never-run"], 10, True, 10, 1, tmp_path / "state")
    assert result == 128 + pod_controller.signal.SIGTERM
    assert client.terminate_calls == [pod_id]


def test_guard_requires_confirmation_before_launch_or_state(tmp_path):
    client = TerminationClient({"id": "pod", "status": "ACTIVE"}, [])
    with pytest.raises(pod_controller.ControllerError, match="--yes"):
        pod_controller.guard_command(
            client,
            "pod",
            [sys.executable, "-c", "pass"],
            10,
            False,
            10,
            1,
            tmp_path / "state",
        )
    assert not (tmp_path / "state").exists()
    assert client.terminate_calls == []


def test_parser_requires_explicit_pod_id_option():
    parser = pod_controller.build_parser()
    parsed = parser.parse_args(["terminate", "--pod-id", "full-id", "--yes"])
    assert parsed.pod_id == "full-id"
    with pytest.raises(SystemExit):
        parser.parse_args(["terminate", "full-id", "--yes"])


def test_unsafe_pod_id_is_rejected_before_any_prime_cli_call():
    run = ScriptedRun([])
    client = pod_controller.PrimeClient(run=run)
    for unsafe in ("--help", "pod/id", "pod id", "pod\nother", ""):
        with pytest.raises(pod_controller.ControllerError, match="safe characters"):
            client.active_exact(unsafe)
    assert run.calls == []


def test_cli_has_no_provision_or_api_key_surface():
    parser = pod_controller.build_parser()
    subparsers = next(action for action in parser._actions if action.dest == "operation")
    commands = set(subparsers.choices)
    assert "create" not in commands
    assert "provision" not in commands
    assert "api-key" not in parser.format_help().lower()
