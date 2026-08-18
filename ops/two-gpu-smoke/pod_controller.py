#!/usr/bin/env python3
"""Fail-closed controller for already-provisioned Prime Intellect pods.

This tool deliberately has no pod-creation operation. It invokes the Prime CLI
with argv arrays, parses only its JSON output, and never accepts or prints API
keys. SSH/SCP use a controller-owned TOFU known_hosts file: accept-new is used
only while the pod alias is unknown, then strict checking is required.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ControllerError(RuntimeError):
    """A safe, user-facing controller failure."""


class SSHNotReadyError(ControllerError):
    """The exact pod exists, but its provider SSH endpoint is not ready yet."""


@dataclass(frozen=True)
class SSHConnection:
    user: str
    host: str
    port: int

    @property
    def destination(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.user}@{host}"


_POD_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def _validate_pod_id(pod_id: str) -> str:
    if not _POD_ID_RE.fullmatch(pod_id):
        raise ControllerError("pod ID must be a full provider ID using safe characters")
    return pod_id


_SSH_RE = re.compile(
    r"^(?P<user>[A-Za-z_][A-Za-z0-9_.-]*)@"
    r"(?P<host>\[[0-9A-Fa-f:]+\]|[A-Za-z0-9_.:-]+)"
    r"(?:\s+-p\s+(?P<port>[0-9]{1,5}))?$"
)


def _json_object(raw: str, operation: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ControllerError(f"{operation} did not return valid JSON") from exc
    if not isinstance(value, dict):
        raise ControllerError(f"{operation} returned a non-object JSON value")
    return value


class PrimeClient:
    """A narrow Prime CLI adapter. There is intentionally no create method."""

    def __init__(
        self,
        prime_bin: str = "prime",
        timeout: float = 30.0,
        run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        page_limit: int = 100,
        max_pages: int = 20,
    ) -> None:
        if not prime_bin or "\x00" in prime_bin:
            raise ControllerError("invalid Prime CLI executable")
        self.prime_bin = prime_bin
        self.timeout = timeout
        self._run_impl = run
        self.page_limit = page_limit
        self.max_pages = max_pages

    def _run_json(self, args: Sequence[str], operation: str) -> dict[str, Any]:
        argv = [self.prime_bin, "--plain", *args]
        try:
            completed = self._run_impl(
                argv,
                check=False,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=self.timeout,
            )
        except FileNotFoundError as exc:
            raise ControllerError(f"Prime CLI not found: {self.prime_bin}") from exc
        except subprocess.TimeoutExpired as exc:
            raise ControllerError(f"{operation} timed out after {self.timeout:g}s") from exc
        if completed.returncode != 0:
            raise ControllerError(f"{operation} failed (exit {completed.returncode}); stderr withheld")
        return _json_object(completed.stdout, operation)

    def _paged_exact(
        self,
        pod_id: str,
        command: str,
        collection_key: str,
    ) -> dict[str, Any] | None:
        _validate_pod_id(pod_id)
        offset = 0
        for _ in range(self.max_pages):
            data = self._run_json(
                [
                    "pods",
                    command,
                    "--limit",
                    str(self.page_limit),
                    "--offset",
                    str(offset),
                    "--output",
                    "json",
                ],
                f"prime pods {command}",
            )
            items = data.get(collection_key)
            if not isinstance(items, list):
                raise ControllerError(f"prime pods {command} JSON lacks .{collection_key}[]")
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                    raise ControllerError(f"prime pods {command} returned an invalid pod record")
                if item["id"] == pod_id:
                    return item
            total = data.get("total_count")
            if not isinstance(total, int) or total < 0:
                raise ControllerError(f"prime pods {command} JSON has invalid total_count")
            offset += len(items)
            if offset >= total:
                return None
            if not items:
                raise ControllerError(f"prime pods {command} pagination made no progress")
        raise ControllerError(
            f"prime pods {command} exceeded the safety pagination bound; exact ID not resolved"
        )

    def active_exact(self, pod_id: str) -> dict[str, Any] | None:
        return self._paged_exact(pod_id, "list", "pods")

    def history_exact(self, pod_id: str) -> dict[str, Any] | None:
        return self._paged_exact(pod_id, "history", "history")

    def status_exact(self, pod_id: str) -> dict[str, Any]:
        if self.active_exact(pod_id) is None:
            if self.history_exact(pod_id) is not None:
                raise ControllerError(f"pod {pod_id} is already terminated")
            raise ControllerError(f"no active pod has exact ID {pod_id}")
        data = self._run_json(
            ["pods", "status", pod_id, "--output", "json"],
            "prime pods status",
        )
        if data.get("id") != pod_id:
            raise ControllerError("status response ID did not exactly match the requested pod")
        return data

    def request_terminate(self, pod_id: str) -> None:
        _validate_pod_id(pod_id)
        argv = [self.prime_bin, "--plain", "pods", "terminate", pod_id, "--yes"]
        try:
            completed = self._run_impl(
                argv,
                check=False,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=self.timeout,
            )
        except FileNotFoundError as exc:
            raise ControllerError(f"Prime CLI not found: {self.prime_bin}") from exc
        except subprocess.TimeoutExpired as exc:
            raise ControllerError(f"prime pods terminate timed out after {self.timeout:g}s") from exc
        if completed.returncode != 0:
            raise ControllerError(
                f"prime pods terminate failed (exit {completed.returncode}); stderr withheld"
            )


def parse_connections(value: Any) -> list[SSHConnection]:
    if value is None or (isinstance(value, str) and value.strip().upper() in {"", "N/A"}):
        raise SSHNotReadyError("pod SSH endpoint is not ready")
    if isinstance(value, list):
        raw_connections = value
    elif isinstance(value, str):
        # Prime CLI 0.6.x flattens a multi-node SSH list with comma-space.
        raw_connections = value.split(", ")
    else:
        raise ControllerError("pod status does not contain an SSH connection")
    connections: list[SSHConnection] = []
    for raw in raw_connections:
        if not isinstance(raw, str):
            raise ControllerError("pod status contains a malformed SSH connection")
        match = _SSH_RE.fullmatch(raw.strip())
        if not match:
            raise ControllerError("pod status contains an unsafe SSH connection string")
        host = match.group("host")
        if host.startswith("["):
            host = host[1:-1]
        port = int(match.group("port") or "22")
        if not 1 <= port <= 65535:
            raise ControllerError("pod status contains an invalid SSH port")
        connections.append(SSHConnection(match.group("user"), host, port))
    if not connections:
        raise ControllerError("pod status does not contain an SSH connection")
    return connections


def _pod_alias(pod_id: str, connection_index: int) -> str:
    _validate_pod_id(pod_id)
    digest = hashlib.sha256(f"{pod_id}\0{connection_index}".encode()).hexdigest()[:32]
    return f"prime-pod-{digest}"


def ensure_known_hosts(path: Path) -> None:
    path = path.expanduser().resolve(strict=False)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        parent_stat = path.parent.lstat()
        if not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != os.getuid():
            raise ControllerError("known_hosts parent must be an owner-controlled directory")
        os.chmod(path.parent, 0o700)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        os.close(fd)
        file_stat = path.lstat()
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_uid != os.getuid():
            raise ControllerError("known_hosts must be an owner-controlled regular file")
        os.chmod(path, 0o600)
    except OSError as exc:
        raise ControllerError(f"cannot safely initialize known_hosts at {path}") from exc


def known_alias_is_pinned(path: Path, alias: str) -> bool:
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("|"):
                    continue
                fields = stripped.split()
                if fields and alias in fields[0].split(","):
                    return True
    except OSError as exc:
        raise ControllerError(f"cannot read known_hosts at {path}") from exc
    return False


class SSHTransport:
    def __init__(
        self,
        client: PrimeClient,
        identity: Path,
        known_hosts: Path,
        connect_timeout: int = 15,
        ready_timeout: float = 600,
        ready_poll_seconds: float = 5,
        run: Callable[..., subprocess.CompletedProcess[Any]] = subprocess.run,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.client = client
        self.identity = identity.expanduser().resolve(strict=False)
        self.known_hosts = known_hosts.expanduser().resolve(strict=False)
        self.connect_timeout = connect_timeout
        self.ready_timeout = ready_timeout
        self.ready_poll_seconds = ready_poll_seconds
        self._run_impl = run
        self._monotonic = monotonic
        self._sleep = sleep

    def _connection(self, pod_id: str, connection_index: int | None) -> tuple[SSHConnection, int]:
        deadline = self._monotonic() + self.ready_timeout
        while True:
            status = self.client.status_exact(pod_id)
            try:
                connections = parse_connections(status.get("ssh"))
            except SSHNotReadyError as exc:
                remaining = deadline - self._monotonic()
                if remaining <= 0:
                    raise ControllerError(
                        f"pod SSH endpoint did not become ready within {self.ready_timeout:g}s"
                    ) from exc
                self._sleep(min(self.ready_poll_seconds, remaining))
                continue
            break
        if len(connections) > 1 and connection_index is None:
            raise ControllerError(
                "pod has multiple SSH endpoints; choose one explicitly with --connection-index"
            )
        index = 0 if connection_index is None else connection_index
        if index < 0 or index >= len(connections):
            raise ControllerError("SSH connection index is out of range")
        return connections[index], index

    def _options(self, pod_id: str, connection_index: int) -> list[str]:
        if not self.identity.is_file():
            raise ControllerError(f"SSH private key not found: {self.identity}")
        ensure_known_hosts(self.known_hosts)
        alias = _pod_alias(pod_id, connection_index)
        checking = "yes" if known_alias_is_pinned(self.known_hosts, alias) else "accept-new"
        return [
            "-F",
            "/dev/null",
            "-i",
            str(self.identity),
            "-o",
            "BatchMode=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ForwardX11=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "HashKnownHosts=no",
            "-o",
            "CheckHostIP=no",
            "-o",
            f"HostKeyAlias={alias}",
            "-o",
            f"StrictHostKeyChecking={checking}",
            "-o",
            f"ConnectTimeout={self.connect_timeout}",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=2",
        ]

    def ssh(self, pod_id: str, command: list[str], connection_index: int | None) -> int:
        connection, index = self._connection(pod_id, connection_index)
        argv = [
            "ssh",
            *self._options(pod_id, index),
            "-p",
            str(connection.port),
            connection.destination,
        ]
        if command:
            # OpenSSH sends one command string to the remote login shell. Quote each caller
            # argument so shell parsing reconstructs the requested argv without injection.
            argv.append(shlex.join(command))
        return self._run_impl(argv, check=False).returncode

    def upload(
        self,
        pod_id: str,
        local: Path,
        remote: str,
        recursive: bool,
        connection_index: int | None,
    ) -> int:
        local = local.expanduser().resolve(strict=False)
        if not local.exists():
            raise ControllerError(f"upload source does not exist: {local}")
        if local.is_dir() and not recursive:
            raise ControllerError("upload source is a directory; pass --recursive explicitly")
        _validate_remote_path(remote)
        connection, index = self._connection(pod_id, connection_index)
        argv = ["scp", *self._options(pod_id, index), "-P", str(connection.port)]
        if recursive:
            argv.append("-r")
        argv.extend(["--", str(local), f"{connection.destination}:{remote}"])
        return self._run_impl(argv, check=False).returncode

    def download(
        self,
        pod_id: str,
        remote: str,
        local: Path,
        recursive: bool,
        connection_index: int | None,
    ) -> int:
        _validate_remote_path(remote)
        local = local.expanduser().resolve(strict=False)
        if not local.parent.is_dir():
            raise ControllerError(f"download destination parent does not exist: {local.parent}")
        connection, index = self._connection(pod_id, connection_index)
        argv = ["scp", *self._options(pod_id, index), "-P", str(connection.port)]
        if recursive:
            argv.append("-r")
        argv.extend(["--", f"{connection.destination}:{remote}", str(local)])
        return self._run_impl(argv, check=False).returncode


def _validate_remote_path(value: str) -> None:
    # Restrict SCP operands to unambiguous absolute POSIX paths. This avoids
    # option, wildcard, traversal, and legacy remote-shell interpretation.
    if not value.startswith("/") or not re.fullmatch(r"[A-Za-z0-9._/+=,@%~-]+", value):
        raise ControllerError("remote path must be an absolute path using safe characters")
    if ".." in Path(value).parts:
        raise ControllerError("remote path must not contain parent traversal")


def _parse_created_at(value: Any) -> dt.datetime:
    if not isinstance(value, str):
        raise ControllerError("pod record has no created_at timestamp")
    if value.endswith(" UTC"):
        normalized = value.removesuffix(" UTC") + "+00:00"
    else:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ControllerError("pod record has an invalid created_at timestamp") from exc
    if parsed.tzinfo is None:
        raise ControllerError("pod created_at timestamp has no timezone")
    return parsed.astimezone(dt.UTC)


def terminate_exact(
    client: PrimeClient,
    pod_id: str,
    confirmed: bool,
    wait_seconds: float,
    poll_seconds: float,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> str:
    if not confirmed:
        raise ControllerError("termination requires the explicit --yes confirmation")
    active = client.active_exact(pod_id)
    if active is None:
        if client.history_exact(pod_id) is not None:
            return "already-terminated"
        raise ControllerError(f"refusing to terminate: exact pod ID {pod_id} was not found")

    status = str(active.get("status", "")).upper()
    if status not in {"DELETING", "TERMINATED"}:
        client.request_terminate(pod_id)

    deadline = monotonic() + wait_seconds
    while True:
        if client.history_exact(pod_id) is not None:
            return "terminated"
        current = client.active_exact(pod_id)
        if current is not None and str(current.get("status", "")).upper() == "TERMINATED":
            return "terminated"
        if monotonic() >= deadline:
            raise ControllerError(
                f"termination of exact pod ID {pod_id} was not confirmed within {wait_seconds:g}s"
            )
        sleep(min(poll_seconds, max(0.0, deadline - monotonic())))


def ttl_terminate(
    client: PrimeClient,
    pod_id: str,
    ttl_seconds: float,
    confirmed: bool,
    wait_seconds: float,
    poll_seconds: float,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    active = client.active_exact(pod_id)
    if active is None:
        if client.history_exact(pod_id) is not None:
            return {"id": pod_id, "result": "already-terminated"}
        raise ControllerError(f"exact pod ID {pod_id} was not found")
    created_at = _parse_created_at(active.get("created_at"))
    current = now or dt.datetime.now(dt.UTC)
    current = current.astimezone(dt.UTC)
    age = (current - created_at).total_seconds()
    if age < -60:
        raise ControllerError("pod created_at is unexpectedly in the future")
    if age < ttl_seconds:
        return {
            "id": pod_id,
            "result": "not-expired",
            "age_seconds": max(0, int(age)),
            "remaining_seconds": int(ttl_seconds - max(0, age)),
        }
    result = terminate_exact(client, pod_id, confirmed, wait_seconds, poll_seconds)
    return {"id": pod_id, "result": result, "age_seconds": int(age)}


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _iso_utc(value: dt.datetime | None = None) -> str:
    current = (value or _utc_now()).astimezone(dt.UTC)
    return current.isoformat().replace("+00:00", "Z")


def _state_path(state_dir: Path, pod_id: str, mode: str) -> Path:
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", mode):
        raise ControllerError("invalid controller state mode")
    digest = hashlib.sha256(pod_id.encode("utf-8")).hexdigest()
    return state_dir.expanduser().resolve(strict=False) / f"pod-{digest}-{mode}.json"


def write_state_atomic(state_dir: Path, pod_id: str, mode: str, state: str, **fields: Any) -> Path:
    """Write one pod's non-secret controller state via fsync + atomic replace."""
    directory = state_dir.expanduser().resolve(strict=False)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ControllerError("state directory must be owner-controlled")
    os.chmod(directory, 0o700)
    target = _state_path(directory, pod_id, mode)
    payload = {
        "version": 1,
        "pod_id": pod_id,
        "mode": mode,
        "state": state,
        "updated_at": _iso_utc(),
        **fields,
    }
    temporary: str | None = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".state-", suffix=".tmp", dir=directory)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        temporary = None
        os.chmod(target, 0o600)
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return target
    except OSError as exc:
        raise ControllerError(f"cannot atomically write controller state in {directory}") from exc
    finally:
        if temporary is not None:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)


def write_state_best_effort(
    state_dir: Path,
    pod_id: str,
    mode: str,
    state: str,
    **fields: Any,
) -> Path | None:
    """Retain non-secret diagnostics without ever blocking exact-ID termination."""
    try:
        return write_state_atomic(state_dir, pod_id, mode, state, **fields)
    except Exception:
        with contextlib.suppress(OSError):
            print("warning: controller state update failed; termination remains armed", file=sys.stderr)
        return None


def parse_deadline(value: str) -> dt.datetime:
    """Parse an epoch-seconds or timezone-qualified ISO-8601 UTC deadline."""
    try:
        epoch = float(value)
    except ValueError:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            parsed = dt.datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise ControllerError("deadline must be epoch seconds or ISO-8601 with timezone") from exc
        if parsed.tzinfo is None:
            raise ControllerError("ISO-8601 deadline must include a timezone") from None
        return parsed.astimezone(dt.UTC)
    try:
        return dt.datetime.fromtimestamp(epoch, tz=dt.UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise ControllerError("deadline epoch is out of range") from exc


def deadline_reap(
    client: PrimeClient,
    pod_id: str,
    deadline: dt.datetime,
    confirmed: bool,
    wait_seconds: float,
    poll_seconds: float,
    state_dir: Path,
    now: Callable[[], dt.datetime] = _utc_now,
    sleep: Callable[[float], None] = time.sleep,
) -> str:
    if not confirmed:
        raise ControllerError("deadline termination requires the explicit --yes confirmation")
    if client.active_exact(pod_id) is None:
        if client.history_exact(pod_id) is not None:
            write_state_best_effort(state_dir, pod_id, "deadline", "already-terminated")
            return "already-terminated"
        raise ControllerError(f"deadline exact pod ID {pod_id} was not found")
    deadline = deadline.astimezone(dt.UTC)
    write_state_best_effort(state_dir, pod_id, "deadline", "scheduled", deadline=_iso_utc(deadline))
    while True:
        remaining = (deadline - now().astimezone(dt.UTC)).total_seconds()
        if remaining <= 0:
            break
        sleep(min(30.0, remaining))
    write_state_best_effort(state_dir, pod_id, "deadline", "terminating", deadline=_iso_utc(deadline))
    try:
        result = terminate_exact(client, pod_id, True, wait_seconds=wait_seconds, poll_seconds=poll_seconds)
    except Exception as exc:
        write_state_best_effort(
            state_dir,
            pod_id,
            "deadline",
            "error",
            deadline=_iso_utc(deadline),
            error=type(exc).__name__,
        )
        raise
    write_state_best_effort(state_dir, pod_id, "deadline", result, deadline=_iso_utc(deadline))
    return result


def _stop_process_group(process: subprocess.Popen[Any], grace_seconds: float = 5.0) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=grace_seconds)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()


def guard_command(
    client: PrimeClient,
    pod_id: str,
    command: list[str],
    max_seconds: float,
    confirmed: bool,
    wait_seconds: float,
    poll_seconds: float,
    state_dir: Path,
) -> int:
    """Run a local command and terminate the exact pod on every exit path."""
    if not confirmed:
        raise ControllerError("guard termination requires the explicit --yes confirmation")
    if not command:
        raise ControllerError("guard requires a command after --")
    if client.active_exact(pod_id) is None:
        if client.history_exact(pod_id) is not None:
            raise ControllerError(f"guard pod {pod_id} is already terminated")
        raise ControllerError(f"guard exact pod ID {pod_id} was not found")
    write_state_best_effort(state_dir, pod_id, "guard", "starting", max_seconds=max_seconds)

    process: subprocess.Popen[Any] | None = None
    prior_handlers: dict[int, Any] = {}
    signal_seen: list[int] = []

    def request_stop(signum: int, _frame: Any) -> None:
        signal_seen.append(signum)
        if process is not None:
            _stop_process_group(process)

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        prior_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, request_stop)

    command_result = 1
    reason = "completed"
    launch_error: OSError | None = None
    termination_error: Exception | None = None
    try:
        if signal_seen:
            reason = f"signal-{signal_seen[-1]}"
            command_result = 128 + signal_seen[-1]
        else:
            try:
                process = subprocess.Popen(command, start_new_session=True)
            except OSError as exc:
                launch_error = exc
                reason = "command-launch-error"
            else:
                write_state_best_effort(
                    state_dir,
                    pod_id,
                    "guard",
                    "running",
                    pid=process.pid,
                    max_seconds=max_seconds,
                )
                if signal_seen:
                    _stop_process_group(process)
                try:
                    command_result = process.wait(timeout=max_seconds)
                except subprocess.TimeoutExpired:
                    reason = "timeout"
                    _stop_process_group(process)
                    command_result = 124
                if signal_seen:
                    reason = f"signal-{signal_seen[-1]}"
                    command_result = 128 + signal_seen[-1]
    finally:
        if process is not None:
            _stop_process_group(process)
        for signum, handler in prior_handlers.items():
            signal.signal(signum, handler)
        write_state_best_effort(
            state_dir,
            pod_id,
            "guard",
            "terminating",
            reason=reason,
            command_exit=command_result,
        )
        try:
            result = terminate_exact(client, pod_id, True, wait_seconds, poll_seconds)
        except Exception as exc:
            termination_error = exc
            write_state_best_effort(
                state_dir,
                pod_id,
                "guard",
                "error",
                reason=reason,
                command_exit=command_result,
                error=type(exc).__name__,
            )
        else:
            write_state_best_effort(
                state_dir,
                pod_id,
                "guard",
                result,
                reason=reason,
                command_exit=command_result,
            )
    if termination_error is not None:
        if launch_error is not None:
            raise ControllerError(
                "guard command launch and pod termination both failed"
            ) from termination_error
        raise ControllerError("guard could not confirm exact-ID pod termination") from termination_error
    if launch_error is not None:
        raise ControllerError("guard command could not be launched") from launch_error
    return command_result


def _bounded_float(minimum: float, maximum: float) -> Callable[[str], float]:
    def parse(value: str) -> float:
        try:
            result = float(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("must be a number") from exc
        if not minimum <= result <= maximum:
            raise argparse.ArgumentTypeError(f"must be between {minimum:g} and {maximum:g}")
        return result

    return parse


def _pod_id_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--pod-id", required=True, help="full exact pod ID; names/prefixes are rejected")


def _termination_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--yes", action="store_true", help="required explicit destructive confirmation")
    parser.add_argument("--wait-seconds", type=_bounded_float(1, 900), default=120.0)
    parser.add_argument("--poll-seconds", type=_bounded_float(0.1, 30), default=5.0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prime-bin", default="prime")
    parser.add_argument("--prime-timeout", type=_bounded_float(1, 300), default=30.0)
    parser.add_argument(
        "--identity",
        type=Path,
        default=Path(os.environ.get("PRIME_SSH_KEY_PATH", "~/.ssh/id_rsa")),
        help="local SSH private key (never uploaded by this controller)",
    )
    parser.add_argument(
        "--known-hosts",
        type=Path,
        default=Path("~/.prime/two-gpu-smoke/known_hosts"),
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path("~/.prime/two-gpu-smoke/state"),
        help="owner-only directory for atomic guard/deadline state",
    )
    parser.add_argument("--connect-timeout", type=int, choices=range(1, 61), default=15)
    parser.add_argument(
        "--ssh-ready-timeout",
        type=_bounded_float(1, 1800),
        default=600.0,
        help="bounded wait for a newly provisioned pod's SSH endpoint",
    )
    parser.add_argument(
        "--ssh-ready-poll-seconds",
        type=_bounded_float(0.1, 30),
        default=5.0,
    )
    sub = parser.add_subparsers(dest="operation", required=True)

    status = sub.add_parser("status", help="show status for one exact active pod ID")
    _pod_id_option(status)

    ssh = sub.add_parser("ssh", help="connect or run a remote command")
    _pod_id_option(ssh)
    ssh.add_argument("--connection-index", type=int)
    ssh.add_argument("command", nargs=argparse.REMAINDER)

    for name in ("upload", "download"):
        transfer = sub.add_parser(name, help=f"SCP {name} through the pinned transport")
        _pod_id_option(transfer)
        if name == "upload":
            transfer.add_argument("--local", required=True, type=Path)
            transfer.add_argument("--remote", required=True)
        else:
            transfer.add_argument("--remote", required=True)
            transfer.add_argument("--local", required=True, type=Path)
        transfer.add_argument("--recursive", action="store_true")
        transfer.add_argument("--connection-index", type=int)

    terminate = sub.add_parser("terminate", help="idempotently terminate one exact pod ID")
    _pod_id_option(terminate)
    _termination_options(terminate)

    ttl = sub.add_parser("ttl-terminate", help="one-shot age-based TTL check and termination")
    _pod_id_option(ttl)
    ttl.add_argument("--ttl-seconds", type=_bounded_float(1, 2_592_000), required=True)
    _termination_options(ttl)

    deadline = sub.add_parser("deadline", help="wait until UTC/epoch deadline, then terminate")
    _pod_id_option(deadline)
    deadline.add_argument("--deadline", required=True, help="ISO-8601 with timezone or epoch seconds")
    _termination_options(deadline)

    guard = sub.add_parser("guard", help="run a command and always terminate its exact pod")
    _pod_id_option(guard)
    guard.add_argument("--max-seconds", type=_bounded_float(1, 2_592_000), required=True)
    _termination_options(guard)
    guard.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    client = PrimeClient(args.prime_bin, args.prime_timeout)
    try:
        if args.operation == "status":
            print(json.dumps(client.status_exact(args.pod_id), sort_keys=True))
            return 0
        if args.operation in {"ssh", "upload", "download"}:
            transport = SSHTransport(
                client,
                args.identity,
                args.known_hosts,
                args.connect_timeout,
                args.ssh_ready_timeout,
                args.ssh_ready_poll_seconds,
            )
            if args.operation == "ssh":
                command = args.command
                if command[:1] == ["--"]:
                    command = command[1:]
                return transport.ssh(args.pod_id, command, args.connection_index)
            if args.operation == "upload":
                return transport.upload(
                    args.pod_id, args.local, args.remote, args.recursive, args.connection_index
                )
            return transport.download(
                args.pod_id, args.remote, args.local, args.recursive, args.connection_index
            )
        if args.operation == "terminate":
            result = terminate_exact(client, args.pod_id, args.yes, args.wait_seconds, args.poll_seconds)
            print(json.dumps({"id": args.pod_id, "result": result}, sort_keys=True))
            return 0
        if args.operation == "ttl-terminate":
            result = ttl_terminate(
                client, args.pod_id, args.ttl_seconds, args.yes, args.wait_seconds, args.poll_seconds
            )
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.operation == "deadline":
            result = deadline_reap(
                client,
                args.pod_id,
                parse_deadline(args.deadline),
                args.yes,
                args.wait_seconds,
                args.poll_seconds,
                args.state_dir,
            )
            print(json.dumps({"id": args.pod_id, "result": result}, sort_keys=True))
            return 0
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        return guard_command(
            client,
            args.pod_id,
            command,
            args.max_seconds,
            args.yes,
            args.wait_seconds,
            args.poll_seconds,
            args.state_dir,
        )
    except ControllerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
