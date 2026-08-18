"""External fail-closed process-group supervisor.

The READY/GO bootstrap closes the precheck/exec race for the governed target.
A POSIX process group remains a CPU-demo boundary, not a hostile sandbox: a child
that can call ``setsid`` can escape. Production deployment must add a protected
credential domain and cgroup/service-manager kill boundary.
"""

from __future__ import annotations

import os
import select
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import FrameType

from .freeze import FreezeController


class SupervisorError(RuntimeError):
    pass


@dataclass(frozen=True)
class SupervisorResult:
    returncode: int
    reason: str
    pid: int
    pgid: int
    term_sent: bool
    kill_sent: bool
    elapsed_seconds: float
    signal_received: int | None = None


class ProcessGroupSupervisor:
    """Run an argv vector in a dedicated session and police its process group."""

    def __init__(
        self,
        freezer: FreezeController,
        *,
        poll_interval: float = 0.05,
        term_grace_seconds: float = 2.0,
        ready_timeout_seconds: float = 10.0,
        freeze_on_nonzero: bool = True,
    ) -> None:
        if poll_interval <= 0 or term_grace_seconds < 0 or ready_timeout_seconds <= 0:
            raise ValueError("supervisor timing values are invalid")
        self.freezer = freezer
        self.poll_interval = poll_interval
        self.term_grace_seconds = term_grace_seconds
        self.ready_timeout_seconds = ready_timeout_seconds
        self.freeze_on_nonzero = freeze_on_nonzero

    @staticmethod
    def _group_exists(pgid: int) -> bool:
        if pgid <= 1:
            raise SupervisorError(f"unsafe process group id: {pgid}")
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def _terminate_group(self, process: subprocess.Popen[bytes], pgid: int) -> tuple[bool, bool]:
        term_sent = False
        kill_sent = False
        if self._group_exists(pgid):
            try:
                os.killpg(pgid, signal.SIGTERM)
                term_sent = True
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + self.term_grace_seconds
        while self._group_exists(pgid) and time.monotonic() < deadline:
            time.sleep(min(self.poll_interval, max(0.0, deadline - time.monotonic())))
        if self._group_exists(pgid):
            try:
                os.killpg(pgid, signal.SIGKILL)
                kill_sent = True
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=max(1.0, self.term_grace_seconds))
        except subprocess.TimeoutExpired as exc:
            raise SupervisorError(f"process-group leader did not exit after SIGKILL: {process.pid}") from exc
        return term_sent, kill_sent

    @contextmanager
    def _signal_latch(self) -> Iterator[list[int | None]]:
        received: list[int | None] = [None]
        if threading.current_thread() is not threading.main_thread():
            yield received
            return
        watched = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
        previous = {item: signal.getsignal(item) for item in watched}

        def handler(signum: int, frame: FrameType | None) -> None:
            del frame
            received[0] = signum

        try:
            for item in watched:
                signal.signal(item, handler)
            yield received
        finally:
            for item, old_handler in previous.items():
                signal.signal(item, old_handler)

    def _wait_for_ready(
        self,
        process: subprocess.Popen[bytes],
        ready_fd: int,
        signal_latch: list[int | None],
    ) -> bytes:
        deadline = time.monotonic() + self.ready_timeout_seconds
        buffer = b""
        while time.monotonic() < deadline:
            if signal_latch[0] is not None:
                raise SupervisorError(f"supervisor received signal {signal_latch[0]} before exec")
            frozen = self.freezer.state()
            if frozen.frozen:
                raise SupervisorError(f"run froze before target exec: {frozen.reason}")
            if process.poll() is not None:
                raise SupervisorError(f"held bootstrap exited before READY: {process.returncode}")
            readable, _, _ = select.select(
                [ready_fd], [], [], min(self.poll_interval, max(0.0, deadline - time.monotonic()))
            )
            if readable:
                chunk = os.read(ready_fd, 64)
                if not chunk:
                    raise SupervisorError("held bootstrap closed READY pipe")
                buffer += chunk
                if b"\n" in buffer:
                    return buffer
        raise SupervisorError("held bootstrap READY timeout")

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: str | Path | None = None,
        env: Mapping[str, str] | None = None,
        stdout: int | None = None,
        stderr: int | None = None,
        before_release: Callable[[], None] | None = None,
    ) -> SupervisorResult:
        if not command:
            raise ValueError("supervised command is empty")
        started = time.monotonic()
        with self._signal_latch() as received_signal:
            initial = self.freezer.state()
            if initial.frozen:
                raise SupervisorError(f"refusing to start a frozen run: {initial.reason}")
            ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
            go_read, go_write = os.pipe2(os.O_CLOEXEC)
            child_env = dict(env) if env is not None else dict(os.environ)
            child_env["FILIOLAE_READY_FD"] = str(ready_write)
            child_env["FILIOLAE_GO_FD"] = str(go_read)
            process: subprocess.Popen[bytes] | None = None
            pgid = -1
            term_sent = False
            kill_sent = False
            reason = "process exited"
            try:
                process = subprocess.Popen(
                    [sys.executable, "-m", "filiolae._bootstrap", "--", *command],
                    cwd=cwd,
                    env=child_env,
                    stdout=stdout,
                    stderr=stderr,
                    start_new_session=True,
                    pass_fds=(ready_write, go_read),
                )
                pgid = process.pid
            except BaseException as exc:
                self.freezer.freeze(f"supervisor could not launch held bootstrap: {exc}")
                os.close(ready_read)
                os.close(go_write)
                raise
            finally:
                os.close(ready_write)
                os.close(go_read)
            assert process is not None
            try:
                ready = self._wait_for_ready(process, ready_read, received_signal)
                if ready != b"READY\n":
                    raise SupervisorError(f"invalid bootstrap READY message: {ready!r}")
                if os.getpgid(process.pid) != process.pid or os.getsid(process.pid) != process.pid:
                    raise SupervisorError(
                        "held bootstrap did not establish the expected session/process group"
                    )
                if before_release is not None:
                    before_release()
                post_spawn = self.freezer.state()
                if post_spawn.frozen:
                    raise SupervisorError(f"run froze before target exec: {post_spawn.reason}")
                if received_signal[0] is not None:
                    raise SupervisorError(f"supervisor received signal {received_signal[0]} before exec")
                os.write(go_write, b"G")
                os.close(go_write)
                go_write = -1
                while True:
                    frozen = self.freezer.state()
                    if frozen.frozen:
                        reason = f"freeze: {frozen.reason}"
                        term_sent, kill_sent = self._terminate_group(process, pgid)
                        break
                    if received_signal[0] is not None:
                        self.freezer.freeze(
                            f"supervisor received signal {received_signal[0]}",
                            details={"pid": process.pid, "pgid": pgid},
                        )
                        reason = f"signal: {received_signal[0]}"
                        term_sent, kill_sent = self._terminate_group(process, pgid)
                        break
                    returncode = process.poll()
                    if returncode is not None:
                        if returncode != 0 and self.freeze_on_nonzero:
                            self.freezer.freeze(
                                f"governed command exited nonzero: {returncode}",
                                details={"pid": process.pid, "pgid": pgid},
                            )
                            reason = f"nonzero exit: {returncode}"
                        if self._group_exists(pgid):
                            extra_term, extra_kill = self._terminate_group(process, pgid)
                            term_sent = term_sent or extra_term
                            kill_sent = kill_sent or extra_kill
                            if returncode == 0:
                                self.freezer.freeze(
                                    "governed command left process-group descendants",
                                    details={"pid": process.pid, "pgid": pgid},
                                )
                                reason = "straggler process group"
                        break
                    time.sleep(self.poll_interval)
            except BaseException as exc:
                self.freezer.freeze(
                    f"supervisor launch/runtime failure: {type(exc).__name__}: {exc}",
                    details={"pid": process.pid, "pgid": pgid},
                )
                if process.poll() is None or self._group_exists(pgid):
                    extra_term, extra_kill = self._terminate_group(process, pgid)
                    term_sent = term_sent or extra_term
                    kill_sent = kill_sent or extra_kill
                raise
            finally:
                os.close(ready_read)
                if go_write >= 0:
                    os.close(go_write)
            returncode = process.returncode
            if returncode is None:
                raise SupervisorError("supervised process has no terminal return code")
            return SupervisorResult(
                returncode=returncode,
                reason=reason,
                pid=process.pid,
                pgid=pgid,
                term_sent=term_sent,
                kill_sent=kill_sent,
                elapsed_seconds=time.monotonic() - started,
                signal_received=received_signal[0],
            )
