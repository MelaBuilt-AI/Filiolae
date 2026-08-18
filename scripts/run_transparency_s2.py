#!/usr/bin/env python3
"""Execute bounded local Filiolae transparency S2 acceptance."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import contextlib
import hashlib
import http.client
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from filiolae.transparency import verify_checkpoint

ROOT = Path(__file__).parents[1]
S2 = ROOT / "interop" / "s2"
TRUST = S2 / "synthetic-trust.json"
MEDIA_TYPE = "application/vnd.filiolae.receipt-transparency-leaf.v1+json"


class AcceptanceFailure(RuntimeError):
    pass


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def write_json(path: Path, value: object, file_mode: int = 0o600) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(file_mode)


def clean_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in list(env):
        if key.lower().endswith("_proxy") or key.lower() == "no_proxy":
            env.pop(key)
    pinned_go = Path.home() / ".cache" / "go-toolchains" / "go1.25.12" / "bin"
    if pinned_go.is_dir():
        env["PATH"] = f"{pinned_go}:{env.get('PATH', '')}"
    env.update({"GOMAXPROCS": "2", "GOFLAGS": "-p=1", "GOPROXY": "off", "GOSUMDB": "off"})
    return env


class Recorder:
    def __init__(self, work: Path):
        self.work = work
        self.commands = work / "commands.jsonl"
        self.cases: list[dict[str, object]] = []

    def command(self, argv: list[str], *, cwd: Path = ROOT, check: bool = True, env=None, stdout=None):
        with self.commands.open("a") as stream:
            stream.write(
                json.dumps({"argv": argv, "cwd": str(cwd), "observed_at": time.time()}, sort_keys=True) + "\n"
            )
        return subprocess.run(
            argv, cwd=cwd, check=check, env=env, text=True, stdout=stdout, stderr=subprocess.STDOUT
        )

    def case(self, case: str, status: str, detail: str) -> None:
        self.cases.append({"case": case, "status": status, "detail": detail})


def verifier(path: Path) -> tuple[str, Ed25519PublicKey]:
    name, _, encoded = path.read_text().strip().split("+", 2)
    material = base64.b64decode(encoded, validate=True)
    if name != "filiolae.invalid/synthetic-s2/v1" or material[0] != 1 or len(material) != 33:
        raise AcceptanceFailure("synthetic verifier is invalid")
    return name, Ed25519PublicKey.from_public_bytes(material[1:])


def fetch(port: int, method: str, path: str, body: bytes | None = None, headers=None, timeout=15):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        raw = response.read(20 * 1024 * 1024)
        return response.status, raw
    finally:
        connection.close()


def checkpoint(port: int, verifier_path: Path):
    status, raw = fetch(port, "GET", "/checkpoint", timeout=5)
    if status != 200:
        raise AcceptanceFailure(f"checkpoint status {status}")
    origin, public = verifier(verifier_path)
    return verify_checkpoint(raw, origin, public), raw


def wait_size(port: int, verifier_path: Path, expected: int, timeout: float = 15):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            parsed, raw = checkpoint(port, verifier_path)
            last = parsed.tree_size
            if last == expected:
                return parsed, raw
        except Exception:
            pass
        time.sleep(0.05)
    raise AcceptanceFailure(f"checkpoint did not reach {expected}; last={last}")


def stable_size(port: int, verifier_path: Path, timeout: float = 5) -> int:
    deadline = time.monotonic() + timeout
    prior = None
    stable = 0
    while time.monotonic() < deadline:
        try:
            current, _ = checkpoint(port, verifier_path)
            if current.tree_size == prior:
                stable += 1
            else:
                prior, stable = current.tree_size, 0
            if stable >= 8:
                return current.tree_size
        except Exception:
            stable = 0
        time.sleep(0.1)
    raise AcceptanceFailure("checkpoint size did not stabilize after crash recovery")


def append(port: int, leaf: bytes):
    status, raw = fetch(
        port, "POST", "/add", leaf, {"Content-Type": MEDIA_TYPE, "Content-Length": str(len(leaf))}
    )
    if status != 200:
        raise AcceptanceFailure(f"append failed with status {status}: {raw[:200]!r}")
    value = json.loads(raw)
    if set(value) != {"index", "leaf_sha256"} or value["leaf_sha256"] != hashlib.sha256(leaf).hexdigest():
        raise AcceptanceFailure("append acknowledgement is invalid")
    return value


def wait_port(path: Path, process: subprocess.Popen, timeout=15) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AcceptanceFailure(f"process exited before publishing port: {process.returncode}")
        if path.is_file() and path.stat().st_size:
            port = int(path.read_text().strip())
            if not 1 <= port <= 65535 or mode(path) != 0o600:
                raise AcceptanceFailure("published port file is invalid")
            return port
        time.sleep(0.05)
    raise AcceptanceFailure("process did not publish a port")


def socket_inventory(pid: int, output: Path) -> str:
    result = subprocess.run(["ss", "-ltnp"], capture_output=True, text=True, check=True)
    output.write_text(result.stdout)
    output.chmod(0o600)
    lines = [line for line in result.stdout.splitlines() if f"pid={pid}," in line]
    fields = lines[0].split() if len(lines) == 1 else []
    local_address = fields[3] if len(fields) >= 4 else ""
    if len(lines) != 1 or not local_address.startswith("127.0.0.1:"):
        raise AcceptanceFailure(f"process {pid} does not have exactly one IPv4 loopback listener")
    return lines[0]


def s2_processes() -> list[str]:
    checks = [
        ["pgrep", "-a", "-x", "s2-personality"],
        ["pgrep", "-af", "[t]ransparency_s2_fault_proxy.py"],
    ]
    found: list[str] = []
    for argv in checks:
        result = subprocess.run(argv, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            found.extend(line for line in result.stdout.splitlines() if line)
        elif result.returncode != 1:
            raise AcceptanceFailure("cannot inspect S2 process inventory")
    return found


def start_personality(work: Path, binary: Path, storage: Path, private: Path, generation: int):
    port_file = work / f"personality-port-{generation}"
    stdout_path = work / f"personality-{generation}.stdout"
    stderr_path = work / f"personality-{generation}.stderr"
    key_fd = os.open(private, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    stdout = stdout_path.open("wb")
    stderr = stderr_path.open("wb")
    argv = [
        str(binary),
        "--storage-dir",
        str(storage),
        "--events",
        str(work / "personality-events.jsonl"),
        "--port-file",
        str(port_file),
        "--trust",
        str(TRUST),
        "--key-fd",
        str(key_fd),
    ]
    process = subprocess.Popen(
        argv,
        cwd=ROOT,
        env=clean_env(),
        pass_fds=(key_fd,),
        start_new_session=True,
        stdout=stdout,
        stderr=stderr,
    )
    os.close(key_fd)
    stdout.close()
    stderr.close()
    try:
        port = wait_port(port_file, process)
        socket_inventory(process.pid, work / f"socket-personality-{generation}.txt")
        personalities = subprocess.run(
            ["pgrep", "-a", "-x", "s2-personality"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.splitlines()
        if len(personalities) != 1 or not personalities[0].startswith(f"{process.pid} "):
            raise AcceptanceFailure("S2 personality is not the sole active personality")
        return process, port
    except BaseException:
        with contextlib.suppress(Exception):
            stop_process(process)
        raise


def stop_process(process: subprocess.Popen, *, crash=False) -> int:
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGKILL if crash else signal.SIGTERM)
    try:
        return process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        raise AcceptanceFailure("process exceeded shutdown deadline") from None


def start_proxy(work: Path, upstream: int, mode_name: str, target: str, count: int, sequence: int):
    port_file = work / f"proxy-port-{sequence}"
    events = work / f"proxy-events-{sequence}.json"
    argv = [
        sys.executable,
        str(ROOT / "scripts" / "transparency_s2_fault_proxy.py"),
        "--upstream",
        f"http://127.0.0.1:{upstream}",
        "--mode",
        mode_name,
        "--target",
        target,
        "--count",
        str(count),
        "--port-file",
        str(port_file),
        "--events",
        str(events),
    ]
    stderr = (work / f"proxy-{sequence}.stderr").open("wb")
    process = subprocess.Popen(
        argv,
        cwd=ROOT,
        env=clean_env(),
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=stderr,
    )
    stderr.close()
    try:
        port = wait_port(port_file, process)
        socket_inventory(process.pid, work / f"socket-proxy-{sequence}.txt")
        return process, port
    except BaseException:
        with contextlib.suppress(Exception):
            stop_process(process)
        raise


def run_monitor(
    rec: Recorder,
    monitor: str,
    base_port: int,
    mirror: Path,
    verifier_path: Path,
    expected: int,
    label: str,
    expect_success=True,
):
    report_path = rec.work / "reports" / f"{label}-{monitor}.json"
    if monitor == "python":
        argv = [
            sys.executable,
            str(ROOT / "scripts" / "transparency_s2_monitor.py"),
            "--base-url",
            f"http://127.0.0.1:{base_port}",
            "--mirror",
            str(mirror),
            "--verifier",
            str(verifier_path),
            "--trust",
            str(TRUST),
            "--expected-size",
            str(expected),
            "--report",
            str(report_path),
        ]
    else:
        argv = [
            str(rec.work / "bin" / "s2-monitor-go"),
            "--base-url",
            f"http://127.0.0.1:{base_port}",
            "--mirror",
            str(mirror),
            "--verifier",
            str(verifier_path),
            "--trust",
            str(TRUST),
            "--expected-size",
            str(expected),
            "--report",
            str(report_path),
        ]
    result = rec.command(argv, check=False, env=clean_env())
    report = json.loads(report_path.read_bytes())
    wanted = "healthy" if expect_success else "suspect"
    if report.get("status") != wanted or (result.returncode == 0) != expect_success:
        raise AcceptanceFailure(f"{label} {monitor} expected {wanted}, got rc={result.returncode} {report}")
    return report


def compare_reports(first: dict, second: dict, size: int) -> None:
    if (
        first.get("status") != "healthy"
        or second.get("status") != "healthy"
        or first.get("tree_size") != size
        or second.get("tree_size") != size
        or first.get("root_hex") != second.get("root_hex")
    ):
        raise AcceptanceFailure("independent monitor reports disagree")


def make_mirror(path: Path) -> None:
    path.mkdir(mode=0o700)
    if mode(path) != 0o700:
        raise AcceptanceFailure("mirror mode is not 0700")


def copy_public_log(storage: Path, target: Path) -> None:
    target.mkdir(mode=0o700)
    shutil.copy2(storage / "checkpoint", target / "checkpoint")
    shutil.copytree(storage / "tile", target / "tile")


def checksums(root: Path) -> str:
    lines = []
    for path in sorted(item for item in root.rglob("*") if item.is_file() and item.name != "SHA256SUMS"):
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root).as_posix()}")
    content = "\n".join(lines) + "\n"
    (root / "SHA256SUMS").write_text(content)
    return hashlib.sha256(content.encode()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--evidence", type=Path, default=ROOT / "evidence" / "acceptance" / "transparency-s2-20260813"
    )
    args = parser.parse_args()
    if args.evidence.exists():
        parser.error(f"evidence destination already exists: {args.evidence}")
    work = Path(tempfile.mkdtemp(prefix="filiolae-s2-"))
    work.chmod(0o700)
    rec = Recorder(work)
    (work / "reports").mkdir(mode=0o700)
    (work / "bin").mkdir(mode=0o700)
    private = work / "synthetic-checkpoint.private"
    verifier_path = work / "synthetic-checkpoint.verifier"
    storage = work / "tessera-storage"
    storage.mkdir(mode=0o700)
    leaves_dir = work / "synthetic-leaves"
    mirrors = {
        name: work / name
        for name in [
            "mirror-main-python",
            "mirror-main-go",
            "mirror-rebuild-python",
            "mirror-rebuild-go",
            "mirror-fault-python",
            "mirror-fault-go",
        ]
    }
    for path in mirrors.values():
        make_mirror(path)
    personality = None
    proxies: list[subprocess.Popen] = []
    known_ports: list[int] = []
    known_pids: list[int] = []
    try:
        if s2_processes():
            raise AcceptanceFailure("preflight found a residual S2 process")
        # Offline build from exact downloaded lock.
        gomod = (S2 / "go.mod").read_text()
        for pin in [
            "github.com/transparency-dev/tessera v1.0.4",
            "github.com/transparency-dev/merkle v0.0.2",
            "golang.org/x/mod v0.33.0",
            "golang.org/x/net v0.50.0",
        ]:
            if pin not in gomod:
                raise AcceptanceFailure(f"missing dependency pin: {pin}")
        rec.command(
            ["go", "mod", "verify"], cwd=S2, env=clean_env(), stdout=(work / "go-mod-verify.txt").open("w")
        )
        for command, name in [
            ("./cmd/keygen", "s2-keygen"),
            ("./cmd/personality", "s2-personality"),
            ("./cmd/monitor-go", "s2-monitor-go"),
        ]:
            rec.command(
                ["go", "build", "-trimpath", "-o", str(work / "bin" / name), command], cwd=S2, env=clean_env()
            )
        rec.command(
            [str(work / "bin" / "s2-keygen"), "--private", str(private), "--verifier", str(verifier_path)]
        )
        rec.command(
            [
                sys.executable,
                str(ROOT / "scripts" / "generate_transparency_s2_fixture.py"),
                "--output",
                str(leaves_dir),
                "--count",
                "16",
            ]
        )
        if mode(private) != 0o600 or mode(verifier_path) != 0o644 or mode(storage) != 0o700:
            raise AcceptanceFailure("S2 key/storage modes are invalid")
        write_json(
            work / "upstream-review.json",
            {
                "schema": "filiolae.transparency-s2-upstream-review.v1",
                "tessera_release": "v1.0.4",
                "tessera_commit": "6bca8e8d5e23c9941f2b8a08f512b373f7131730",
                "latest_release_at_execution": "v1.0.4",
                "release_published_at": "2026-07-16T13:09:33Z",
                "tag_commit_signed": False,
                "tag_commit_verification_reason": "unsigned",
                "license": "Apache-2.0",
                "github_security_advisories": [],
                "govulncheck": (
                    "0 called-symbol vulnerabilities; 1 imported-package and 23 required-module "
                    "advisories not reached by the S2 call graph; see retained verbose report"
                ),
                "boundary": "bounded synthetic loopback lab, not production",
            },
        )
        shutil.copy2("/tmp/filiolae-s2-govulncheck-verbose.txt", work / "govulncheck-verbose.txt")

        # S2.0
        personality, port = start_personality(work, work / "bin" / "s2-personality", storage, private, 1)
        first_port = port
        known_ports.append(port)
        known_pids.append(personality.pid)
        invalid = bytearray((leaves_dir / "00000000000000000000.leaf").read_bytes())
        invalid[len(invalid) // 2] ^= 1
        status, _ = fetch(
            port,
            "POST",
            "/add",
            bytes(invalid),
            {"Content-Type": MEDIA_TYPE, "Content-Length": str(len(invalid))},
        )
        if status != 422:
            raise AcceptanceFailure(f"invalid synthetic leaf was not rejected: {status}")
        for forbidden in ["/.state/treeState", "/tile/", "/anything"]:
            status, _ = fetch(port, "GET", forbidden)
            if status != 404:
                raise AcceptanceFailure(f"forbidden path exposed: {forbidden}")
        rec.case(
            "S2.0",
            "passed",
            (
                "pins/modes verified; one 127.0.0.1 ephemeral listener; "
                "invalid leaf and internal/arbitrary paths rejected"
            ),
        )

        # S2.1
        acknowledgements = [append(port, (leaves_dir / f"{i:020d}.leaf").read_bytes()) for i in range(9)]
        if [item["index"] for item in acknowledgements] != list(range(9)):
            raise AcceptanceFailure("baseline indices are not contiguous")
        wait_size(port, verifier_path, 9)
        py = run_monitor(rec, "python", port, mirrors["mirror-main-python"], verifier_path, 9, "s2-1")
        go = run_monitor(rec, "go", port, mirrors["mirror-main-go"], verifier_path, 9, "s2-1")
        compare_reports(py, go, 9)
        rec.case(
            "S2.1",
            "passed",
            "nine synthetic leaves; exact complete Python/Go mirrors agree on checkpoint root",
        )

        # S2.2
        if stop_process(personality) != 0:
            raise AcceptanceFailure("personality did not stop cleanly for restart")
        personality, port = start_personality(work, work / "bin" / "s2-personality", storage, private, 2)
        known_ports.append(port)
        known_pids.append(personality.pid)
        if port == first_port:
            raise AcceptanceFailure("restart unexpectedly reused the same ephemeral port")
        wait_size(port, verifier_path, 9)
        py = run_monitor(
            rec, "python", port, mirrors["mirror-rebuild-python"], verifier_path, 9, "s2-2-rebuild"
        )
        go = run_monitor(rec, "go", port, mirrors["mirror-rebuild-go"], verifier_path, 9, "s2-2-rebuild")
        compare_reports(py, go, 9)
        append(port, (leaves_dir / f"{9:020d}.leaf").read_bytes())
        append(port, (leaves_dir / f"{10:020d}.leaf").read_bytes())
        wait_size(port, verifier_path, 11)
        py = run_monitor(rec, "python", port, mirrors["mirror-main-python"], verifier_path, 11, "s2-2-growth")
        go = run_monitor(rec, "go", port, mirrors["mirror-main-go"], verifier_path, 11, "s2-2-growth")
        compare_reports(py, go, 11)
        if not py.get("consistency_proof_hex") or py["consistency_proof_hex"] != go.get(
            "consistency_proof_hex"
        ):
            raise AcceptanceFailure("restart growth lacks agreeing consistency evidence")
        rec.case(
            "S2.2",
            "passed",
            "new ephemeral port; empty-mirror rebuild; exact old bytes; append-only growth 9->11 verified",
        )

        # S2.3
        append(port, (leaves_dir / f"{11:020d}.leaf").read_bytes())
        wait_size(port, verifier_path, 12)
        proxy, proxy_port = start_proxy(work, port, "truncate-read", "/tile/entries/000.p/12", 2, 1)
        proxies.append(proxy)
        known_ports.append(proxy_port)
        known_pids.append(proxy.pid)
        run_monitor(
            rec,
            "python",
            proxy_port,
            mirrors["mirror-fault-python"],
            verifier_path,
            12,
            "s2-3-truncated",
            False,
        )
        run_monitor(
            rec, "go", proxy_port, mirrors["mirror-fault-go"], verifier_path, 12, "s2-3-truncated", False
        )
        if (mirrors["mirror-fault-python"] / "state.json").exists() or (
            mirrors["mirror-fault-go"] / "state.json"
        ).exists():
            raise AcceptanceFailure("truncated resource advanced monitor state")
        stop_process(proxy)
        proxies.remove(proxy)
        py = run_monitor(
            rec, "python", port, mirrors["mirror-fault-python"], verifier_path, 12, "s2-3-recover"
        )
        go = run_monitor(rec, "go", port, mirrors["mirror-fault-go"], verifier_path, 12, "s2-3-recover")
        compare_reports(py, go, 12)
        rec.case(
            "S2.3",
            "passed",
            (
                "both monitors stayed suspect/no-state on truncated bundle and "
                "recovered from exact immutable resource"
            ),
        )

        # S2.4
        proxy, proxy_port = start_proxy(work, port, "drop-append-response", "/add", 1, 2)
        proxies.append(proxy)
        known_ports.append(proxy_port)
        known_pids.append(proxy.pid)
        lost_leaf = (leaves_dir / f"{12:020d}.leaf").read_bytes()
        outcome = "unknown"
        try:
            append(proxy_port, lost_leaf)
            outcome = "unexpected-success"
        except (OSError, http.client.HTTPException, AcceptanceFailure):
            outcome = "unknown"
        if outcome != "unknown":
            raise AcceptanceFailure("dropped response was not treated as unknown")
        stop_process(proxy)
        proxies.remove(proxy)
        wait_size(port, verifier_path, 13)
        retry = append(port, lost_leaf)
        if retry["index"] != 13:
            raise AcceptanceFailure("lost-response retry did not create visible duplicate index")
        wait_size(port, verifier_path, 14)
        py = run_monitor(rec, "python", port, mirrors["mirror-main-python"], verifier_path, 14, "s2-4")
        go = run_monitor(rec, "go", port, mirrors["mirror-main-go"], verifier_path, 14, "s2-4")
        compare_reports(py, go, 14)
        leaves_py = json.loads((mirrors["mirror-main-python"] / "state.json").read_bytes())["leaves_b64"]
        if leaves_py[12] != leaves_py[13]:
            raise AcceptanceFailure("lost-response duplicate is not visible in mirror")
        rec.case(
            "S2.4",
            "passed",
            (
                "dropped accepted response remained unknown; monitors resolved inclusion; "
                "retry became two explicit identical leaves"
            ),
        )

        # S2.5
        append(port, (leaves_dir / f"{14:020d}.leaf").read_bytes())
        wait_size(port, verifier_path, 15)
        proxy, proxy_port = start_proxy(work, port, "mutate-read", "/tile/entries/000.p/9", 2, 3)
        proxies.append(proxy)
        known_ports.append(proxy_port)
        known_pids.append(proxy.pid)
        run_monitor(
            rec,
            "python",
            proxy_port,
            mirrors["mirror-main-python"],
            verifier_path,
            15,
            "s2-5-conflict",
            False,
        )
        run_monitor(
            rec, "go", proxy_port, mirrors["mirror-main-go"], verifier_path, 15, "s2-5-conflict", False
        )
        for key in ["mirror-main-python", "mirror-main-go"]:
            state = json.loads((mirrors[key] / "state.json").read_bytes())
            if state["tree_size"] != 14 or not (mirrors[key] / "conflicts").is_dir():
                raise AcceptanceFailure("immutable conflict was not preserved without state advancement")
        stop_process(proxy)
        proxies.remove(proxy)
        py = run_monitor(
            rec, "python", port, mirrors["mirror-main-python"], verifier_path, 15, "s2-5-recover"
        )
        go = run_monitor(rec, "go", port, mirrors["mirror-main-go"], verifier_path, 15, "s2-5-recover")
        compare_reports(py, go, 15)
        rec.case(
            "S2.5",
            "passed",
            (
                "changed old immutable URL preserved as conflict; both monitors refused "
                "14->15 advancement, then recovered"
            ),
        )

        # S2.6
        crash_leaf = (leaves_dir / f"{15:020d}.leaf").read_bytes()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(append, port, crash_leaf)
            time.sleep(0.01)
            crash_rc = stop_process(personality, crash=True)
            try:
                crash_ack = future.result(timeout=20)
                crash_client = {"outcome": "acknowledged", "ack": crash_ack}
            except Exception as error:
                crash_client = {"outcome": "unknown", "error_type": type(error).__name__}
        if crash_rc not in {-signal.SIGKILL, 128 + signal.SIGKILL}:
            raise AcceptanceFailure("crash injection did not kill personality")
        personality, port = start_personality(work, work / "bin" / "s2-personality", storage, private, 3)
        known_ports.append(port)
        known_pids.append(personality.pid)
        recovered_size = stable_size(port, verifier_path)
        if recovered_size not in {15, 16}:
            raise AcceptanceFailure(f"crash recovery exposed invalid size {recovered_size}")
        if crash_client["outcome"] == "acknowledged" and recovered_size != 16:
            raise AcceptanceFailure("acknowledged crash append is absent")
        if recovered_size == 15:
            append(port, crash_leaf)
            wait_size(port, verifier_path, 16)
        py = run_monitor(rec, "python", port, mirrors["mirror-main-python"], verifier_path, 16, "s2-6")
        go = run_monitor(rec, "go", port, mirrors["mirror-main-go"], verifier_path, 16, "s2-6")
        compare_reports(py, go, 16)
        write_json(
            work / "crash-outcome.json",
            {
                "schema": "filiolae.transparency-s2-crash-outcome.v1",
                "client": crash_client,
                "recovered_size": recovered_size,
                "final_size": 16,
            },
        )
        if stop_process(personality) != 0:
            raise AcceptanceFailure("final clean shutdown failed")
        personality = None
        private.unlink()
        if private.exists():
            raise AcceptanceFailure("synthetic private checkpoint key remains")
        time.sleep(0.2)
        residual = subprocess.run(["ss", "-ltnp"], capture_output=True, text=True, check=True).stdout
        if s2_processes():
            raise AcceptanceFailure("S2 process remains after cleanup")
        if any(f"127.0.0.1:{item}" in residual for item in known_ports):
            raise AcceptanceFailure("S2 listener remains after cleanup")
        if any(Path(f"/proc/{pid}").exists() for pid in known_pids):
            raise AcceptanceFailure("S2 process remains after cleanup")
        (work / "socket-final.txt").write_text(residual)
        rec.case(
            "S2.6",
            "passed",
            (
                f"SIGKILL outcome reconciled at size {recovered_size}; "
                "final exact size 16; clean stop, no key/listener"
            ),
        )

        # Final evidence, excluding key and private .state.
        evidence = args.evidence
        evidence.mkdir(mode=0o700, parents=True)
        for filename in [
            "commands.jsonl",
            "upstream-review.json",
            "govulncheck-verbose.txt",
            "personality-events.jsonl",
            "crash-outcome.json",
            "socket-final.txt",
            "go-mod-verify.txt",
        ]:
            shutil.copy2(work / filename, evidence / filename)
        for pattern in [
            "personality-*.stdout",
            "personality-*.stderr",
            "socket-*.txt",
            "proxy-events-*.json",
            "proxy-*.stderr",
        ]:
            for path in work.glob(pattern):
                shutil.copy2(path, evidence / path.name)
        shutil.copytree(work / "reports", evidence / "reports")
        shutil.copytree(leaves_dir, evidence / "synthetic-leaves")
        shutil.copy2(verifier_path, evidence / "synthetic-checkpoint.verifier")
        shutil.copy2(TRUST, evidence / "synthetic-trust.json")
        copy_public_log(storage, evidence / "log-public")
        for name, path in mirrors.items():
            shutil.copytree(path, evidence / name)
        source = evidence / "source"
        source.mkdir()
        shutil.copytree(S2 / "cmd", source / "cmd")
        shutil.copytree(S2 / "internal", source / "internal")
        for path in [
            S2 / "go.mod",
            S2 / "go.sum",
            ROOT / "scripts" / "transparency_s2_monitor.py",
            ROOT / "scripts" / "transparency_s2_fault_proxy.py",
            ROOT / "scripts" / "generate_transparency_s2_fixture.py",
            Path(__file__),
        ]:
            shutil.copy2(path, source / path.name)
        result = {
            "schema": "filiolae.transparency-s2-acceptance.v1",
            "status": "passed",
            "date": "2026-08-13",
            "cases": rec.cases,
            "final_tree_size": 16,
            "final_root_hex": py["root_hex"],
            "tessera": {"version": "v1.0.4", "commit": "6bca8e8d5e23c9941f2b8a08f512b373f7131730"},
            "isolation": "separate-process/disjoint-mode-0700-roots; same UID, not production UID isolation",
            "network": (
                "runtime services/dials were IPv4 127.0.0.1 ephemeral only with no proxy "
                "environment; public dependency/advisory metadata was fetched during preflight"
            ),
            "non_claims": [
                "public transparency",
                "independent administration",
                "witness quorum",
                "trusted time",
                "public retention",
                "production containment",
                "Gate coupling",
                "release readiness",
            ],
        }
        write_json(evidence / "RESULT.json", result)
        root_digest = checksums(evidence)
        write_json(
            evidence / "PACKAGE.json",
            {
                "schema": "filiolae.transparency-s2-evidence-package.v1",
                "pre_package_sha256sums_sha256": root_digest,
                "private_keys_retained": False,
                "files_before_final_sha256sums": len([p for p in evidence.rglob("*") if p.is_file()]),
            },
        )
        # Regenerate the external package inventory to include PACKAGE itself.
        root_digest = checksums(evidence)
        print(
            json.dumps(
                {
                    "status": "passed",
                    "evidence": str(evidence),
                    "sha256sums_sha256": root_digest,
                    "final_root_hex": py["root_hex"],
                },
                sort_keys=True,
            )
        )
        return 0
    except BaseException:
        if personality is not None and personality.poll() is None:
            with contextlib.suppress(Exception):
                stop_process(personality)
        for proxy in proxies:
            if proxy.poll() is None:
                with contextlib.suppress(Exception):
                    stop_process(proxy)
        raise
    finally:
        if private.exists():
            private.unlink()
        # Work area is removed only after successful evidence copy or failed cleanup.
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
