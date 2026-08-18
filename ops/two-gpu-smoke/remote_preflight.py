#!/usr/bin/env python3
"""Strict on-pod validation and fresh-directory bootstrap for the local-anchor smoke."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from common import (
    BUILD_GENERATED_SOURCE_FILES,
    DATASET_LFS_FILES,
    DATASET_REPO_ID,
    DATASET_REVISION,
    MODEL_LFS_FILES,
    MODEL_REPO_ID,
    MODEL_REVISION,
    PATCHED_PRIME_FILES,
    PRIME_RL_SHA,
    PRIME_SUBMODULES,
    VERIFIERS_SHA,
    SmokeToolError,
    absolute_no_symlinks,
    atomic_write_json,
    load_manifest,
    require_regular_file,
    run_checked,
    sha256_file,
)

FROZEN_SYNC_ARGS = (
    "sync",
    "--frozen",
    "--package",
    "prime-rl",
    "--package",
    "reverse-text-v1",
    "--extra",
    "flash-attn",
    "--extra",
    "disagg",
    "--no-dev",
)


def _git(repository: Path, *arguments: str) -> str:
    return run_checked(["git", *arguments], cwd=repository, timeout=60).stdout.strip()


def _extract_patched_source(archive_path: Path, destination: Path) -> None:
    if destination.exists():
        raise SmokeToolError(f"fresh prime-rl destination required for source bootstrap: {destination}")
    absolute_no_symlinks(destination.parent)
    with tempfile.TemporaryDirectory(prefix=".prime-rl-source-", dir=destination.parent) as temporary:
        temporary_root = Path(temporary)
        with tarfile.open(archive_path, "r") as archive:
            for member in archive.getmembers():
                member_path = Path(member.name)
                if (
                    member_path.is_absolute()
                    or ".." in member_path.parts
                    or not member_path.parts
                    or member_path.parts[0] != "prime-rl"
                    or not (member.isdir() or member.isreg())
                ):
                    raise SmokeToolError(f"unsafe patched-source archive member: {member.name}")
            archive.extractall(temporary_root, filter="data")
        extracted = temporary_root / "prime-rl"
        if not extracted.is_dir():
            raise SmokeToolError("patched-source archive has no prime-rl root")
        os.replace(extracted, destination)


def _validate_source_manifest(prime_rl: Path, manifest_path: Path) -> dict[str, object]:
    try:
        source_manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SmokeToolError(f"invalid patched-source manifest: {exc}") from exc
    if (
        source_manifest.get("schema") != "filiolae.prime-rl-patched-source.v1"
        or source_manifest.get("prime_rl_commit") != PRIME_RL_SHA
        or source_manifest.get("verifiers_commit") != VERIFIERS_SHA
        or source_manifest.get("submodules") != PRIME_SUBMODULES
        or source_manifest.get("archive_policy") != "tracked-regular-files-only; no symlinks or special nodes"
        or set(source_manifest.get("patched_files", [])) != PATCHED_PRIME_FILES
    ):
        raise SmokeToolError("patched-source manifest has inconsistent pins")
    files = source_manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise SmokeToolError("patched-source manifest has no file hashes")
    expected_paths: set[str] = set()
    for relative, expected_sha in files.items():
        if not isinstance(relative, str) or relative.startswith(("/", "../")) or "/../" in relative:
            raise SmokeToolError(f"unsafe patched-source path: {relative!r}")
        candidate = require_regular_file(prime_rl / relative)
        if not candidate.resolve().is_relative_to(prime_rl.resolve()):
            raise SmokeToolError(f"patched-source path escapes root: {relative}")
        if __import__("common").sha256_file(candidate) != expected_sha:
            raise SmokeToolError(f"patched-source digest mismatch: {relative}")
        expected_paths.add(relative)
    for relative, expected_sha in BUILD_GENERATED_SOURCE_FILES.items():
        candidate = prime_rl / relative
        if not candidate.exists():
            continue
        require_regular_file(candidate)
        if not candidate.resolve().is_relative_to(prime_rl.resolve()):
            raise SmokeToolError(f"build-generated source path escapes root: {relative}")
        if __import__("common").sha256_file(candidate) != expected_sha:
            raise SmokeToolError(f"build-generated source digest mismatch: {relative}")
        expected_paths.add(relative)
    ignored = {".git", ".venv", ".claude", "__pycache__", ".pytest_cache", ".ruff_cache"}
    actual_paths = {
        path.relative_to(prime_rl).as_posix()
        for path in prime_rl.rglob("*")
        if path.is_file() and not any(part in ignored for part in path.relative_to(prime_rl).parts)
    }
    unexpected = actual_paths - expected_paths
    if unexpected:
        raise SmokeToolError(f"unexpected files in patched source: {sorted(unexpected)[:10]}")
    return source_manifest


def _validate_patched_prime(prime_rl: Path, patch: Path, source_manifest: Path) -> None:
    _validate_source_manifest(prime_rl, source_manifest)
    if (prime_rl / ".git").exists():
        if _git(prime_rl, "rev-parse", "HEAD") != PRIME_RL_SHA:
            raise SmokeToolError(f"remote prime-rl is not pinned at {PRIME_RL_SHA}")
        for submodule_path, expected_sha in PRIME_SUBMODULES.items():
            gitlink = _git(prime_rl, "ls-tree", "HEAD", submodule_path).split()
            if len(gitlink) < 3 or gitlink[1] != "commit" or gitlink[2] != expected_sha:
                raise SmokeToolError(f"remote prime-rl has the wrong {submodule_path} gitlink")
        changed = set(_git(prime_rl, "diff", "--name-only").splitlines())
        if changed != PATCHED_PRIME_FILES:
            raise SmokeToolError(f"remote patched tree has unexpected changed paths: {sorted(changed)}")
        untracked = [
            line for line in _git(prime_rl, "status", "--porcelain").splitlines() if line.startswith("??")
        ]
        if untracked:
            raise SmokeToolError(f"remote prime-rl has untracked files: {untracked[:5]}")
    run_checked(["git", "apply", "--reverse", "--check", str(patch)], cwd=prime_rl, timeout=60)


def _require_executable(path: Path) -> Path:
    absolute_no_symlinks(path.parent)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise SmokeToolError(f"executable file required: {path}")
    return path


def _validate_installed_wheel(wheel: Path, venv_python: Path) -> str:
    result = run_checked(
        [
            str(venv_python),
            "-c",
            "import filiolae, pathlib; print(pathlib.Path(filiolae.__file__).resolve().parent)",
        ],
        timeout=60,
    )
    installed_root = Path(result.stdout.strip())
    absolute_no_symlinks(installed_root)
    with zipfile.ZipFile(wheel) as archive:
        members = sorted(
            name for name in archive.namelist() if name.startswith("filiolae/") and name.endswith(".py")
        )
        if not members:
            raise SmokeToolError("payload wheel has no Filiolae Python modules")
        for member in members:
            relative = Path(member).relative_to("filiolae")
            installed = require_regular_file(installed_root / relative)
            if archive.read(member) != installed.read_bytes():
                raise SmokeToolError(f"installed Filiolae differs from payload wheel: {relative}")
    return str(installed_root)


def _payload_wheel(manifest: dict[str, object], payload: Path) -> Path:
    wheel_name = manifest.get("filiolae_wheel")
    if (
        not isinstance(wheel_name, str)
        or len(wheel_name) > 200
        or Path(wheel_name).name != wheel_name
        or wheel_name.count("-") < 4
        or not wheel_name.startswith("filiolae-")
        or not wheel_name.endswith(".whl")
    ):
        raise SmokeToolError("payload manifest has an invalid Filiolae wheel filename")
    files = manifest.get("files")
    if not isinstance(files, dict) or wheel_name not in files:
        raise SmokeToolError("payload manifest does not bind the Filiolae wheel")
    return require_regular_file(payload / wheel_name)


def _validate_runtime_lineage(venv_python: Path, prime_rl: Path) -> dict[str, str]:
    result = run_checked(
        [
            str(venv_python),
            "-c",
            "import importlib.util, json; "
            "names=['prime_rl.orchestrator.orchestrator','reverse_text_v1']; "
            "print(json.dumps({name: importlib.util.find_spec(name).origin for name in names}))",
        ],
        timeout=60,
    )
    try:
        origins = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SmokeToolError("runtime lineage probe returned invalid JSON") from exc
    expected_roots = {
        "prime_rl.orchestrator.orchestrator": prime_rl / "src" / "prime_rl",
        "reverse_text_v1": (
            prime_rl / "deps" / "verifiers" / "environments" / "reverse_text_v1" / "reverse_text_v1"
        ),
    }
    verified: dict[str, str] = {}
    for name, root in expected_roots.items():
        origin = origins.get(name) if isinstance(origins, dict) else None
        if not isinstance(origin, str):
            raise SmokeToolError(f"runtime package has no concrete origin: {name}")
        path = require_regular_file(Path(origin))
        if not path.resolve().is_relative_to(root.resolve()):
            raise SmokeToolError(f"runtime package does not resolve beneath verified source: {name}")
        verified[name] = str(path)
    return verified


def _validate_config(path: Path, *, expected_steps: int = 2) -> dict[str, object]:
    try:
        config = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise SmokeToolError(f"invalid smoke TOML: {exc}") from exc
    if config.get("max_steps") != expected_steps:
        raise SmokeToolError(f"smoke profile requires max_steps = {expected_steps}")
    if config.get("weight_broadcast", {}).get("type") != "filesystem":
        raise SmokeToolError("smoke requires explicit filesystem weight broadcasting")
    ckpt = config.get("ckpt", {})
    if not isinstance(ckpt, dict) or "resume_step" in ckpt:
        raise SmokeToolError("smoke must be a fresh, non-resumed run")
    if config.get("model", {}).get("name") != MODEL_REPO_ID:
        raise SmokeToolError("unexpected smoke model")
    return config


def _gpu_report(policy: dict[str, object]) -> list[dict[str, str]]:
    if shutil.which("nvidia-smi") is None:
        raise SmokeToolError("nvidia-smi is unavailable")
    query = run_checked(
        [
            "nvidia-smi",
            "--query-gpu=index,uuid,name,memory.total,driver_version",
            "--format=csv,noheader,nounits",
        ],
        timeout=30,
    ).stdout.splitlines()
    if len(query) != 2:
        raise SmokeToolError(f"exactly two physical GPUs are required, found {len(query)}")
    rows: list[dict[str, str]] = []
    for expected_index, line in enumerate(query):
        fields = [item.strip() for item in line.split(",", 4)]
        if len(fields) != 5 or fields[0] != str(expected_index):
            raise SmokeToolError(f"unexpected GPU index/order: {line!r}")
        row = dict(zip(("index", "uuid", "name", "memory_mib", "driver"), fields, strict=True))
        expected_name = policy.get("name_contains")
        min_memory = policy.get("min_memory_mib")
        if not isinstance(expected_name, str) or expected_name not in row["name"]:
            raise SmokeToolError(f"GPU {expected_index} name violates policy: {row['name']!r}")
        try:
            memory_mib = int(row["memory_mib"])
        except ValueError as exc:
            raise SmokeToolError(f"invalid GPU memory report: {row['memory_mib']!r}") from exc
        if not isinstance(min_memory, int) or memory_mib < min_memory:
            raise SmokeToolError(f"GPU {expected_index} has only {memory_mib} MiB")
        rows.append(row)
    mig_query = run_checked(
        [
            "nvidia-smi",
            "--query-gpu=index,mig.mode.current",
            "--format=csv,noheader,nounits",
        ],
        timeout=30,
    ).stdout.splitlines()
    if len(mig_query) != 2:
        raise SmokeToolError("could not establish MIG mode for exactly two GPUs")
    for expected_index, line in enumerate(mig_query):
        fields = [item.strip() for item in line.split(",", 1)]
        if len(fields) != 2 or fields[0] != str(expected_index):
            raise SmokeToolError(f"unexpected MIG index/order: {line!r}")
        mode = fields[1]
        if mode == "Enabled":
            raise SmokeToolError("MIG-enabled devices are outside the first smoke profile")
        if mode not in {"Disabled", "N/A", "[N/A]", "Not Supported"}:
            raise SmokeToolError(f"unrecognized MIG mode for GPU {expected_index}: {mode!r}")
    return rows


def _snapshot_file(snapshot: Path, cache: Path, name: str, *, kind: str = "model") -> Path:
    candidate = snapshot / name
    if not candidate.is_symlink():
        return require_regular_file(candidate)
    try:
        resolved = candidate.resolve(strict=True)
        blobs = (cache / "blobs").resolve(strict=True)
    except OSError as exc:
        raise SmokeToolError(f"{kind} snapshot has a broken cache link: {name}") from exc
    if not resolved.is_relative_to(blobs):
        raise SmokeToolError(f"{kind} snapshot link escapes its content-addressed blob store: {name}")
    return require_regular_file(resolved)


def _bind_main_ref(cache: Path, revision: str, *, kind: str) -> Path:
    refs = cache / "refs"
    try:
        refs.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        raise SmokeToolError(f"cannot create the pinned {kind} reference directory") from exc
    absolute_no_symlinks(refs)
    main_ref = refs / "main"
    if main_ref.exists():
        current = require_regular_file(main_ref).read_text().strip()
        if current != revision:
            raise SmokeToolError(f"existing {kind} main reference conflicts with the reviewed revision")
        return main_ref
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(main_ref, flags, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(revision)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise SmokeToolError(f"cannot safely bind {kind} main to the reviewed revision") from exc
    return require_regular_file(main_ref, mode=0o600)


def _bind_model_main_ref(model_cache: Path, revision: str) -> Path:
    return _bind_main_ref(model_cache, revision, kind="model")


def _assert_model_snapshot(
    payload_manifest: dict[str, object],
    hf_home: Path,
    venv_python: Path,
    *,
    prefetch: bool,
    timeout: int,
) -> Path:
    model = payload_manifest.get("model")
    if (
        not isinstance(model, dict)
        or model.get("repo_id") != MODEL_REPO_ID
        or model.get("snapshot_commit") != MODEL_REVISION
        or model.get("lfs_files") != MODEL_LFS_FILES
    ):
        raise SmokeToolError("payload model policy is missing or inconsistent with reviewed pins")
    repo_id = MODEL_REPO_ID
    revision = MODEL_REVISION
    absolute_no_symlinks(hf_home)
    model_cache = hf_home / "hub" / f"models--{repo_id.replace('/', '--')}"
    snapshot = model_cache / "snapshots" / revision
    if prefetch:
        env = {
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "HOME", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR"}
        }
        env["HF_HOME"] = str(hf_home)
        run_checked(
            [
                str(venv_python),
                "-c",
                "from huggingface_hub import snapshot_download; import sys; "
                "print(snapshot_download(sys.argv[1], revision=sys.argv[2]))",
                repo_id,
                revision,
            ],
            timeout=timeout,
            env=env,
        )
    absolute_no_symlinks(snapshot)
    if not snapshot.is_dir():
        raise SmokeToolError(f"exact model snapshot is unavailable: {snapshot}")
    for required_name in ("config.json", "tokenizer_config.json"):
        required = _snapshot_file(snapshot, model_cache, required_name)
        if required.stat().st_size == 0:
            raise SmokeToolError(f"exact model snapshot is incomplete: empty {required_name}")
    for name, expected in MODEL_LFS_FILES.items():
        candidate = _snapshot_file(snapshot, model_cache, name)
        size = candidate.stat().st_size
        if size != expected["size"]:
            raise SmokeToolError(f"exact model snapshot has the wrong size for {name}: {size}")
        digest = sha256_file(candidate)
        if digest != expected["sha256"]:
            raise SmokeToolError(f"exact model snapshot digest mismatch for {name}: {digest}")
    _bind_model_main_ref(model_cache, revision)
    return snapshot


def _assert_dataset_snapshot(
    payload_manifest: dict[str, object],
    hf_home: Path,
    venv_python: Path,
    *,
    prefetch: bool,
    timeout: int,
) -> dict[str, object]:
    dataset = payload_manifest.get("dataset")
    if (
        not isinstance(dataset, dict)
        or dataset.get("repo_id") != DATASET_REPO_ID
        or dataset.get("snapshot_commit") != DATASET_REVISION
        or dataset.get("lfs_files") != DATASET_LFS_FILES
    ):
        raise SmokeToolError("payload dataset policy is missing or inconsistent with reviewed pins")
    repo_id = DATASET_REPO_ID
    revision = DATASET_REVISION
    absolute_no_symlinks(hf_home)
    dataset_cache = hf_home / "hub" / f"datasets--{repo_id.replace('/', '--')}"
    snapshot = dataset_cache / "snapshots" / revision
    if prefetch:
        env = {
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "HOME", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR"}
        }
        env["HF_HOME"] = str(hf_home)
        run_checked(
            [
                str(venv_python),
                "-c",
                "from huggingface_hub import snapshot_download; import sys; "
                "print(snapshot_download(sys.argv[1], repo_type='dataset', revision=sys.argv[2]))",
                repo_id,
                revision,
            ],
            timeout=timeout,
            env=env,
        )
    absolute_no_symlinks(snapshot)
    if not snapshot.is_dir():
        raise SmokeToolError(f"exact dataset snapshot is unavailable: {snapshot}")
    readme = _snapshot_file(snapshot, dataset_cache, "README.md", kind="dataset")
    if readme.stat().st_size == 0:
        raise SmokeToolError("exact dataset snapshot is incomplete: empty README.md")
    for name, expected in DATASET_LFS_FILES.items():
        candidate = _snapshot_file(snapshot, dataset_cache, name, kind="dataset")
        size = candidate.stat().st_size
        if size != expected["size"]:
            raise SmokeToolError(f"exact dataset snapshot has the wrong size for {name}: {size}")
        digest = sha256_file(candidate)
        if digest != expected["sha256"]:
            raise SmokeToolError(f"exact dataset snapshot digest mismatch for {name}: {digest}")
    _bind_main_ref(dataset_cache, revision, kind="dataset")
    env = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "HOME", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR"}
    }
    env["HF_HOME"] = str(hf_home)
    if prefetch:
        run_checked(
            [
                str(venv_python),
                "-c",
                "from datasets import load_dataset; import sys; "
                "rows=load_dataset(sys.argv[1], revision=sys.argv[2], split='train'); "
                "print(len(rows), rows.column_names)",
                repo_id,
                revision,
            ],
            timeout=timeout,
            env=env,
        )
    env.update(
        {
            "HF_HOME": str(hf_home),
            "HF_HUB_OFFLINE": "1",
            "HF_DATASETS_OFFLINE": "1",
        }
    )
    result = run_checked(
        [
            str(venv_python),
            "-c",
            "from datasets import load_dataset; import json, sys; "
            "rows=load_dataset(sys.argv[1], split='train'); "
            "print(json.dumps({'rows': len(rows), 'columns': rows.column_names}, sort_keys=True))",
            repo_id,
        ],
        timeout=timeout,
        env=env,
    )
    try:
        loaded = json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise SmokeToolError("offline dataset validation returned invalid evidence") from exc
    if loaded != {"columns": ["prompt"], "rows": 1000}:
        raise SmokeToolError(f"offline dataset validation returned unexpected content: {loaded!r}")
    return {"snapshot": str(snapshot), "offline_load": loaded}


def _publish_exact(path: Path, data: bytes, *, mode: int = 0o600) -> Path:
    if path.exists():
        candidate = require_regular_file(path, mode=mode)
        if candidate.read_bytes() != data:
            raise SmokeToolError(f"existing prewarmed harness file conflicts with reviewed bytes: {path}")
        return candidate
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise SmokeToolError(f"cannot publish reviewed harness file: {path}") from exc
    return require_regular_file(path, mode=mode)


def _prepare_null_harness(
    payload: Path,
    prime_rl: Path,
    venv_bin: Path,
    hf_home: Path,
    *,
    prefetch: bool,
    timeout: int,
    script_dir: Path = Path("/tmp/vf-scripts"),
) -> dict[str, str]:
    program = require_regular_file(
        prime_rl / "deps" / "verifiers" / "verifiers" / "v1" / "harnesses" / "null" / "program.py"
    )
    lock = require_regular_file(payload / "null-harness-program.py.lock")
    bundled_uv = _require_executable(payload / "bin" / "uv")
    pip_shim = _require_executable(payload / "bin" / "pip")
    script_bytes = program.read_bytes()
    digest = hashlib.sha256(script_bytes).hexdigest()
    try:
        script_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise SmokeToolError("cannot create the stable null-harness script directory") from exc
    absolute_no_symlinks(script_dir)
    if not os.access(script_dir, os.W_OK):
        raise SmokeToolError("stable null-harness script directory is not writable")
    script = _publish_exact(script_dir / f"{digest}.py", script_bytes)
    script_lock = _publish_exact(Path(str(script) + ".lock"), lock.read_bytes())
    xdg_config = hf_home / "filiolae-xdg-config"
    uv_cache = hf_home / "filiolae-uv-cache"
    harness_home = hf_home / "filiolae-harness-home"
    local_bin = harness_home / ".local" / "bin"
    for directory in (xdg_config, uv_cache, harness_home, harness_home / ".local", local_bin):
        try:
            directory.mkdir(mode=0o700, exist_ok=True)
            os.chmod(directory, 0o700)
        except OSError as exc:
            raise SmokeToolError(f"cannot create reviewed harness cache directory: {directory}") from exc
        absolute_no_symlinks(directory)
    local_uv = _publish_exact(local_bin / "uv", bundled_uv.read_bytes(), mode=0o700)
    local_pip = _publish_exact(local_bin / "pip", pip_shim.read_bytes(), mode=0o700)
    env = {
        key: value
        for key, value in os.environ.items()
        if key in {"LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR"}
    }
    env.update(
        {
            "HOME": str(harness_home),
            "PATH": f"{local_bin}:{payload / 'bin'}:{venv_bin}:/usr/bin:/bin",
            "XDG_CONFIG_HOME": str(xdg_config),
            "UV_CACHE_DIR": str(uv_cache),
        }
    )
    ensure_result = run_checked(
        [
            "sh",
            "-c",
            'export PATH="$HOME/.local/bin:$PATH" UV_INSTALL_DIR="$HOME/.local/bin"; '
            "pip install -q -U --user uv 2>/dev/null; "
            "command -v pip; command -v uv; uv --version",
        ],
        timeout=30,
        env=env,
    )
    if ensure_result.stdout.strip().splitlines() != [
        str(local_pip),
        str(local_uv),
        "uv 0.11.8 (x86_64-unknown-linux-gnu)",
    ]:
        raise SmokeToolError("null-harness ensure-uv command did not resolve only reviewed tools")
    sync_command = [
        str(local_uv),
        "sync",
        "--script",
        str(script),
        "--frozen",
        "--no-config",
        "-q",
    ]
    if prefetch:
        run_checked(sync_command, timeout=timeout, env=env)
    offline_env = {**env, "UV_OFFLINE": "1"}
    run_checked(sync_command, timeout=timeout, env=offline_env)
    runtime_sync_command = [str(local_uv), "sync", "--script", str(script), "-q", "--no-config"]
    run_checked(runtime_sync_command, timeout=timeout, env=offline_env)
    interpreter_result = run_checked(
        [str(local_uv), "python", "find", "--script", str(script), "--no-config"],
        timeout=60,
        env=offline_env,
    )
    try:
        interpreter = Path(interpreter_result.stdout.strip().splitlines()[-1])
    except IndexError as exc:
        raise SmokeToolError("null-harness prewarm returned no interpreter") from exc
    if not interpreter.is_absolute() or interpreter.name not in {"python", "python3", "python3.12"}:
        raise SmokeToolError(f"null-harness prewarm returned an unsafe interpreter path: {interpreter}")
    environment_root = interpreter.parent.parent
    absolute_no_symlinks(environment_root)
    if not environment_root.resolve().is_relative_to(uv_cache.resolve()):
        raise SmokeToolError("null-harness interpreter environment escapes the reviewed uv cache")
    try:
        resolved_interpreter = interpreter.resolve(strict=True)
    except OSError as exc:
        raise SmokeToolError("null-harness interpreter link is broken") from exc
    _require_executable(resolved_interpreter)
    run_checked([str(interpreter), str(script), "--help"], timeout=60, env=offline_env)
    version = run_checked([str(local_uv), "--version"], timeout=30, env=offline_env).stdout.strip()
    if version != "uv 0.11.8 (x86_64-unknown-linux-gnu)":
        raise SmokeToolError(f"unexpected null-harness uv version: {version!r}")
    return {
        "program_sha256": digest,
        "lock_sha256": sha256_file(script_lock),
        "script": str(script),
        "interpreter": str(interpreter),
        "uv_version": version,
        "uv_cache": str(uv_cache),
        "xdg_config_home": str(xdg_config),
        "harness_home": str(harness_home),
    }


def _cuda_allocation_check(venv_python: Path) -> None:
    env = {key: value for key, value in os.environ.items() if key in {"PATH", "LD_LIBRARY_PATH"}}
    env["CUDA_VISIBLE_DEVICES"] = "0,1"
    run_checked(
        [
            str(venv_python),
            "-c",
            "import torch; assert torch.cuda.device_count() == 2, torch.cuda.device_count(); "
            "xs=[torch.empty(1, device=f'cuda:{i}') for i in range(2)]; "
            "torch.cuda.synchronize(0); torch.cuda.synchronize(1); print([x.device.index for x in xs])",
        ],
        timeout=120,
        env=env,
    )


def _dry_run_config(
    entrypoint: str,
    config: Path,
    output_parent: Path,
    charter: Path,
    venv_bin: Path,
    hf_home: Path,
    timeout: int,
) -> dict[str, object]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "HOME", "LANG", "LC_ALL", "LD_LIBRARY_PATH", "CUDA_HOME"}
    }
    env.update(
        {
            "PATH": f"{venv_bin}:{env.get('PATH', '/usr/bin:/bin')}",
            "CUDA_VISIBLE_DEVICES": "0,1",
            "FILIOLAE_CHARTER": str(charter),
            "HF_HOME": str(hf_home),
            "HF_HUB_OFFLINE": "1",
            "HF_DATASETS_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "WANDB_MODE": "offline",
        }
    )
    with tempfile.TemporaryDirectory(prefix=".filiolae-dry-run-", dir=output_parent) as temporary:
        dry_output = Path(temporary) / "output"
        result = run_checked(
            [entrypoint, "@", str(config), "--output-dir", str(dry_output), "--dry-run"],
            timeout=timeout,
            env=env,
        )
        resolved = require_regular_file(dry_output / "configs" / "orchestrator.toml")
        resolved_config = tomllib.loads(resolved.read_text())
        if resolved_config.get("weight_broadcast", {}).get("type") != "filesystem":
            raise SmokeToolError("dry-run resolved config is not filesystem broadcast")
        return {
            "stdout": result.stdout[-4000:],
            "resolved_config_sha256": __import__("common").sha256_file(resolved),
            "weight_broadcast_type": "filesystem",
        }


def preflight(args: argparse.Namespace) -> dict[str, object]:
    payload = Path(args.payload_dir).absolute()
    absolute_no_symlinks(payload)
    manifest = load_manifest(payload)
    expected_run = manifest.get("runs", {}).get(args.profile)
    if expected_run != args.run_id:
        raise SmokeToolError(f"payload {args.profile} run ID does not match requested run ID")
    if (
        manifest.get("prime_rl_commit") != PRIME_RL_SHA
        or manifest.get("verifiers_commit") != VERIFIERS_SHA
        or manifest.get("submodules") != PRIME_SUBMODULES
    ):
        raise SmokeToolError("payload host pins are inconsistent")
    prime_rl = Path(args.prime_rl).absolute()
    patch = require_regular_file(payload / "prime-rl-fail-closed.patch")
    source_archive = require_regular_file(payload / "prime-rl-patched.tar")
    source_manifest = require_regular_file(payload / "prime-rl-source-manifest.json")
    if args.bootstrap_source:
        _extract_patched_source(source_archive, prime_rl)
    absolute_no_symlinks(prime_rl)
    _validate_patched_prime(prime_rl, patch, source_manifest)
    for archived_name, live_name in (
        ("prime-rl.pyproject.toml", "pyproject.toml"),
        ("prime-rl.uv.lock", "uv.lock"),
    ):
        archived = require_regular_file(payload / archived_name)
        live = require_regular_file(prime_rl / live_name)
        if archived.read_bytes() != live.read_bytes():
            raise SmokeToolError(f"remote prime-rl {live_name} differs from archived payload pin")
    config_name = "smoke.toml" if args.profile == "happy" else "tamper.toml"
    config = require_regular_file(payload / config_name)
    charter = require_regular_file(payload / "charter.yaml")
    wheel = _payload_wheel(manifest, payload)
    venv_dir = Path(args.venv_dir).absolute() if args.venv_dir else prime_rl / ".venv"
    bundled_uv = _require_executable(payload / "bin" / "uv")
    if sha256_file(bundled_uv) != ("646adf5cf12ba17d1a41fa77c8dd6496f73651dcfeeed6b5f4ec019b36bc7153"):
        raise SmokeToolError("bundled uv 0.11.8 digest mismatch")
    if args.bootstrap_frozen:
        if venv_dir != prime_rl / ".venv":
            raise SmokeToolError("frozen bootstrap requires the canonical PRIME_RL/.venv path")
        run_checked(
            [str(bundled_uv), *FROZEN_SYNC_ARGS],
            cwd=prime_rl,
            timeout=args.bootstrap_timeout,
        )
    venv_python = _require_executable(venv_dir / "bin" / "python")
    # Refresh Filiolae and both console wrappers from the manifest-bound wheel on every profile,
    # including later no-network tamper runs against an already-created prime-rl environment.
    run_checked(
        [
            str(bundled_uv),
            "pip",
            "install",
            "--python",
            str(venv_python),
            "--reinstall",
            "--no-deps",
            str(wheel),
        ],
        cwd=prime_rl,
        timeout=120,
    )
    installed_root = _validate_installed_wheel(wheel, venv_python)
    runtime_lineage = _validate_runtime_lineage(venv_python, prime_rl)
    entrypoints = {
        name: str(_require_executable(venv_dir / "bin" / name))
        for name in ("filiolae", "filiolae-rl", "vllm-router")
    }
    private_key = require_regular_file(Path(args.anchor_private_key).absolute(), mode=0o600)
    _validate_config(config, expected_steps=2 if args.profile == "happy" else 4)

    output = Path(args.output).absolute()
    anchor_dir = Path(args.anchor_dir).absolute()
    report_path = Path(args.report).absolute()
    for path, label in ((output, "output"), (anchor_dir, "anchor directory")):
        if path.exists():
            raise SmokeToolError(f"fresh {label} path required: {path}")
        absolute_no_symlinks(path.parent)
    if private_key.is_relative_to(output) or private_key.is_relative_to(anchor_dir):
        raise SmokeToolError("anchor private key must be outside output and receipt directory")
    if anchor_dir.is_relative_to(output) or output.is_relative_to(anchor_dir):
        raise SmokeToolError("output and anchor receipt directory must be disjoint")
    absolute_no_symlinks(report_path.parent)
    if report_path.exists():
        raise SmokeToolError(f"refusing to replace preflight report: {report_path}")

    gpu_policy = manifest.get("gpu_policy")
    if not isinstance(gpu_policy, dict) or gpu_policy.get("count") != 2:
        raise SmokeToolError("payload GPU policy is invalid")
    min_free = manifest.get("min_free_bytes")
    if not isinstance(min_free, int) or min_free < 10 * 1024**3:
        raise SmokeToolError("payload has an invalid minimum-free-space policy")
    free = shutil.disk_usage(output.parent).free
    if free < min_free:
        raise SmokeToolError(f"insufficient free space: {free} bytes available, {min_free} required")
    for required in args.require_path:
        candidate = Path(required).absolute()
        absolute_no_symlinks(candidate)
        if not os.access(candidate, os.R_OK):
            raise SmokeToolError(f"required offline cache asset is unreadable: {candidate}")

    for command in ("git", "timeout"):
        if shutil.which(command) is None:
            raise SmokeToolError(f"required command is unavailable: {command}")
    import_check = run_checked(
        [
            str(venv_python),
            "-c",
            "import filiolae, flash_attn, prime_rl, prime_rl.trainer.model, reverse_text_v1; "
            "from filiolae.anchor import load_private_key; "
            "from filiolae.charter import Charter; import pathlib, sys; "
            "load_private_key(pathlib.Path(sys.argv[1])); Charter.load(pathlib.Path(sys.argv[2]))",
            str(private_key),
            str(charter),
        ],
        timeout=60,
    )
    del import_check
    gpus = _gpu_report(gpu_policy)
    _cuda_allocation_check(venv_python)
    hf_home = Path(args.hf_home).absolute()
    model_snapshot = _assert_model_snapshot(
        manifest,
        hf_home,
        venv_python,
        prefetch=args.prefetch_model,
        timeout=args.prefetch_timeout,
    )
    dataset_evidence = _assert_dataset_snapshot(
        manifest,
        hf_home,
        venv_python,
        prefetch=args.prefetch_dataset,
        timeout=args.prefetch_timeout,
    )
    null_harness = _prepare_null_harness(
        payload,
        prime_rl,
        venv_dir / "bin",
        hf_home,
        prefetch=args.prefetch_harness,
        timeout=args.prefetch_timeout,
    )
    dry_run = _dry_run_config(
        entrypoints["filiolae-rl"],
        config,
        output.parent,
        charter,
        venv_dir / "bin",
        hf_home,
        args.dry_run_timeout,
    )

    output.mkdir(mode=0o700)
    anchor_dir.mkdir(mode=0o700)
    report: dict[str, object] = {
        "schema": "filiolae.two-gpu-remote-preflight.v1",
        "ok": True,
        "ts": datetime.now(UTC).isoformat(),
        "run_id": args.run_id,
        "profile": args.profile,
        "config": str(config),
        "payload_manifest_sha256": __import__("common").sha256_file(payload / "manifest.json"),
        "prime_rl_commit": PRIME_RL_SHA,
        "verifiers_commit": VERIFIERS_SHA,
        "output": str(output),
        "anchor_dir": str(anchor_dir),
        "free_bytes_before_run": free,
        "gpus": gpus,
        "model_snapshot": str(model_snapshot),
        "dataset": dataset_evidence,
        "null_harness": null_harness,
        "dry_run": dry_run,
        "containment": "POSIX process group; setsid escape remains possible; not a systemd/cgroup claim",
        "candidate_quality_evaluated": False,
        "installed_filiolae_root": installed_root,
        "runtime_lineage": runtime_lineage,
        "allowed_build_generated_source_files": BUILD_GENERATED_SOURCE_FILES,
        "entrypoints": entrypoints,
        "venv_dir": str(venv_dir),
        "bootstrap_source": args.bootstrap_source,
        "bootstrap_frozen": args.bootstrap_frozen,
        "bootstrap_command": ("uv " + " ".join(FROZEN_SYNC_ARGS) if args.bootstrap_frozen else None),
    }
    atomic_write_json(report_path, report)
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload-dir", required=True)
    parser.add_argument("--prime-rl", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--profile", choices=("happy", "tamper"), required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--anchor-private-key", required=True)
    parser.add_argument("--anchor-dir", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--venv-dir", help="default: PRIME_RL/.venv")
    parser.add_argument(
        "--bootstrap-source",
        action="store_true",
        help="extract the payload's verified pre-patched source into a fresh --prime-rl path",
    )
    parser.add_argument(
        "--bootstrap-frozen",
        action="store_true",
        help=("run only frozen prime-rl + reverse-text-v1 sync, then install payload wheel without deps"),
    )
    parser.add_argument("--bootstrap-timeout", type=int, default=900)
    parser.add_argument("--hf-home", required=True, help="prepopulated/prefetched exact model cache")
    parser.add_argument("--prefetch-model", action="store_true")
    parser.add_argument("--prefetch-dataset", action="store_true")
    parser.add_argument("--prefetch-harness", action="store_true")
    parser.add_argument("--prefetch-timeout", type=int, default=900)
    parser.add_argument("--dry-run-timeout", type=int, default=180)
    parser.add_argument("--require-path", action="append", default=[], help="offline cache path; repeatable")
    return parser.parse_args()


def main() -> int:
    try:
        report = preflight(parse_args())
    except SmokeToolError as exc:
        print(f"remote preflight failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
