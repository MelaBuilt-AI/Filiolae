#!/usr/bin/env python3
"""Shared, standard-library-only helpers for the two-GPU smoke tools."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
PRIME_RL_SHA = "60bc29547a8824ad1de7b9af8d265e2b27b2a72d"
VERIFIERS_SHA = "d30a3f48e5f14b06b3081b2102ec32cc3149b849"
PRIME_SUBMODULES = {
    "deps/pydantic-config": "4f5ae373582ceffdbf7e6bd1998c9ad568fcc1ad",
    "deps/renderers": "d4707862ac83aa3773c21f4096aec72bd17b91e4",
    "deps/research-environments": "f9c43a74fe6179381f108575c8a8426a9923eecc",
    "deps/verifiers": VERIFIERS_SHA,
}
PATCHED_PRIME_FILES = {
    "src/prime_rl/entrypoints/rl.py",
    "src/prime_rl/orchestrator/orchestrator.py",
    "src/prime_rl/orchestrator/types.py",
    "src/prime_rl/orchestrator/watcher.py",
}
# hatch-vcs writes this deterministic fallback file into the VCS-less renderers
# source while uv builds the pinned editable workspace package.
BUILD_GENERATED_SOURCE_FILES = {
    "deps/renderers/renderers/_version.py": (
        "4f6226fa3bc647fbaaf498ba011c579a39b51dad8408ce3b06b22d6dbe0dac82"
    ),
}
MODEL_REPO_ID = "PrimeIntellect/Qwen3-0.6B-Reverse-Text-SFT"
MODEL_REVISION = "c97a910849ec6aa962add3dc253a0817d61c0210"
# Git-LFS object IDs are SHA-256 digests of the exact downloaded bytes.
MODEL_LFS_FILES = {
    "model.safetensors": {
        "size": 2_384_234_968,
        "sha256": "02cf0d57934ba6f692eeefa6cf854749195f1d4da6e6727de0b956ce40fec293",
    },
    "tokenizer.json": {
        "size": 11_422_654,
        "sha256": "aeb13307a71acd8fe81861d94ad54ab689df773318809eed3cbe794b4492dae4",
    },
}
DATASET_REPO_ID = "PrimeIntellect/Reverse-Text-RL"
DATASET_REVISION = "eacc9a0d76d9fd22e40008ab9d546008bdd7e432"
DATASET_LFS_FILES = {
    "data/train-00000-of-00001.parquet": {
        "size": 63_899,
        "sha256": "3cff91965e9de35d04a1d9297535bd13f8268aa38201abec97b6a5d94e7dabe2",
    },
}


class SmokeToolError(RuntimeError):
    """A bounded, operator-actionable smoke-tool failure."""


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def prime_run_output(output: Path) -> Path:
    """Return pinned prime-rl v0.8.0's resolved orchestrator run directory."""
    return output.absolute() / "run_default"


def validate_run_id(value: str) -> str:
    if not RUN_ID_RE.fullmatch(value) or value.startswith((".", "-")):
        raise SmokeToolError(f"unsafe run ID: {value!r}")
    return value


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_json(path: Path, value: Any, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def run_checked(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: float = 300,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(list(argv), cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SmokeToolError(f"command failed to execute: {argv!r}: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[-2000:]
        raise SmokeToolError(f"command exited {result.returncode}: {argv!r}: {detail}")
    return result


def absolute_no_symlinks(path: Path, *, must_exist: bool = True) -> Path:
    if not path.is_absolute():
        raise SmokeToolError(f"path must be absolute: {path}")
    current = Path(path.anchor)
    parts = path.parts[1:]
    for index, part in enumerate(parts):
        current /= part
        if current.is_symlink():
            raise SmokeToolError(f"symlink path component rejected: {current}")
        if must_exist or index < len(parts) - 1:
            try:
                current.lstat()
            except FileNotFoundError as exc:
                raise SmokeToolError(f"required path does not exist: {current}") from exc
    return path


def require_regular_file(path: Path, *, mode: int | None = None) -> Path:
    absolute_no_symlinks(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise SmokeToolError(f"regular file required: {path}")
    if mode is not None and stat.S_IMODE(info.st_mode) != mode:
        raise SmokeToolError(f"unsafe mode for {path}: {stat.S_IMODE(info.st_mode):04o}, expected {mode:04o}")
    return path


def require_safe_tree(root: Path, *, excluded: Iterable[Path] = ()) -> list[Path]:
    """Return regular files, rejecting symlinks and special nodes anywhere in a tree."""
    absolute_no_symlinks(root)
    excluded_resolved = {item.resolve() for item in excluded}
    files: list[Path] = []
    for current_root, directories, names in os.walk(root, followlinks=False):
        base = Path(current_root)
        for name in [*directories, *names]:
            item = base / name
            if item.resolve() in excluded_resolved:
                continue
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise SmokeToolError(f"symlink rejected in evidence tree: {item}")
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode):
                raise SmokeToolError(f"special file rejected in evidence tree: {item}")
            files.append(item)
    return sorted(files)


def ensure_outside(path: Path, protected_roots: Iterable[Path]) -> None:
    resolved = path.resolve(strict=False)
    for root in protected_roots:
        root_resolved = root.resolve(strict=True)
        if resolved == root_resolved or resolved.is_relative_to(root_resolved):
            raise SmokeToolError(f"output must be outside protected source tree {root_resolved}: {path}")


def load_manifest(payload_dir: Path) -> dict[str, Any]:
    manifest_path = require_regular_file(payload_dir / "manifest.json")
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SmokeToolError(f"invalid payload manifest: {exc}") from exc
    if manifest.get("schema") != "filiolae.two-gpu-smoke-payload.v1":
        raise SmokeToolError("unexpected payload manifest schema")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise SmokeToolError("payload manifest has no file map")
    expected_paths: set[str] = set()
    for relative, expected in files.items():
        if not isinstance(relative, str) or relative.startswith(("/", "../")) or "/../" in relative:
            raise SmokeToolError(f"unsafe manifest path: {relative!r}")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise SmokeToolError(f"invalid manifest digest for {relative!r}")
        candidate = require_regular_file(payload_dir / relative)
        if not candidate.resolve().is_relative_to(payload_dir.resolve()):
            raise SmokeToolError(f"manifest path escapes payload: {relative}")
        actual = sha256_file(candidate)
        if actual != expected:
            raise SmokeToolError(f"payload digest mismatch for {relative}: {actual} != {expected}")
        expected_paths.add(relative)
    actual_paths = {
        path.relative_to(payload_dir).as_posix()
        for path in require_safe_tree(payload_dir)
        if path != manifest_path
    }
    unexpected = actual_paths - expected_paths
    missing = expected_paths - actual_paths
    if unexpected or missing:
        raise SmokeToolError(
            f"payload file set differs from manifest: unexpected={sorted(unexpected)[:5]}, "
            f"missing={sorted(missing)[:5]}"
        )
    return manifest


def process_start_token(pid: int) -> str | None:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().split()
    except (FileNotFoundError, OSError):
        return None
    return fields[21] if len(fields) > 21 else None
