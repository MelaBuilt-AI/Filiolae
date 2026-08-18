#!/usr/bin/env python3
"""Run all CPU-side checks and build a secret-free two-GPU smoke payload."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from common import (
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
    ensure_outside,
    fsync_directory,
    repo_root,
    require_regular_file,
    run_checked,
    sha256_file,
    validate_run_id,
)


def _git_output(repository: Path, *arguments: str) -> str:
    return run_checked(["git", *arguments], cwd=repository).stdout.strip()


def validate_sources(root: Path, prime_rl: Path) -> tuple[str, str]:
    filiolae_sha = _git_output(root, "rev-parse", "HEAD")
    if _git_output(root, "status", "--porcelain"):
        raise SmokeToolError("Filiolae checkout must be clean before building an acceptance payload")
    if _git_output(prime_rl, "rev-parse", "HEAD") != PRIME_RL_SHA:
        raise SmokeToolError(f"prime-rl must be detached at {PRIME_RL_SHA}")
    if _git_output(prime_rl, "status", "--porcelain"):
        raise SmokeToolError("source prime-rl checkout must be clean and unpatched")
    for submodule_path, expected_sha in PRIME_SUBMODULES.items():
        gitlink = _git_output(prime_rl, "ls-tree", "HEAD", submodule_path).split()
        if len(gitlink) < 3 or gitlink[1] != "commit" or gitlink[2] != expected_sha:
            raise SmokeToolError(f"unexpected {submodule_path} gitlink: {' '.join(gitlink)}")
        submodule = prime_rl / submodule_path
        if _git_output(submodule, "rev-parse", "HEAD") != expected_sha:
            raise SmokeToolError(f"{submodule_path} must be initialized at the pinned commit")
        if _git_output(submodule, "status", "--porcelain"):
            raise SmokeToolError(f"{submodule_path} submodule must be clean")
    patch = require_regular_file(root / "adapters" / "prime-rl-v0.8.0-fail-closed.patch")
    run_checked(["git", "apply", "--check", str(patch)], cwd=prime_rl)
    harness_program = require_regular_file(
        prime_rl / "deps" / "verifiers" / "verifiers" / "v1" / "harnesses" / "null" / "program.py"
    )
    harness_lock = require_regular_file(root / "ops" / "two-gpu-smoke" / "null-harness-program.py.lock")
    with tempfile.TemporaryDirectory(prefix="filiolae-harness-lock-") as temporary:
        script = Path(temporary) / "null-harness-program.py"
        shutil.copyfile(harness_program, script)
        shutil.copyfile(harness_lock, Path(str(script) + ".lock"))
        run_checked(["uv", "lock", "--script", str(script), "--check", "--offline"], timeout=120)
    return filiolae_sha, sha256_file(patch)


def run_quality(root: Path) -> None:
    commands = (
        (["uv", "lock", "--check"], 120),
        (["uv", "run", "ruff", "check", "."], 300),
        (["uv", "run", "ruff", "format", "--check", "."], 300),
        (["uv", "run", "pytest"], 600),
        (["uv", "run", "python", "scripts/release_preflight.py", "--scope", "technical"], 120),
    )
    for command, timeout in commands:
        run_checked(command, cwd=root, timeout=timeout)


def validate_patch_in_worktree(
    root: Path,
    prime_rl: Path,
    temporary_root: Path,
    source_archive: Path,
    source_manifest: Path,
) -> None:
    worktree = temporary_root / "prime-rl-patched"
    patch = root / "adapters" / "prime-rl-v0.8.0-fail-closed.patch"
    run_checked(["git", "worktree", "add", "--detach", str(worktree), PRIME_RL_SHA], cwd=prime_rl)
    try:
        run_checked(["git", "apply", str(patch)], cwd=worktree)
        changed = set(_git_output(worktree, "diff", "--name-only").splitlines())
        if changed != PATCHED_PRIME_FILES:
            raise SmokeToolError(f"patch changed unexpected paths: {sorted(changed)}")
        run_checked(
            [
                sys.executable,
                "-m",
                "py_compile",
                *[str(worktree / item) for item in sorted(PATCHED_PRIME_FILES)],
            ],
            timeout=120,
        )
        excluded_names = {".git", ".venv", ".claude", "__pycache__", ".pytest_cache", ".ruff_cache"}
        source_stage = temporary_root / "prime-rl-source"
        source_stage.mkdir()

        def copy_tracked(repository: Path, destination_prefix: Path = Path()) -> None:
            tracked = run_checked(["git", "ls-files", "-z"], cwd=repository, timeout=120).stdout.split("\0")
            for relative_text in sorted(item for item in tracked if item):
                relative = Path(relative_text)
                if any(part in excluded_names for part in relative.parts):
                    continue
                if repository == worktree and relative.as_posix() in PRIME_SUBMODULES:
                    continue
                source = repository / relative
                absolute_no_symlinks(source)
                info = source.lstat()
                if not stat.S_ISREG(info.st_mode):
                    raise SmokeToolError(f"tracked source is not a regular file: {source}")
                destination = source_stage / destination_prefix / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination, follow_symlinks=False)

        copy_tracked(worktree)
        for submodule_path in PRIME_SUBMODULES:
            copy_tracked(prime_rl / submodule_path, Path(submodule_path))

        file_map = {
            path.relative_to(source_stage).as_posix(): sha256_file(path)
            for path in sorted(source_stage.rglob("*"))
            if path.is_file()
        }
        for submodule_path in PRIME_SUBMODULES:
            if not any(name.startswith(f"{submodule_path}/") for name in file_map):
                raise SmokeToolError(f"patched source archive would omit {submodule_path}")
        atomic_write_json(
            source_manifest,
            {
                "schema": "filiolae.prime-rl-patched-source.v1",
                "prime_rl_commit": PRIME_RL_SHA,
                "verifiers_commit": VERIFIERS_SHA,
                "submodules": PRIME_SUBMODULES,
                "archive_policy": "tracked-regular-files-only; no symlinks or special nodes",
                "patched_files": sorted(PATCHED_PRIME_FILES),
                "files": file_map,
            },
            mode=0o644,
        )

        with tarfile.open(source_archive, "w", dereference=False) as archive:
            archive.add(source_stage, arcname="prime-rl", recursive=True)
    finally:
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(worktree)],
            cwd=prime_rl,
            capture_output=True,
            text=True,
        )


def build_payload(args: argparse.Namespace) -> dict[str, object]:
    root = repo_root()
    prime_rl = Path(args.prime_rl).resolve(strict=True)
    output = Path(args.output).absolute()
    ensure_outside(output, (root, prime_rl))
    if output.exists() or output.with_suffix(output.suffix + ".sha256").exists():
        raise SmokeToolError(f"refusing to overwrite payload output: {output}")
    validate_run_id(args.campaign_id)
    validate_run_id(args.happy_run_id)
    validate_run_id(args.tamper_run_id)
    if args.happy_run_id == args.tamper_run_id:
        raise SmokeToolError("happy and tamper run IDs must be distinct")
    public_key = require_regular_file(Path(args.anchor_public_key).absolute())
    run_checked(
        [
            sys.executable,
            "-c",
            "from filiolae.anchor import load_public_key; import pathlib, sys; "
            "load_public_key(pathlib.Path(sys.argv[1]))",
            str(public_key),
        ],
        cwd=root,
        timeout=30,
    )
    uv_binary = require_regular_file(Path(shutil.which("uv") or "").absolute())
    if sha256_file(uv_binary) != "646adf5cf12ba17d1a41fa77c8dd6496f73651dcfeeed6b5f4ec019b36bc7153":
        raise SmokeToolError("payload build requires Linux x86_64 uv 0.11.8 at the reviewed digest")
    filiolae_sha, patch_sha = validate_sources(root, prime_rl)
    run_quality(root)

    with tempfile.TemporaryDirectory(prefix="filiolae-smoke-build-") as temporary_name:
        temporary_root = Path(temporary_name)
        stage = temporary_root / "payload"
        scripts = stage / "bin"
        scripts.mkdir(parents=True)
        validate_patch_in_worktree(
            root,
            prime_rl,
            temporary_root,
            stage / "prime-rl-patched.tar",
            stage / "prime-rl-source-manifest.json",
        )
        dist = temporary_root / "dist"
        run_checked(["uv", "build", "--wheel", "--out-dir", str(dist)], cwd=root, timeout=300)
        wheels = list(dist.glob("filiolae-*.whl"))
        if len(wheels) != 1:
            raise SmokeToolError(f"expected exactly one built wheel, found {len(wheels)}")
        wheel = wheels[0]
        wheel_name = wheel.name
        if wheel_name.count("-") < 4 or not wheel_name.endswith(".whl"):
            raise SmokeToolError(f"built wheel has an invalid install filename: {wheel_name}")
        copies = {
            wheel_name: wheel,
            "prime-rl-fail-closed.patch": root / "adapters" / "prime-rl-v0.8.0-fail-closed.patch",
            "smoke.toml": root / "examples" / "prime-rl" / "reverse-text-filesystem-smoke.toml",
            "charter.yaml": root / "examples" / "charter.demo.yaml",
            "anchor-public.pem": public_key,
            "prime-rl.pyproject.toml": prime_rl / "pyproject.toml",
            "prime-rl.uv.lock": prime_rl / "uv.lock",
            "null-harness-program.py.lock": root / "ops" / "two-gpu-smoke" / "null-harness-program.py.lock",
        }
        for destination, source in copies.items():
            shutil.copyfile(source, stage / destination, follow_symlinks=False)
        smoke_text = (stage / "smoke.toml").read_text()
        if smoke_text.count("max_steps = 2") != 1:
            raise SmokeToolError("cannot derive tamper profile from the pinned happy profile")
        (stage / "tamper.toml").write_text(smoke_text.replace("max_steps = 2", "max_steps = 4", 1))
        shutil.copyfile(uv_binary, scripts / "uv", follow_symlinks=False)
        os.chmod(scripts / "uv", 0o755)
        shutil.copyfile(Path(__file__).parent / "pip", scripts / "pip", follow_symlinks=False)
        os.chmod(scripts / "pip", 0o755)
        shutil.copyfile(Path(__file__).parent / "bootstrap_remote.sh", scripts / "bootstrap_remote.sh")
        os.chmod(scripts / "bootstrap_remote.sh", 0o755)
        for name in (
            "common.py",
            "remote_preflight.py",
            "run_happy.py",
            "run_tamper.py",
            "tamper_after_step1.py",
            "collect_evidence.py",
        ):
            shutil.copyfile(Path(__file__).parent / name, scripts / name, follow_symlinks=False)
        file_map = {
            path.relative_to(stage).as_posix(): sha256_file(path)
            for path in sorted(stage.rglob("*"))
            if path.is_file()
        }
        manifest: dict[str, object] = {
            "schema": "filiolae.two-gpu-smoke-payload.v1",
            "created_at": datetime.now(UTC).isoformat(),
            "campaign_id": args.campaign_id,
            "runs": {"happy": args.happy_run_id, "tamper": args.tamper_run_id},
            "filiolae_commit": filiolae_sha,
            "prime_rl_commit": PRIME_RL_SHA,
            "verifiers_commit": VERIFIERS_SHA,
            "submodules": PRIME_SUBMODULES,
            "patch_sha256": patch_sha,
            "min_free_bytes": args.min_free_gib * 1024**3,
            "gpu_policy": {
                "name_contains": args.expected_gpu_name,
                "min_memory_mib": args.min_gpu_memory_mib,
                "count": 2,
            },
            "model": {
                "repo_id": MODEL_REPO_ID,
                "snapshot_commit": MODEL_REVISION,
                "lfs_files": MODEL_LFS_FILES,
            },
            "dataset": {
                "repo_id": DATASET_REPO_ID,
                "snapshot_commit": DATASET_REVISION,
                "lfs_files": DATASET_LFS_FILES,
            },
            "filiolae_wheel": wheel_name,
            "files": file_map,
            "non_claims": [
                "local-anchor signing is same-control-domain",
                "process-group containment can be escaped with setsid",
                "this profile does not evaluate candidate quality",
            ],
        }
        atomic_write_json(stage / "manifest.json", manifest, mode=0o644)
        output.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(output, "w:gz") as archive:
            archive.add(stage, arcname="payload", recursive=True)
        payload_sha = sha256_file(output)
        checksum = output.with_suffix(output.suffix + ".sha256")
        checksum.write_text(f"{payload_sha}  {output.name}\n")
        with checksum.open("rb") as stream:
            os.fsync(stream.fileno())
        fsync_directory(output.parent)
    return {
        "payload": str(output),
        "sha256": payload_sha,
        "campaign_id": args.campaign_id,
        "runs": manifest["runs"],
        "filiolae_commit": filiolae_sha,
        "prime_rl_commit": PRIME_RL_SHA,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prime-rl", required=True, help="clean pinned prime-rl checkout")
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--happy-run-id", required=True)
    parser.add_argument("--tamper-run-id", required=True)
    parser.add_argument("--anchor-public-key", required=True, help="public key only; never pass private key")
    parser.add_argument("--output", required=True, help="new .tar.gz path outside both source trees")
    parser.add_argument("--min-free-gib", type=int, default=40)
    parser.add_argument("--expected-gpu-name", default="NVIDIA RTX A6000")
    parser.add_argument("--min-gpu-memory-mib", type=int, default=47000)
    args = parser.parse_args()
    if args.min_free_gib < 10:
        parser.error("--min-free-gib must be at least 10")
    if not args.expected_gpu_name.strip() or args.min_gpu_memory_mib < 10000:
        parser.error("invalid GPU policy")
    return args


def main() -> int:
    try:
        report = build_payload(parse_args())
    except SmokeToolError as exc:
        print(f"preflight failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
