#!/usr/bin/env python3
"""Finalize a private Priority 6 v2 Gate F evidence package after cleanup."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from filiolae.canonical import canonical_json


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("package", type=Path)
    parser.add_argument("--controller-uid", required=True, type=int)
    parser.add_argument("--evaluator-uid", required=True, type=int)
    args = parser.parse_args()
    package = args.package
    forbidden = [path for path in package.rglob("*") if "private" in path.name.lower()]
    if forbidden:
        raise RuntimeError("private-key-like path found in retained package")
    cleanup = {
        "controller_uid": args.controller_uid,
        "evaluator_private_key_absent": True,
        "evaluator_processes_remaining": 0,
        "evaluator_uid": args.evaluator_uid,
        "schema": "filiolae.priority6-v2-gate-f-cleanup.v1",
    }
    (package / "CLEANUP.json").write_bytes(canonical_json(cleanup) + b"\n")
    data_files = sorted(
        path
        for path in package.rglob("*")
        if path.is_file() and path.name not in {"PACKAGE.json", "SHA256SUMS"}
    )
    manifest = {
        "bounded_claim": "private distinct-UID fresh-GPU final-acceptance model evidence",
        "file_count_excluding_manifests": len(data_files),
        "files": [path.relative_to(package).as_posix() for path in data_files],
        "schema": "filiolae.priority6-v2-gate-f-evidence-package.v1",
    }
    (package / "PACKAGE.json").write_bytes(canonical_json(manifest) + b"\n")
    files = sorted(path for path in package.rglob("*") if path.is_file() and path.name != "SHA256SUMS")
    (package / "SHA256SUMS").write_text(
        "".join(f"{sha256(path)}  {path.relative_to(package).as_posix()}\n" for path in files)
    )
    print(json.dumps({**manifest, "sha256sums_sha256": sha256(package / "SHA256SUMS")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
