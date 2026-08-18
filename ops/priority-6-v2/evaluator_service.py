#!/usr/bin/env python3
"""Evaluator-owned one-request CPU fixture service for Priority 6 v2 CI."""

from __future__ import annotations

import argparse
import json
import os
import stat
import time
from pathlib import Path

from filiolae.canonical import canonical_json
from filiolae.paired_eval import load_request, request_sha256, run_cpu_fixture_evaluator


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-root", required=True, type=Path)
    parser.add_argument("--terminal-root", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--evaluator-bundle", required=True, type=Path)
    parser.add_argument("--suite", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--source-manifest", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--allowed-request", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--proof", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=float, default=60)
    args = parser.parse_args()
    deadline = time.monotonic() + args.timeout_seconds
    request_files: list[Path] = []
    while time.monotonic() < deadline:
        request_files = sorted(args.request_root.glob("*.json"))
        if request_files:
            break
        time.sleep(0.02)
    if len(request_files) != 1:
        raise RuntimeError("evaluator did not receive exactly one bounded request")
    request_path = request_files[0]
    request = load_request(request_path)
    digest = request_sha256(request)
    if request_path.name != f"{digest}.json":
        raise RuntimeError("request filename does not match its canonical digest")
    descriptor = os.open(
        args.allowed_request,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        0o400,
    )
    try:
        os.fchmod(descriptor, 0o400)
        os.write(descriptor, (digest + "\n").encode("ascii"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    receipt = run_cpu_fixture_evaluator(
        request_path=request_path,
        source_path=args.source,
        candidate_path=args.candidate,
        evaluator_bundle=args.evaluator_bundle,
        suite_path=args.suite,
        config_path=args.config,
        source_manifest_path=args.source_manifest,
        private_key_path=args.private_key,
        allowed_request_path=args.allowed_request,
        fixture_path=args.fixture,
        terminal_root=args.terminal_root,
    )
    info = args.allowed_request.stat(follow_symlinks=False)
    proof = {
        "evaluator_gid": os.getgid(),
        "evaluator_pid": os.getpid(),
        "evaluator_uid": os.getuid(),
        "request_allowlist_mode": f"{stat.S_IMODE(info.st_mode):04o}",
        "request_allowlist_owner_uid": info.st_uid,
        "request_sha256": digest,
        "schema": "filiolae.priority6-v2-evaluator-service-proof.v1",
        "terminal_status": receipt.body["status"],
    }
    args.proof.write_bytes(canonical_json(proof) + b"\n")
    args.proof.chmod(0o640)
    print(json.dumps(proof, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
