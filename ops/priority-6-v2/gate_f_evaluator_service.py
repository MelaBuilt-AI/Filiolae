#!/usr/bin/env python3
"""Distinct-credential real-model paired evaluator for Priority 6 v2 Gate F."""

from __future__ import annotations

import argparse
import gc
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import stat
import sys
import time
from pathlib import Path
from typing import Any

import filiolae.anchor
import filiolae.artifacts
import filiolae.canonical
import filiolae.paired_eval
import filiolae.shadow_eval
from filiolae.artifacts import digest_path
from filiolae.canonical import canonical_json
from filiolae.paired_eval import (
    load_request,
    request_sha256,
    run_model_outputs_evaluator,
    verify_model_evaluator_bundle,
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def load_module(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("filiolae_gate_f_runtime", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pinned model runtime")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def verify_executing_bundle(bundle_path: Path, service_path: Path, runtime_path: Path) -> dict[str, Any]:
    bundle = verify_model_evaluator_bundle(bundle_path)
    package = Path(filiolae.paired_eval.__file__).parent
    observed_files = {
        "filiolae/anchor.py": sha256(Path(filiolae.anchor.__file__)),
        "filiolae/artifacts.py": sha256(Path(filiolae.artifacts.__file__)),
        "filiolae/canonical.py": sha256(Path(filiolae.canonical.__file__)),
        "filiolae/paired_eval.py": sha256(Path(filiolae.paired_eval.__file__)),
        "filiolae/shadow_eval.py": sha256(Path(filiolae.shadow_eval.__file__)),
        "ops/gate_d_runtime.py": sha256(runtime_path),
        "ops/gate_f_evaluator_service.py": sha256(service_path),
    }
    if bundle["files"] != observed_files:
        raise RuntimeError("executing model evaluator bytes differ from pinned bundle")
    observed_runtime = {
        "cryptography": importlib.metadata.version("cryptography"),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "safetensors": importlib.metadata.version("safetensors"),
        "torch": importlib.metadata.version("torch"),
        "transformers": importlib.metadata.version("transformers"),
    }
    if bundle["runtime"] != observed_runtime:
        raise RuntimeError(f"model evaluator runtime differs from pinned bundle: {observed_runtime}")
    return {"files": observed_files, "runtime": observed_runtime, "package": str(package)}


def completions(path: Path) -> list[dict[str, str]]:
    values = json.loads(path.read_text())
    return [{"case_id": value["case_id"], "completion": value["completion"]} for value in values]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-root", required=True, type=Path)
    parser.add_argument("--terminal-root", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--model-metadata", required=True, type=Path)
    parser.add_argument("--evaluator-bundle", required=True, type=Path)
    parser.add_argument("--suite", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--source-manifest", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--allowed-request", required=True, type=Path)
    parser.add_argument("--outputs", required=True, type=Path)
    parser.add_argument("--proof", required=True, type=Path)
    parser.add_argument("--gate-runtime", required=True, type=Path)
    parser.add_argument("--service-path", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=float, default=600)
    parser.add_argument("--batch-size", type=int, default=64)
    args = parser.parse_args()
    bundle_proof = verify_executing_bundle(args.evaluator_bundle, args.service_path, args.gate_runtime)
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

    runtime = load_module(args.gate_runtime)
    rows = runtime.load_cases(args.suite, expected_count=128)
    summaries: dict[str, Any] = {}
    output_paths: dict[str, Path] = {}
    for name, model_path in (("source", args.source), ("candidate", args.candidate)):
        model, tokenizer = runtime.load_runtime(model_path, args.model_metadata)
        model.to("cuda:0")
        output_path = args.outputs.parent / f"{name}-raw-results.json"
        summaries[name] = runtime.evaluate_model(
            model, tokenizer, rows, output_path, batch_size=args.batch_size
        )
        output_paths[name] = output_path
        del model, tokenizer
        gc.collect()
        import torch

        torch.cuda.empty_cache()

    _, source_sha, _ = digest_path(args.source)
    _, candidate_sha, _ = digest_path(args.candidate)
    model_outputs = {
        "bindings": {
            "candidate_sha256": candidate_sha,
            "config_sha256": sha256(args.config),
            "evaluator_sha256": sha256(args.evaluator_bundle),
            "source_policy_sha256": sha256(args.source_manifest),
            "source_sha256": source_sha,
            "suite_sha256": sha256(args.suite),
        },
        "candidate": completions(output_paths["candidate"]),
        "inference": {
            "batch_size": args.batch_size,
            "bundle": bundle_proof,
            "candidate_summary": summaries["candidate"],
            "device": "cuda:0",
            "do_sample": False,
            "max_new_tokens": 96,
            "source_summary": summaries["source"],
        },
        "schema": "filiolae.paired-eval-model-outputs.v1",
        "source": completions(output_paths["source"]),
    }
    args.outputs.write_bytes(canonical_json(model_outputs) + b"\n")
    args.outputs.chmod(0o640)
    receipt = run_model_outputs_evaluator(
        request_path=request_path,
        source_path=args.source,
        candidate_path=args.candidate,
        evaluator_bundle=args.evaluator_bundle,
        suite_path=args.suite,
        config_path=args.config,
        source_manifest_path=args.source_manifest,
        private_key_path=args.private_key,
        allowed_request_path=args.allowed_request,
        outputs_path=args.outputs,
        terminal_root=args.terminal_root,
    )
    info = args.allowed_request.stat(follow_symlinks=False)
    proof = {
        "candidate_quality_bps": receipt.body["candidate_quality_bps"],
        "evaluator_gid": os.getgid(),
        "evaluator_pid": os.getpid(),
        "evaluator_uid": os.getuid(),
        "model_outputs_sha256": sha256(args.outputs),
        "request_allowlist_mode": f"{stat.S_IMODE(info.st_mode):04o}",
        "request_allowlist_owner_uid": info.st_uid,
        "request_sha256": digest,
        "schema": "filiolae.priority6-v2-gate-f-evaluator-service-proof.v1",
        "source_quality_bps": receipt.body["source_quality_bps"],
        "terminal_status": receipt.body["status"],
    }
    args.proof.write_bytes(canonical_json(proof) + b"\n")
    args.proof.chmod(0o640)
    print(json.dumps(proof, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
