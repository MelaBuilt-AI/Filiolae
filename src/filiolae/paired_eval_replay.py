"""Fail-closed post-hoc replay of retained paired-inference completions.

This module imports already captured completions into the standard Filiolae paired-evaluator
receipt and terminal protocol. It never performs inference and cannot establish live evaluator
isolation or a new model-quality experiment.
"""

from __future__ import annotations

import base64
import hashlib
import os
import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .anchor import load_private_key, load_public_key, public_key_id
from .artifacts import digest_path
from .canonical import canonical_json
from .paired_eval import (
    PairedEvalProtocolError,
    _absolute_without_symlinks,
    _canonical_document,
    _commit_terminal,
    _digest,
    _fsync_directory,
    _load_suite,
    _score,
    _validate_config,
    _verify_allowed_request,
    _write_file,
    load_request,
    load_terminal_receipt,
    request_bytes,
    request_sha256,
    verify_terminal_evidence,
)
from .shadow_eval import CandidateEvalReceipt, CandidateEvalRequest, sign_candidate_eval_receipt

REPLAY_SCHEMA = "filiolae.paired-eval-completion-replay.v1"
REPLAY_CONFIG_SCHEMA = "filiolae.reverse-text-paired-replay-config.v1"
ORIGINAL_RECEIPT_SCHEMA = "filiolae.priority6-stage2-gpu-eval.v1"
ORIGINAL_SIGNATURE_DOMAIN = b"filiolae-priority6-stage2-v1\0"
REPLAY_BUNDLE_PURPOSE = "posthoc-completion-replay-no-live-inference-claim"


def replay_evaluator_bundle_body() -> dict[str, Any]:
    """Return the exact code identity for the post-hoc completion replay worker."""
    package = Path(__file__).parent
    names = (
        "anchor.py",
        "artifacts.py",
        "canonical.py",
        "paired_eval.py",
        "paired_eval_replay.py",
        "paired_eval_replay_worker.py",
        "shadow_eval.py",
    )
    return {
        "cryptography_constraint": ">=45,<47",
        "files": {name: hashlib.sha256((package / name).read_bytes()).hexdigest() for name in names},
        "purpose": REPLAY_BUNDLE_PURPOSE,
        "python_constraint": ">=3.11,<3.13",
        "schema": "filiolae.paired-evaluator-bundle.v1",
    }


def verify_replay_evaluator_bundle(path: Path) -> None:
    bundle = _canonical_document(path, maximum=64 * 1024)
    if bundle != replay_evaluator_bundle_body():
        raise PairedEvalProtocolError("executing replay evaluator code differs from the pinned bundle")


def _verify_replay_inputs(
    request: CandidateEvalRequest,
    *,
    source_path: Path,
    candidate_path: Path,
    evaluator_bundle: Path,
    suite_path: Path,
    config_path: Path,
    source_manifest_path: Path,
    replay_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, str]], int]:
    expected = {
        evaluator_bundle: request.policy.evaluator_sha256,
        suite_path: request.policy.suite_sha256,
        config_path: request.policy.config_sha256,
        source_manifest_path: request.policy.source_policy_sha256,
        candidate_path: request.candidate_sha256,
    }
    for path, digest in expected.items():
        if _digest(path) != digest:
            raise PairedEvalProtocolError("replay artifact contradicts the signed request")
    verify_replay_evaluator_bundle(evaluator_bundle)
    source_manifest = _canonical_document(source_manifest_path, maximum=64 * 1024)
    if (
        source_manifest.get("schema") != "filiolae.source-policy-manifest.v1"
        or source_manifest.get("source_policy_version") != request.source_policy_version
        or not isinstance(source_manifest.get("source_weights"), dict)
    ):
        raise PairedEvalProtocolError("replay source-policy manifest is invalid")
    weights = source_manifest["source_weights"]
    if set(weights) != {"artifact_kind", "sha256", "size"}:
        raise PairedEvalProtocolError("replay source-policy weights fields are invalid")
    kind, digest, size = digest_path(_absolute_without_symlinks(source_path))
    if (kind, digest, size) != (weights["artifact_kind"], weights["sha256"], weights["size"]):
        raise PairedEvalProtocolError("replay source weights contradict the pinned manifest")
    config = _canonical_document(config_path, maximum=64 * 1024)
    if config.get("schema") != REPLAY_CONFIG_SCHEMA or set(config) != {
        "charter_thresholds",
        "inference",
        "parsing",
        "prompting",
        "replay",
        "schema",
        "scoring",
        "suite",
    }:
        raise PairedEvalProtocolError("replay config schema or fields are invalid")
    core = {name: value for name, value in config.items() if name != "replay"}
    core["schema"] = "filiolae.reverse-text-paired-eval-config.v1"
    cases = _load_suite(suite_path)
    _validate_config(core, request, cases)
    replay_config = config["replay"]
    if not isinstance(replay_config, dict) or set(replay_config) != {
        "mode",
        "original_config_sha256",
        "original_receipt_schema",
        "original_receipt_sha256",
        "original_signer_key_id",
        "original_status",
        "package_sha256",
    }:
        raise PairedEvalProtocolError("replay provenance config fields are invalid")
    if (
        replay_config.get("mode") != "posthoc-retained-completions"
        or replay_config.get("original_receipt_schema") != ORIGINAL_RECEIPT_SCHEMA
        or replay_config.get("original_status") not in {"passed", "threshold-failed"}
        or _digest(replay_path) != replay_config.get("package_sha256")
    ):
        raise PairedEvalProtocolError("replay provenance config is invalid")
    _, _, candidate_size = digest_path(_absolute_without_symlinks(candidate_path))
    return config, source_manifest, cases, candidate_size


def _original_public_key(pem: str) -> Ed25519PublicKey:
    if not isinstance(pem, str) or not pem or len(pem.encode("utf-8")) > 4096:
        raise PairedEvalProtocolError("original replay public key is invalid")
    try:
        key = serialization.load_pem_public_key(pem.encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise PairedEvalProtocolError("original replay public key cannot be loaded") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise PairedEvalProtocolError("original replay public key is not Ed25519")
    return key


def _verify_original_receipt(
    package: dict[str, Any],
    config: dict[str, Any],
    request: CandidateEvalRequest,
    source_manifest: dict[str, Any],
    cases: list[dict[str, str]],
    candidate_size: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    replay_config = config["replay"]
    receipt = package.get("original_receipt")
    if not isinstance(receipt, dict) or set(receipt) != {
        "body",
        "signature",
        "signer_key_id",
    }:
        raise PairedEvalProtocolError("original replay receipt envelope is invalid")
    receipt_raw = canonical_json(receipt) + b"\n"
    if hashlib.sha256(receipt_raw).hexdigest() != replay_config["original_receipt_sha256"]:
        raise PairedEvalProtocolError("original replay receipt digest is not config-pinned")
    key = _original_public_key(package.get("original_public_key_pem"))
    raw_key = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = "sha256:" + hashlib.sha256(raw_key).hexdigest()
    if (
        receipt.get("signer_key_id") != key_id
        or replay_config.get("original_signer_key_id") != key_id
        or receipt.get("body", {}).get("signer_key_id") != key_id
    ):
        raise PairedEvalProtocolError("original replay signer is not config-pinned")
    try:
        signature = base64.b64decode(receipt["signature"], validate=True)
        key.verify(signature, ORIGINAL_SIGNATURE_DOMAIN + canonical_json(receipt["body"]))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise PairedEvalProtocolError("original replay receipt signature is invalid") from exc
    if len(signature) != 64:
        raise PairedEvalProtocolError("original replay receipt signature length is invalid")
    body = receipt["body"]
    required_body = {
        "candidate",
        "candidate_size",
        "candidate_tree_sha256",
        "case_retry_count",
        "config_sha256",
        "device",
        "do_sample",
        "dtype",
        "finished_at",
        "maximum_regression_bps",
        "minimum_quality_bps",
        "model_repo_id",
        "model_revision",
        "network_policy",
        "regression_bps",
        "schema",
        "signer_key_id",
        "source",
        "source_manifest_sha256",
        "source_size",
        "source_tree_sha256",
        "started_at",
        "status",
        "suite_sha256",
        "tokenizer_json_sha256",
    }
    if not isinstance(body, dict) or set(body) != required_body:
        raise PairedEvalProtocolError("original replay receipt body fields are invalid")
    source_weights = source_manifest["source_weights"]
    if (
        body.get("schema") != ORIGINAL_RECEIPT_SCHEMA
        or body.get("status") != replay_config["original_status"]
        or body.get("candidate_tree_sha256") != request.candidate_sha256
        or body.get("candidate_size") != candidate_size
        or body.get("source_tree_sha256") != source_weights["sha256"]
        or body.get("source_size") != source_weights["size"]
        or body.get("suite_sha256") != request.policy.suite_sha256
        or body.get("config_sha256") != replay_config["original_config_sha256"]
        or body.get("source_manifest_sha256") != request.policy.source_policy_sha256
        or body.get("minimum_quality_bps") != request.policy.minimum_quality_bps
        or body.get("maximum_regression_bps") != request.policy.maximum_regression_bps
        or body.get("case_retry_count") != 0
        or body.get("do_sample") is not False
    ):
        raise PairedEvalProtocolError("original replay receipt bindings are invalid")
    source_rows = package.get("source_results")
    candidate_rows = package.get("candidate_results")
    if not isinstance(source_rows, list) or not isinstance(candidate_rows, list):
        raise PairedEvalProtocolError("replay completion rows are missing")
    source_recomputed, source_quality, source_lcs = _score(
        cases,
        [row.get("completion") if isinstance(row, dict) else None for row in source_rows],
    )
    candidate_recomputed, candidate_quality, candidate_lcs = _score(
        cases,
        [row.get("completion") if isinstance(row, dict) else None for row in candidate_rows],
    )
    source_sha256 = hashlib.sha256(canonical_json(source_rows) + b"\n").hexdigest()
    candidate_sha256 = hashlib.sha256(canonical_json(candidate_rows) + b"\n").hexdigest()
    if (
        source_rows != source_recomputed
        or candidate_rows != candidate_recomputed
        or body.get("source")
        != {
            "count": len(source_rows),
            "mean_lcs_bps": source_lcs,
            "outputs_sha256": source_sha256,
            "quality_bps": source_quality,
        }
        or body.get("candidate")
        != {
            "count": len(candidate_rows),
            "mean_lcs_bps": candidate_lcs,
            "outputs_sha256": candidate_sha256,
            "quality_bps": candidate_quality,
        }
        or body.get("regression_bps") != source_quality - candidate_quality
    ):
        raise PairedEvalProtocolError("original replay outputs or aggregate claims do not recompute")
    passed = (
        candidate_quality >= request.policy.minimum_quality_bps
        and source_quality - candidate_quality <= request.policy.maximum_regression_bps
    )
    if body["status"] != ("passed" if passed else "threshold-failed"):
        raise PairedEvalProtocolError("original replay threshold status does not recompute")
    provenance = {
        "mode": "posthoc-retained-completions",
        "original_receipt_sha256": replay_config["original_receipt_sha256"],
        "original_signer_key_id": key_id,
        "original_status": body["status"],
        "replay_package_sha256": replay_config["package_sha256"],
    }
    return source_recomputed, candidate_recomputed, provenance


def run_completion_replay_evaluator(
    *,
    request_path: Path,
    source_path: Path,
    candidate_path: Path,
    evaluator_bundle: Path,
    suite_path: Path,
    config_path: Path,
    source_manifest_path: Path,
    private_key_path: Path,
    allowed_request_path: Path,
    replay_path: Path,
    terminal_root: Path,
    clock=None,
) -> CandidateEvalReceipt:
    """Replay retained completions and emit the standard signed paired-eval terminal result."""
    request = load_request(request_path)
    allowlist_evidence = _verify_allowed_request(allowed_request_path, request)
    existing = load_terminal_receipt(terminal_root, request)
    if existing is not None:
        return existing
    config, source_manifest, cases, candidate_size = _verify_replay_inputs(
        request,
        source_path=source_path,
        candidate_path=candidate_path,
        evaluator_bundle=evaluator_bundle,
        suite_path=suite_path,
        config_path=config_path,
        source_manifest_path=source_manifest_path,
        replay_path=replay_path,
    )
    key = load_private_key(_absolute_without_symlinks(private_key_path))
    if request.policy.evaluator_signer_key_id != public_key_id(key.public_key()):
        raise PairedEvalProtocolError("replay evaluator private key is not request-pinned")
    package = _canonical_document(replay_path)
    if (
        set(package)
        != {
            "candidate_results",
            "original_public_key_pem",
            "original_receipt",
            "schema",
            "source_results",
        }
        or package.get("schema") != REPLAY_SCHEMA
    ):
        raise PairedEvalProtocolError("completion replay package schema or fields are invalid")
    source_results, candidate_results, provenance = _verify_original_receipt(
        package, config, request, source_manifest, cases, candidate_size
    )
    source_quality = 10_000 * sum(bool(row["exact"]) for row in source_results) // len(source_results)
    candidate_quality = (
        10_000 * sum(bool(row["exact"]) for row in candidate_results) // len(candidate_results)
    )
    now = (clock or (lambda: datetime.now(UTC)))()
    receipt = sign_candidate_eval_receipt(
        request,
        key,
        status="completed",
        candidate_quality_bps=candidate_quality,
        source_quality_bps=source_quality,
        completed_at=now,
    )
    return _commit_terminal(
        terminal_root,
        request,
        receipt,
        {
            **allowlist_evidence,
            **provenance,
            "candidate_mean_lcs_bps": sum(row["lcs_bps"] for row in candidate_results)
            // len(candidate_results),
            "candidate_results": candidate_results,
            "evaluator_gid": os.getgid(),
            "evaluator_mode": "posthoc-completion-replay-no-live-inference",
            "evaluator_pid": os.getpid(),
            "evaluator_uid": os.getuid(),
            "failure_code": None,
            "source_mean_lcs_bps": sum(row["lcs_bps"] for row in source_results) // len(source_results),
            "source_results": source_results,
            "status": "completed",
        },
        key,
    )


class ReplayFilesystemShadowEvaluator:
    """Controller adapter for an externally executed completion-replay worker."""

    def __init__(
        self,
        command: Sequence[str],
        *,
        request_root: Path,
        terminal_root: Path,
        source_path: Path,
        evaluator_bundle: Path,
        suite_path: Path,
        config_path: Path,
        source_manifest_path: Path,
        private_key_path: Path,
        public_key_path: Path,
        allowed_request_path: Path,
        replay_path: Path,
        timeout_seconds: float = 30,
    ) -> None:
        if not command or timeout_seconds <= 0 or timeout_seconds > 3600:
            raise PairedEvalProtocolError("replay evaluator command or timeout is invalid")
        self.command = tuple(command)
        self.request_root = _absolute_without_symlinks(Path(request_root), allow_missing_leaf=True)
        self.terminal_root = _absolute_without_symlinks(Path(terminal_root), allow_missing_leaf=True)
        self.source_path = _absolute_without_symlinks(Path(source_path))
        self.evaluator_bundle = _absolute_without_symlinks(Path(evaluator_bundle))
        self.suite_path = _absolute_without_symlinks(Path(suite_path))
        self.config_path = _absolute_without_symlinks(Path(config_path))
        self.source_manifest_path = _absolute_without_symlinks(Path(source_manifest_path))
        self.private_key_path = Path(os.path.abspath(private_key_path))
        self.public_key_path = _absolute_without_symlinks(Path(public_key_path))
        self.allowed_request_path = Path(os.path.abspath(allowed_request_path))
        self.replay_path = _absolute_without_symlinks(Path(replay_path))
        self.timeout_seconds = timeout_seconds

    def _write_request(self, request: CandidateEvalRequest) -> Path:
        digest = request_sha256(request)
        self.request_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.request_root / f"{digest}.json"
        raw = request_bytes(request)
        if path.exists():
            if path.is_symlink() or path.read_bytes() != raw:
                raise PairedEvalProtocolError("existing replay request contradicts its digest")
        else:
            _write_file(path, raw)
            os.chmod(path, 0o444)
            _fsync_directory(self.request_root)
        return path

    def evaluate(self, request: CandidateEvalRequest, candidate_path: Path) -> CandidateEvalReceipt:
        existing = load_terminal_receipt(self.terminal_root, request)
        if existing is not None:
            return verify_terminal_evidence(
                self.terminal_root,
                request,
                load_public_key(self.public_key_path),
                self.suite_path,
            )
        request_path = self._write_request(request)
        argv = [
            *self.command,
            "--request",
            str(request_path),
            "--source",
            str(self.source_path),
            "--candidate",
            str(candidate_path),
            "--evaluator-bundle",
            str(self.evaluator_bundle),
            "--suite",
            str(self.suite_path),
            "--config",
            str(self.config_path),
            "--source-manifest",
            str(self.source_manifest_path),
            "--private-key",
            str(self.private_key_path),
            "--allow-request-file",
            str(self.allowed_request_path),
            "--replay",
            str(self.replay_path),
            "--terminal-root",
            str(self.terminal_root),
        ]
        environment = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.defpath,
            "PYTHONHASHSEED": "0",
        }
        try:
            result = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                env=environment,
                text=True,
                timeout=self.timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            recovered = load_terminal_receipt(self.terminal_root, request)
            if recovered is not None:
                return verify_terminal_evidence(
                    self.terminal_root,
                    request,
                    load_public_key(self.public_key_path),
                    self.suite_path,
                )
            raise PairedEvalProtocolError("replay evaluator timed out or could not execute") from exc
        recovered = load_terminal_receipt(self.terminal_root, request)
        if recovered is not None:
            return verify_terminal_evidence(
                self.terminal_root,
                request,
                load_public_key(self.public_key_path),
                self.suite_path,
            )
        if result.returncode != 0:
            raise PairedEvalProtocolError("replay evaluator exited without a terminal result")
        raise PairedEvalProtocolError("replay evaluator returned without a terminal result")
