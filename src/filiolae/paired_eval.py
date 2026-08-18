"""One-shot filesystem protocol for a separately operated paired evaluator.

The CPU fixture path in this module is a protocol rehearsal only. It never performs
model inference and cannot support a model-quality claim.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import uuid
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import asdict
from datetime import UTC, datetime
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .anchor import load_private_key, load_public_key, public_key_id
from .artifacts import ArtifactError, digest_path
from .canonical import canonical_json
from .shadow_eval import (
    CandidateEvalError,
    CandidateEvalPolicy,
    CandidateEvalReceipt,
    CandidateEvalRequest,
    sign_candidate_eval_receipt,
)

REQUEST_SCHEMA = "filiolae.paired-eval-request.v1"
EVIDENCE_SCHEMA = "filiolae.paired-eval-evidence.v1"
FIXTURE_SCHEMA = "filiolae.paired-eval-cpu-fixture.v1"
MODEL_OUTPUTS_SCHEMA = "filiolae.paired-eval-model-outputs.v1"
CASE_SCHEMA = "filiolae.reverse-text-eval-case.v1"
PRIORITY6_V2_CASE_SCHEMA = "filiolae.priority6-v2-reversal-case.v1"
SOURCE_SCHEMA = "filiolae.source-policy-manifest.v1"
MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
EVIDENCE_SIGNATURE_DOMAIN = b"filiolae-paired-eval-evidence-v1\0"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_TAG = re.compile(r"<reversed_text>(.*?)</reversed_text>", re.DOTALL)


class PairedEvalProtocolError(CandidateEvalError):
    """A bounded, fail-closed paired-evaluation protocol error."""


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _absolute_without_symlinks(path: Path, *, allow_missing_leaf: bool = False) -> Path:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for index, part in enumerate(absolute.parts[1:]):
        current /= part
        if current.is_symlink():
            raise PairedEvalProtocolError("symlink path component is forbidden")
        if not current.exists() and not (allow_missing_leaf and index == len(absolute.parts[1:]) - 1):
            raise PairedEvalProtocolError("required paired-evaluation path component is missing")
    return absolute


def _canonical_document(path: Path, *, maximum: int = MAX_DOCUMENT_BYTES) -> dict[str, Any]:
    try:
        path = _absolute_without_symlinks(path)
        if path.is_symlink() or not path.is_file():
            raise PairedEvalProtocolError("paired-evaluation input must be a regular non-symlink file")
        raw = path.read_bytes()
    except OSError as exc:
        raise PairedEvalProtocolError("paired-evaluation input is unavailable") from exc
    if not raw.endswith(b"\n") or len(raw) > maximum:
        raise PairedEvalProtocolError("paired-evaluation input is not a bounded document")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PairedEvalProtocolError("paired-evaluation input is invalid JSON") from exc
    if not isinstance(value, dict) or raw != canonical_json(value) + b"\n":
        raise PairedEvalProtocolError("paired-evaluation input is not canonical JSON")
    return value


def request_body(request: CandidateEvalRequest) -> dict[str, Any]:
    return {
        "attempt_id": request.attempt_id,
        "candidate_sha256": request.candidate_sha256,
        "evaluated_ledger_head_sha256": request.evaluated_ledger_head_sha256,
        "evaluated_ledger_seq": request.evaluated_ledger_seq,
        "policy": asdict(request.policy),
        "run_id": request.run_id,
        "schema": REQUEST_SCHEMA,
        "source_policy_version": request.source_policy_version,
        "step": request.step,
    }


def request_bytes(request: CandidateEvalRequest) -> bytes:
    return canonical_json(request_body(request)) + b"\n"


def request_sha256(request: CandidateEvalRequest) -> str:
    return hashlib.sha256(request_bytes(request)).hexdigest()


def request_from_bytes(raw: bytes) -> CandidateEvalRequest:
    if not raw.endswith(b"\n") or len(raw) > 64 * 1024:
        raise PairedEvalProtocolError("paired-evaluation request is not a bounded document")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PairedEvalProtocolError("paired-evaluation request is invalid JSON") from exc
    expected = {
        "attempt_id",
        "candidate_sha256",
        "evaluated_ledger_head_sha256",
        "evaluated_ledger_seq",
        "policy",
        "run_id",
        "schema",
        "source_policy_version",
        "step",
    }
    if not isinstance(value, dict) or set(value) != expected or raw != canonical_json(value) + b"\n":
        raise PairedEvalProtocolError("paired-evaluation request fields or canonical form are invalid")
    if value["schema"] != REQUEST_SCHEMA:
        raise PairedEvalProtocolError("paired-evaluation request schema is unsupported")
    for name in ("run_id", "attempt_id"):
        if not isinstance(value[name], str) or not value[name] or len(value[name]) > 256:
            raise PairedEvalProtocolError(f"paired-evaluation request {name} is invalid")
    for name in ("candidate_sha256", "evaluated_ledger_head_sha256"):
        if not isinstance(value[name], str) or _HEX64.fullmatch(value[name]) is None:
            raise PairedEvalProtocolError(f"paired-evaluation request {name} is invalid")
    for name, minimum in (("step", 1), ("source_policy_version", 0), ("evaluated_ledger_seq", 0)):
        field = value[name]
        if isinstance(field, bool) or not isinstance(field, int) or field < minimum or field > 2**63 - 1:
            raise PairedEvalProtocolError(f"paired-evaluation request {name} is invalid")
    try:
        policy = CandidateEvalPolicy.from_parameters(value["policy"])
    except CandidateEvalError as exc:
        raise PairedEvalProtocolError(str(exc)) from exc
    return CandidateEvalRequest(
        run_id=value["run_id"],
        attempt_id=value["attempt_id"],
        step=value["step"],
        source_policy_version=value["source_policy_version"],
        candidate_sha256=value["candidate_sha256"],
        evaluated_ledger_seq=value["evaluated_ledger_seq"],
        evaluated_ledger_head_sha256=value["evaluated_ledger_head_sha256"],
        policy=policy,
    )


def load_request(path: Path) -> CandidateEvalRequest:
    try:
        path = _absolute_without_symlinks(path)
        if path.is_symlink() or not path.is_file():
            raise PairedEvalProtocolError("paired-evaluation request must be a regular file")
        return request_from_bytes(path.read_bytes())
    except OSError as exc:
        raise PairedEvalProtocolError("paired-evaluation request is unavailable") from exc


def _digest(path: Path) -> str:
    try:
        return digest_path(_absolute_without_symlinks(path))[1]
    except (ArtifactError, FileNotFoundError, OSError, TypeError, ValueError) as exc:
        raise PairedEvalProtocolError("paired-evaluation artifact is unavailable or unsafe") from exc


def evaluator_bundle_body() -> dict[str, Any]:
    """Return the exact in-tree code identity used by the CPU evaluator worker."""
    package = Path(__file__).parent
    names = (
        "anchor.py",
        "artifacts.py",
        "canonical.py",
        "paired_eval.py",
        "paired_eval_worker.py",
        "shadow_eval.py",
    )
    return {
        "cryptography_constraint": ">=45,<47",
        "files": {name: hashlib.sha256((package / name).read_bytes()).hexdigest() for name in names},
        "purpose": "cpu-protocol-rehearsal-no-quality-claim",
        "python_constraint": ">=3.11,<3.13",
        "schema": "filiolae.paired-evaluator-bundle.v1",
    }


def verify_evaluator_bundle(path: Path) -> None:
    bundle = _canonical_document(path, maximum=64 * 1024)
    if bundle != evaluator_bundle_body():
        raise PairedEvalProtocolError("executing evaluator code differs from the pinned bundle")


def verify_model_evaluator_bundle(path: Path) -> dict[str, Any]:
    """Validate the bounded identity document for a real-model paired evaluator.

    The evaluator service additionally compares every listed digest with the bytes it
    executes. This parser keeps the signed request bound to a canonical, reviewable
    evaluator identity without treating the CPU fixture bundle as model-quality code.
    """
    bundle = _canonical_document(path, maximum=64 * 1024)
    files = bundle.get("files")
    runtime = bundle.get("runtime")
    if (
        set(bundle) != {"files", "purpose", "runtime", "schema"}
        or bundle.get("schema") != "filiolae.priority6-v2-model-evaluator-bundle.v1"
        or bundle.get("purpose") != "final-acceptance-real-model-paired-inference"
        or not isinstance(files, dict)
        or not files
        or any(
            not isinstance(name, str)
            or not name
            or not isinstance(digest, str)
            or _HEX64.fullmatch(digest) is None
            for name, digest in files.items()
        )
        or not isinstance(runtime, dict)
        or not runtime
        or any(
            not isinstance(name, str) or not isinstance(value, str) or not value
            for name, value in runtime.items()
        )
    ):
        raise PairedEvalProtocolError("model evaluator bundle is invalid")
    return bundle


def _verify_inputs(
    request: CandidateEvalRequest,
    *,
    source_path: Path,
    candidate_path: Path,
    evaluator_bundle: Path,
    suite_path: Path,
    config_path: Path,
    source_manifest_path: Path,
    model_evaluator: bool = False,
) -> dict[str, Any]:
    expected = {
        evaluator_bundle: request.policy.evaluator_sha256,
        suite_path: request.policy.suite_sha256,
        config_path: request.policy.config_sha256,
        source_manifest_path: request.policy.source_policy_sha256,
        candidate_path: request.candidate_sha256,
    }
    for path, digest in expected.items():
        if _digest(path) != digest:
            raise PairedEvalProtocolError("paired-evaluation artifact contradicts the signed request")
    if model_evaluator:
        verify_model_evaluator_bundle(evaluator_bundle)
    else:
        verify_evaluator_bundle(evaluator_bundle)
    source = _canonical_document(source_manifest_path, maximum=64 * 1024)
    if (
        source.get("schema") != SOURCE_SCHEMA
        or source.get("source_policy_version") != request.source_policy_version
        or not isinstance(source.get("source_weights"), dict)
    ):
        raise PairedEvalProtocolError("source-policy manifest schema or version is invalid")
    weights = source["source_weights"]
    if set(weights) != {"artifact_kind", "sha256", "size"}:
        raise PairedEvalProtocolError("source-policy manifest weights fields are invalid")
    kind, digest, size = digest_path(_absolute_without_symlinks(source_path))
    if (kind, digest, size) != (weights["artifact_kind"], weights["sha256"], weights["size"]):
        raise PairedEvalProtocolError("source weights contradict the pinned source-policy manifest")
    config = _canonical_document(config_path, maximum=64 * 1024)
    if config.get("schema") != "filiolae.reverse-text-paired-eval-config.v1":
        raise PairedEvalProtocolError("paired-evaluation config schema is unsupported")
    return config


def _load_suite(path: Path) -> list[dict[str, str]]:
    try:
        path = _absolute_without_symlinks(path)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_DOCUMENT_BYTES:
            raise PairedEvalProtocolError("paired-evaluation suite is unavailable or unsafe")
        lines = path.read_bytes().splitlines(keepends=True)
    except OSError as exc:
        raise PairedEvalProtocolError("paired-evaluation suite is unavailable") from exc
    if not lines or len(lines) > 1024:
        raise PairedEvalProtocolError("paired-evaluation suite is empty or has too many cases")
    cases: list[dict[str, str]] = []
    for line in lines:
        if not line.endswith(b"\n"):
            raise PairedEvalProtocolError("paired-evaluation suite has an unterminated line")
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PairedEvalProtocolError("paired-evaluation suite line is invalid JSON") from exc
        if (
            not isinstance(value, dict)
            or set(value) != {"answer", "case_id", "prompt", "schema"}
            or line != canonical_json(value) + b"\n"
            or value.get("schema") not in {CASE_SCHEMA, PRIORITY6_V2_CASE_SCHEMA}
            or any(
                not isinstance(value.get(name), str) or not value[name]
                for name in ("answer", "case_id", "prompt")
            )
            or len(value["case_id"]) > 256
            or len(value["prompt"].encode("utf-8")) > 4096
            or len(value["answer"].encode("utf-8")) > 4096
            or value["answer"] != value["prompt"][::-1]
        ):
            raise PairedEvalProtocolError("paired-evaluation suite case is invalid")
        cases.append(value)
    case_ids = [case["case_id"] for case in cases]
    if case_ids != sorted(case_ids) or len(case_ids) != len(set(case_ids)):
        raise PairedEvalProtocolError("paired-evaluation suite IDs must be unique and sorted")
    return cases


def _validate_config(
    config: dict[str, Any], request: CandidateEvalRequest, cases: list[dict[str, str]]
) -> None:
    suite = config.get("suite")
    prompting = config.get("prompting")
    inference = config.get("inference")
    parsing = config.get("parsing")
    scoring = config.get("scoring")
    thresholds = config.get("charter_thresholds")
    if (
        set(config)
        != {
            "charter_thresholds",
            "inference",
            "parsing",
            "prompting",
            "schema",
            "scoring",
            "suite",
        }
        or not isinstance(suite, dict)
        or suite.get("sha256") != request.policy.suite_sha256
        or suite.get("case_count") != len(cases)
        or suite.get("order") != "case_id_ascii_ascending"
        or not isinstance(prompting, dict)
        or prompting.get("system")
        != "Reverse the text character-by-character. Put your answer in <reversed_text> tags."
        or not isinstance(prompting.get("renderer"), str)
        or not prompting["renderer"]
        or not isinstance(inference, dict)
        or inference.get("do_sample") is not False
        or isinstance(inference.get("temperature"), bool)
        or inference.get("temperature") != 0
        or isinstance(inference.get("top_p"), bool)
        or inference.get("top_p") != 1
        or isinstance(inference.get("completions_per_case"), bool)
        or inference.get("completions_per_case") != 1
        or isinstance(inference.get("case_retry_count"), bool)
        or inference.get("case_retry_count") != 0
        or isinstance(inference.get("max_completion_tokens"), bool)
        or not isinstance(inference.get("max_completion_tokens"), int)
        or not 1 <= inference["max_completion_tokens"] <= 4096
        or parsing
        != {
            "captured_text_normalization": "strip",
            "flags": ["DOTALL"],
            "match": "first",
            "pattern": "<reversed_text>(.*?)</reversed_text>",
        }
        or scoring
        != {
            "diagnostic": "mean_sequence_matcher_ratio_bps",
            "incomplete_case_policy": "error_no_scores",
            "primary": "exact_match_rate_bps",
            "primary_formula": f"floor(10000 * exact_matches / {len(cases)})",
        }
        or not isinstance(thresholds, dict)
        or any(isinstance(value, bool) for value in thresholds.values())
        or thresholds
        != {
            "maximum_receipt_age_seconds": request.policy.maximum_receipt_age_seconds,
            "maximum_regression_bps": request.policy.maximum_regression_bps,
            "minimum_quality_bps": request.policy.minimum_quality_bps,
        }
    ):
        raise PairedEvalProtocolError("paired-evaluation config contradicts the executed scorer")


def _fixture_completions(fixture: dict[str, Any], case_ids: list[str], model: str) -> list[str]:
    values = fixture.get(model)
    if not isinstance(values, list) or len(values) != len(case_ids):
        raise PairedEvalProtocolError("CPU fixture result count is incomplete")
    completions: list[str] = []
    for index, value in enumerate(values):
        if (
            not isinstance(value, dict)
            or set(value) != {"case_id", "completion"}
            or value.get("case_id") != case_ids[index]
            or not isinstance(value.get("completion"), str)
        ):
            raise PairedEvalProtocolError("CPU fixture case ordering or fields are invalid")
        completions.append(value["completion"])
    return completions


def _score(cases: list[dict[str, str]], completions: list[str]) -> tuple[list[dict[str, Any]], int, int]:
    results: list[dict[str, Any]] = []
    exact_count = 0
    lcs_total = 0
    for case, completion in zip(cases, completions, strict=True):
        if not isinstance(completion, str) or len(completion.encode("utf-8")) > 16 * 1024:
            raise PairedEvalProtocolError("paired-evaluation completion is invalid or unbounded")
        match = _TAG.search(completion)
        parsed = match.group(1).strip() if match else ""
        exact = parsed == case["answer"]
        lcs_bps = int(10_000 * SequenceMatcher(None, parsed, case["answer"]).ratio())
        exact_count += int(exact)
        lcs_total += lcs_bps
        results.append(
            {
                "case_id": case["case_id"],
                "completion": completion,
                "exact": exact,
                "lcs_bps": lcs_bps,
                "parsed": parsed,
            }
        )
    quality_bps = 10_000 * exact_count // len(cases)
    mean_lcs_bps = lcs_total // len(cases)
    return results, quality_bps, mean_lcs_bps


def _terminal_path(root: Path, digest: str) -> Path:
    if _HEX64.fullmatch(digest) is None:
        raise PairedEvalProtocolError("terminal request digest is invalid")
    return root / digest[:2] / digest


def _load_terminal(root: Path, digest: str) -> tuple[CandidateEvalReceipt, dict[str, Any], str, str] | None:
    root = _absolute_without_symlinks(root, allow_missing_leaf=True)
    terminal = _terminal_path(root, digest)
    if not terminal.exists():
        return None
    if terminal.is_symlink() or not terminal.is_dir():
        raise PairedEvalProtocolError("terminal result path is unsafe")
    receipt_path = terminal / "receipt.json"
    evidence_path = terminal / "evidence.json"
    try:
        receipt_raw = receipt_path.read_bytes()
        evidence_envelope = _canonical_document(evidence_path)
    except OSError as exc:
        raise PairedEvalProtocolError("terminal result is incomplete") from exc
    receipt = CandidateEvalReceipt.from_bytes(receipt_raw)
    if set(evidence_envelope) != {"body", "signature", "signer_key_id"}:
        raise PairedEvalProtocolError("terminal evidence envelope fields are invalid")
    body = evidence_envelope["body"]
    signer_key_id = evidence_envelope["signer_key_id"]
    signature = evidence_envelope["signature"]
    if (
        not isinstance(body, dict)
        or body.get("schema") != EVIDENCE_SCHEMA
        or body.get("request_sha256") != digest
        or body.get("receipt_sha256") != hashlib.sha256(receipt_raw).hexdigest()
        or signer_key_id != receipt.signer_key_id
        or not isinstance(signature, str)
    ):
        raise PairedEvalProtocolError("terminal result bindings are invalid")
    return receipt, body, signer_key_id, signature


def load_terminal_receipt(root: Path, request: CandidateEvalRequest) -> CandidateEvalReceipt | None:
    loaded = _load_terminal(root, request_sha256(request))
    if loaded is None:
        return None
    receipt, evidence, _, _ = loaded
    if evidence.get("request") != request_body(request):
        raise PairedEvalProtocolError("terminal result belongs to another request")
    return receipt


def verify_terminal_evidence(
    root: Path,
    request: CandidateEvalRequest,
    public_key: Ed25519PublicKey,
    suite_path: Path,
) -> CandidateEvalReceipt:
    """Verify the signed complete-output package and independently recompute scores."""
    loaded = _load_terminal(root, request_sha256(request))
    if loaded is None:
        raise PairedEvalProtocolError("terminal result is missing")
    receipt, evidence, signer_key_id, signature_text = loaded
    if evidence.get("request") != request_body(request):
        raise PairedEvalProtocolError("terminal result belongs to another request")
    if signer_key_id != public_key_id(public_key) or signer_key_id != request.policy.evaluator_signer_key_id:
        raise PairedEvalProtocolError("terminal evidence signer is not request-pinned")
    expected_receipt = {
        "attempt_id": request.attempt_id,
        "candidate_sha256": request.candidate_sha256,
        "config_sha256": request.policy.config_sha256,
        "evaluated_ledger_head_sha256": request.evaluated_ledger_head_sha256,
        "evaluated_ledger_seq": request.evaluated_ledger_seq,
        "evaluator_sha256": request.policy.evaluator_sha256,
        "run_id": request.run_id,
        "source_policy_sha256": request.policy.source_policy_sha256,
        "source_policy_version": request.source_policy_version,
        "step": request.step,
        "suite_sha256": request.policy.suite_sha256,
    }
    if any(receipt.body.get(name) != value for name, value in expected_receipt.items()):
        raise PairedEvalProtocolError("terminal receipt does not bind the exact request")
    try:
        signature = base64.b64decode(signature_text, validate=True)
        public_key.verify(signature, EVIDENCE_SIGNATURE_DOMAIN + canonical_json(evidence))
        public_key.verify(base64.b64decode(receipt.signature, validate=True), receipt.signed_bytes())
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise PairedEvalProtocolError("terminal evidence or receipt signature is invalid") from exc
    if len(signature) != 64:
        raise PairedEvalProtocolError("terminal evidence signature length is invalid")
    cases = _load_suite(suite_path)
    evaluator_uid = evidence.get("evaluator_uid")
    if (
        isinstance(evaluator_uid, bool)
        or not isinstance(evaluator_uid, int)
        or evidence.get("request_allowlist_owner_uid") != evaluator_uid
        or evidence.get("request_allowlist_mode") not in {"0400", "0440", "0444"}
    ):
        raise PairedEvalProtocolError("terminal evidence has no valid evaluator-owned request allowlist")
    if receipt.body["status"] == "error":
        if (
            evidence.get("status") != "error"
            or evidence.get("candidate_results") != []
            or evidence.get("source_results") != []
        ):
            raise PairedEvalProtocolError("failed terminal evidence contains unexpected outputs")
        return receipt
    source_results = evidence.get("source_results")
    candidate_results = evidence.get("candidate_results")
    if not isinstance(source_results, list) or not isinstance(candidate_results, list):
        raise PairedEvalProtocolError("terminal evidence output lists are missing")
    for name, results in (("source", source_results), ("candidate", candidate_results)):
        if len(results) != len(cases):
            raise PairedEvalProtocolError(f"terminal {name} output count is incomplete")
    source_recomputed, source_quality, source_lcs = _score(
        cases, [result.get("completion") if isinstance(result, dict) else None for result in source_results]
    )
    candidate_recomputed, candidate_quality, candidate_lcs = _score(
        cases,
        [result.get("completion") if isinstance(result, dict) else None for result in candidate_results],
    )
    if (
        source_results != source_recomputed
        or candidate_results != candidate_recomputed
        or evidence.get("source_mean_lcs_bps") != source_lcs
        or evidence.get("candidate_mean_lcs_bps") != candidate_lcs
        or receipt.body.get("source_quality_bps") != source_quality
        or receipt.body.get("candidate_quality_bps") != candidate_quality
        or evidence.get("status") != "completed"
    ):
        raise PairedEvalProtocolError("terminal evidence scores or complete outputs do not recompute")
    return receipt


def _write_file(path: Path, raw: bytes, *, mode: int = 0o600) -> None:
    descriptor = os.open(
        path,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        os.fchmod(descriptor, mode)
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _commit_terminal(
    root: Path,
    request: CandidateEvalRequest,
    receipt: CandidateEvalReceipt,
    evidence: dict[str, Any],
    private_key: Ed25519PrivateKey,
) -> CandidateEvalReceipt:
    digest = request_sha256(request)
    existing = _load_terminal(root, digest)
    if existing is not None:
        return existing[0]
    root = _absolute_without_symlinks(root, allow_missing_leaf=True)
    parent = _terminal_path(root, digest).parent
    if root.is_symlink() or parent.is_symlink():
        raise PairedEvalProtocolError("terminal store path is unsafe")
    parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    os.chmod(parent, 0o2750)
    temporary = parent / f".{digest}.{uuid.uuid4().hex}"
    temporary.mkdir(mode=0o750)
    os.chmod(temporary, 0o2750)
    receipt_raw = receipt.to_bytes()
    evidence_body = {
        **evidence,
        "receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
        "request": request_body(request),
        "request_sha256": digest,
        "schema": EVIDENCE_SCHEMA,
    }
    evidence_envelope = {
        "body": evidence_body,
        "signature": base64.b64encode(
            private_key.sign(EVIDENCE_SIGNATURE_DOMAIN + canonical_json(evidence_body))
        ).decode(),
        "signer_key_id": public_key_id(private_key.public_key()),
    }
    try:
        _write_file(temporary / "receipt.json", receipt_raw, mode=0o640)
        _write_file(
            temporary / "evidence.json",
            canonical_json(evidence_envelope) + b"\n",
            mode=0o640,
        )
        _fsync_directory(temporary)
        with suppress(FileExistsError):
            os.rename(temporary, _terminal_path(root, digest))
        _fsync_directory(parent)
    finally:
        if temporary.exists():
            for child in temporary.iterdir():
                child.unlink(missing_ok=True)
            temporary.rmdir()
    loaded = _load_terminal(root, digest)
    if loaded is None:
        raise PairedEvalProtocolError("terminal result commit failed")
    return loaded[0]


def _verify_allowed_request(path: Path, request: CandidateEvalRequest) -> dict[str, Any]:
    path = _absolute_without_symlinks(path)
    try:
        info = path.stat(follow_symlinks=False)
        raw = path.read_bytes()
    except OSError as exc:
        raise PairedEvalProtocolError("evaluator request allowlist is unavailable") from exc
    expected = (request_sha256(request) + "\n").encode("ascii")
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o022
        or raw != expected
    ):
        raise PairedEvalProtocolError("request digest is not evaluator-owned and allowlisted")
    return {
        "request_allowlist_mode": f"{stat.S_IMODE(info.st_mode):04o}",
        "request_allowlist_owner_uid": info.st_uid,
        "request_allowlist_sha256": hashlib.sha256(raw).hexdigest(),
    }


def run_cpu_fixture_evaluator(
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
    fixture_path: Path,
    terminal_root: Path,
    clock=None,
) -> CandidateEvalReceipt:
    """Execute a complete deterministic CPU rehearsal and commit one terminal result."""
    request = load_request(request_path)
    allowlist_evidence = _verify_allowed_request(allowed_request_path, request)
    existing = load_terminal_receipt(terminal_root, request)
    if existing is not None:
        return existing
    config = _verify_inputs(
        request,
        source_path=source_path,
        candidate_path=candidate_path,
        evaluator_bundle=evaluator_bundle,
        suite_path=suite_path,
        config_path=config_path,
        source_manifest_path=source_manifest_path,
    )
    key = load_private_key(_absolute_without_symlinks(private_key_path))
    if request.policy.evaluator_signer_key_id != public_key_id(key.public_key()):
        raise PairedEvalProtocolError("evaluator private key is not request-pinned")
    cases = _load_suite(suite_path)
    _validate_config(config, request, cases)
    now = (clock or (lambda: datetime.now(UTC)))()
    fixture_sha256 = _digest(fixture_path)
    try:
        fixture = _canonical_document(fixture_path)
        if (
            hashlib.sha256(canonical_json(fixture) + b"\n").hexdigest() != fixture_sha256
            or fixture.get("schema") != FIXTURE_SCHEMA
            or set(fixture)
            != {
                "candidate",
                "schema",
                "source",
            }
        ):
            raise PairedEvalProtocolError("CPU fixture schema is invalid")
        case_ids = [case["case_id"] for case in cases]
        source_results, source_quality, source_lcs = _score(
            cases, _fixture_completions(fixture, case_ids, "source")
        )
        candidate_results, candidate_quality, candidate_lcs = _score(
            cases, _fixture_completions(fixture, case_ids, "candidate")
        )
    except PairedEvalProtocolError:
        receipt = sign_candidate_eval_receipt(
            request,
            key,
            status="error",
            candidate_quality_bps=None,
            source_quality_bps=None,
            completed_at=now,
        )
        return _commit_terminal(
            terminal_root,
            request,
            receipt,
            {
                **allowlist_evidence,
                "candidate_results": [],
                "cpu_fixture_sha256": fixture_sha256,
                "evaluator_gid": os.getgid(),
                "evaluator_pid": os.getpid(),
                "evaluator_uid": os.getuid(),
                "failure_code": "incomplete-or-invalid-case-output",
                "source_results": [],
                "status": "error",
            },
            key,
        )
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
            "candidate_mean_lcs_bps": candidate_lcs,
            "candidate_results": candidate_results,
            "cpu_fixture_sha256": fixture_sha256,
            "evaluator_gid": os.getgid(),
            "evaluator_pid": os.getpid(),
            "evaluator_uid": os.getuid(),
            "failure_code": None,
            "source_mean_lcs_bps": source_lcs,
            "source_results": source_results,
            "status": "completed",
        },
        key,
    )


def run_model_outputs_evaluator(
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
    outputs_path: Path,
    terminal_root: Path,
    clock=None,
) -> CandidateEvalReceipt:
    """Score and sign evaluator-owned outputs from real, paired model inference.

    Unlike :func:`run_cpu_fixture_evaluator`, this path rejects the fixture bundle
    and requires an explicit real-model evaluator bundle plus model/artifact
    bindings in the evaluator-owned output document.
    """
    request = load_request(request_path)
    allowlist_evidence = _verify_allowed_request(allowed_request_path, request)
    existing = load_terminal_receipt(terminal_root, request)
    if existing is not None:
        return existing
    config = _verify_inputs(
        request,
        source_path=source_path,
        candidate_path=candidate_path,
        evaluator_bundle=evaluator_bundle,
        suite_path=suite_path,
        config_path=config_path,
        source_manifest_path=source_manifest_path,
        model_evaluator=True,
    )
    key = load_private_key(_absolute_without_symlinks(private_key_path))
    if request.policy.evaluator_signer_key_id != public_key_id(key.public_key()):
        raise PairedEvalProtocolError("evaluator private key is not request-pinned")
    cases = _load_suite(suite_path)
    _validate_config(config, request, cases)
    outputs = _canonical_document(outputs_path)
    bindings = outputs.get("bindings")
    expected_bindings = {
        "candidate_sha256": request.candidate_sha256,
        "config_sha256": request.policy.config_sha256,
        "evaluator_sha256": request.policy.evaluator_sha256,
        "source_policy_sha256": request.policy.source_policy_sha256,
        "source_sha256": _digest(source_path),
        "suite_sha256": request.policy.suite_sha256,
    }
    if (
        set(outputs) != {"bindings", "candidate", "inference", "schema", "source"}
        or outputs.get("schema") != MODEL_OUTPUTS_SCHEMA
        or bindings != expected_bindings
        or not isinstance(outputs.get("inference"), dict)
        or not outputs["inference"]
    ):
        raise PairedEvalProtocolError("model output document is invalid or unbound")
    case_ids = [case["case_id"] for case in cases]
    source_results, source_quality, source_lcs = _score(
        cases, _fixture_completions(outputs, case_ids, "source")
    )
    candidate_results, candidate_quality, candidate_lcs = _score(
        cases, _fixture_completions(outputs, case_ids, "candidate")
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
            "candidate_mean_lcs_bps": candidate_lcs,
            "candidate_results": candidate_results,
            "evaluator_gid": os.getgid(),
            "evaluator_pid": os.getpid(),
            "evaluator_uid": os.getuid(),
            "failure_code": None,
            "inference": outputs["inference"],
            "model_outputs_sha256": _digest(outputs_path),
            "source_mean_lcs_bps": source_lcs,
            "source_results": source_results,
            "status": "completed",
        },
        key,
    )


class FilesystemShadowEvaluator:
    """Controller-side adapter for one externally executed filesystem request."""

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
        fixture_path: Path,
        timeout_seconds: float = 30,
        simulation: str | None = None,
    ) -> None:
        if not command or timeout_seconds <= 0 or timeout_seconds > 3600:
            raise PairedEvalProtocolError("external evaluator command or timeout is invalid")
        if simulation not in {None, "lost-response", "crash-before-terminal", "hang"}:
            raise PairedEvalProtocolError("external evaluator simulation mode is invalid")
        self.command = tuple(command)
        self.request_root = _absolute_without_symlinks(Path(request_root), allow_missing_leaf=True)
        self.terminal_root = _absolute_without_symlinks(Path(terminal_root), allow_missing_leaf=True)
        self.source_path = _absolute_without_symlinks(Path(source_path))
        self.evaluator_bundle = _absolute_without_symlinks(Path(evaluator_bundle))
        self.suite_path = _absolute_without_symlinks(Path(suite_path))
        self.config_path = _absolute_without_symlinks(Path(config_path))
        self.source_manifest_path = _absolute_without_symlinks(Path(source_manifest_path))
        # The controller must not need read/stat authority over the evaluator-owned
        # private key. The worker validates the absolute path inside its credential.
        self.private_key_path = Path(os.path.abspath(private_key_path))
        self.public_key_path = _absolute_without_symlinks(Path(public_key_path))
        # As with the key, the controller knows this evaluator-owned path but
        # need not have write authority over it. The worker checks owner/mode/content.
        self.allowed_request_path = Path(os.path.abspath(allowed_request_path))
        self.fixture_path = _absolute_without_symlinks(Path(fixture_path))
        self.timeout_seconds = timeout_seconds
        self.simulation = simulation

    def _write_request(self, request: CandidateEvalRequest) -> Path:
        digest = request_sha256(request)
        self.request_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.request_root / f"{digest}.json"
        raw = request_bytes(request)
        if path.exists():
            if path.is_symlink() or path.read_bytes() != raw:
                raise PairedEvalProtocolError("existing evaluator request contradicts the request digest")
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
            "--fixture",
            str(self.fixture_path),
            "--terminal-root",
            str(self.terminal_root),
        ]
        if self.simulation is not None:
            argv.extend(("--simulate", self.simulation))
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
            raise PairedEvalProtocolError("external evaluator timed out or could not execute") from exc
        recovered = load_terminal_receipt(self.terminal_root, request)
        if recovered is not None:
            return verify_terminal_evidence(
                self.terminal_root,
                request,
                load_public_key(self.public_key_path),
                self.suite_path,
            )
        if result.returncode != 0:
            raise PairedEvalProtocolError("external evaluator exited without a terminal result")
        raise PairedEvalProtocolError("external evaluator returned without a terminal result")
