"""Digest-bound signed candidate shadow-evaluation receipts."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .anchor import public_key_id
from .artifacts import ArtifactError, digest_path
from .canonical import canonical_json

RECEIPT_SCHEMA = "filiolae.candidate-eval-receipt.v1"
SIGNATURE_DOMAIN = b"filiolae-candidate-eval-receipt-v1\0"
MAX_RECEIPT_BYTES = 64 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_BODY_FIELDS = {
    "schema",
    "run_id",
    "attempt_id",
    "step",
    "source_policy_version",
    "candidate_sha256",
    "source_policy_sha256",
    "evaluator_sha256",
    "suite_sha256",
    "config_sha256",
    "evaluated_ledger_seq",
    "evaluated_ledger_head_sha256",
    "completed_at",
    "status",
    "candidate_quality_bps",
    "source_quality_bps",
}
_RECEIPT_FIELDS = {"body", "signer_key_id", "signature"}
_POLICY_FIELDS = {
    "evaluator_sha256",
    "suite_sha256",
    "config_sha256",
    "source_policy_sha256",
    "evaluator_signer_key_id",
    "minimum_quality_bps",
    "maximum_regression_bps",
    "maximum_receipt_age_seconds",
}


class CandidateEvalError(RuntimeError):
    pass


def _strict_object(raw: bytes) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise CandidateEvalError(f"duplicate candidate-evaluation field: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateEvalError("candidate-evaluation receipt is invalid JSON") from exc
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise CandidateEvalError("candidate-evaluation receipt is not canonical JSON")
    return value


def _integer(value: object, name: str, *, minimum: int = 0, maximum: int = 10_000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise CandidateEvalError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CandidateEvalError("candidate-evaluation completion time must be UTC")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CandidateEvalError("candidate-evaluation completion time is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise CandidateEvalError("candidate-evaluation completion time must be UTC")
    return parsed


@dataclass(frozen=True)
class CandidateEvalPolicy:
    evaluator_sha256: str
    suite_sha256: str
    config_sha256: str
    source_policy_sha256: str
    evaluator_signer_key_id: str
    minimum_quality_bps: int
    maximum_regression_bps: int
    maximum_receipt_age_seconds: int

    @classmethod
    def from_parameters(cls, value: dict[str, Any]) -> CandidateEvalPolicy:
        if not isinstance(value, dict) or set(value) != _POLICY_FIELDS:
            raise CandidateEvalError("candidate shadow-evaluation policy fields are invalid")
        for name in (
            "evaluator_sha256",
            "suite_sha256",
            "config_sha256",
            "source_policy_sha256",
        ):
            if not isinstance(value[name], str) or _HEX64.fullmatch(value[name]) is None:
                raise CandidateEvalError(f"{name} must be lowercase SHA-256")
        signer = value["evaluator_signer_key_id"]
        if not isinstance(signer, str) or _KEY_ID.fullmatch(signer) is None:
            raise CandidateEvalError("evaluator_signer_key_id is invalid")
        return cls(
            evaluator_sha256=value["evaluator_sha256"],
            suite_sha256=value["suite_sha256"],
            config_sha256=value["config_sha256"],
            source_policy_sha256=value["source_policy_sha256"],
            evaluator_signer_key_id=signer,
            minimum_quality_bps=_integer(value["minimum_quality_bps"], "minimum_quality_bps"),
            maximum_regression_bps=_integer(value["maximum_regression_bps"], "maximum_regression_bps"),
            maximum_receipt_age_seconds=_integer(
                value["maximum_receipt_age_seconds"],
                "maximum_receipt_age_seconds",
                minimum=1,
                maximum=3600,
            ),
        )


@dataclass(frozen=True)
class CandidateEvalRequest:
    run_id: str
    attempt_id: str
    step: int
    source_policy_version: int
    candidate_sha256: str
    evaluated_ledger_seq: int
    evaluated_ledger_head_sha256: str
    policy: CandidateEvalPolicy


@dataclass(frozen=True)
class CandidateEvalReceipt:
    body: dict[str, Any]
    signer_key_id: str
    signature: str

    @classmethod
    def from_bytes(cls, raw: bytes) -> CandidateEvalReceipt:
        if not raw.endswith(b"\n") or len(raw) > MAX_RECEIPT_BYTES:
            raise CandidateEvalError("candidate-evaluation receipt is not a bounded document")
        value = _strict_object(raw[:-1])
        if set(value) != _RECEIPT_FIELDS or not isinstance(value["body"], dict):
            raise CandidateEvalError("candidate-evaluation receipt fields are invalid")
        if set(value["body"]) != _BODY_FIELDS:
            raise CandidateEvalError("candidate-evaluation receipt body fields are invalid")
        receipt = cls(value["body"], value["signer_key_id"], value["signature"])
        receipt.validate_types()
        return receipt

    def validate_types(self) -> None:
        body = self.body
        if body.get("schema") != RECEIPT_SCHEMA:
            raise CandidateEvalError("candidate-evaluation receipt schema is unsupported")
        for name in ("run_id", "attempt_id"):
            if not isinstance(body.get(name), str) or not body[name] or len(body[name]) > 256:
                raise CandidateEvalError(f"candidate-evaluation {name} is invalid")
        _integer(body.get("step"), "step", minimum=1, maximum=2**63 - 1)
        _integer(
            body.get("source_policy_version"),
            "source_policy_version",
            minimum=0,
            maximum=2**63 - 1,
        )
        _integer(
            body.get("evaluated_ledger_seq"),
            "evaluated_ledger_seq",
            minimum=0,
            maximum=2**63 - 1,
        )
        for name in (
            "candidate_sha256",
            "source_policy_sha256",
            "evaluator_sha256",
            "suite_sha256",
            "config_sha256",
            "evaluated_ledger_head_sha256",
        ):
            if not isinstance(body.get(name), str) or _HEX64.fullmatch(body[name]) is None:
                raise CandidateEvalError(f"candidate-evaluation {name} is invalid")
        if body.get("status") not in {"completed", "error"}:
            raise CandidateEvalError("candidate-evaluation status is invalid")
        candidate = body.get("candidate_quality_bps")
        source = body.get("source_quality_bps")
        if body["status"] == "completed":
            _integer(candidate, "candidate_quality_bps")
            _integer(source, "source_quality_bps")
        elif candidate is not None or source is not None:
            raise CandidateEvalError("failed candidate evaluation must not contain quality metrics")
        _timestamp(body.get("completed_at"))
        if (
            not isinstance(self.signer_key_id, str)
            or _KEY_ID.fullmatch(self.signer_key_id) is None
            or not isinstance(self.signature, str)
        ):
            raise CandidateEvalError("candidate-evaluation signature metadata is invalid")
        try:
            signature = base64.b64decode(self.signature, validate=True)
        except (ValueError, TypeError) as exc:
            raise CandidateEvalError("candidate-evaluation signature encoding is invalid") from exc
        if len(signature) != 64:
            raise CandidateEvalError("candidate-evaluation signature length is invalid")

    def signed_bytes(self) -> bytes:
        return SIGNATURE_DOMAIN + canonical_json(self.body)

    def to_dict(self) -> dict[str, Any]:
        return {"body": self.body, "signer_key_id": self.signer_key_id, "signature": self.signature}

    def to_bytes(self) -> bytes:
        return canonical_json(self.to_dict()) + b"\n"


class ShadowEvaluator(Protocol):
    def evaluate(self, request: CandidateEvalRequest, candidate_path: Path) -> CandidateEvalReceipt: ...


def sign_candidate_eval_receipt(
    request: CandidateEvalRequest,
    private_key: Ed25519PrivateKey,
    *,
    status: str,
    candidate_quality_bps: int | None,
    source_quality_bps: int | None,
    completed_at: datetime,
) -> CandidateEvalReceipt:
    """Sign one receipt after an evaluator has independently established its result."""
    body = {
        "schema": RECEIPT_SCHEMA,
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
        "step": request.step,
        "source_policy_version": request.source_policy_version,
        "candidate_sha256": request.candidate_sha256,
        "source_policy_sha256": request.policy.source_policy_sha256,
        "evaluator_sha256": request.policy.evaluator_sha256,
        "suite_sha256": request.policy.suite_sha256,
        "config_sha256": request.policy.config_sha256,
        "evaluated_ledger_seq": request.evaluated_ledger_seq,
        "evaluated_ledger_head_sha256": request.evaluated_ledger_head_sha256,
        "completed_at": completed_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "status": status,
        "candidate_quality_bps": candidate_quality_bps,
        "source_quality_bps": source_quality_bps,
    }
    key_id = public_key_id(private_key.public_key())
    signature = base64.b64encode(private_key.sign(SIGNATURE_DOMAIN + canonical_json(body))).decode()
    receipt = CandidateEvalReceipt(body, key_id, signature)
    receipt.validate_types()
    return receipt


class CPUMockShadowEvaluator:
    """Deterministic signed evaluator for control-plane tests, not a model-quality claim."""

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        candidate_quality_bps: int | None,
        source_quality_bps: int | None,
        status: str = "completed",
        clock=None,
    ) -> None:
        self.private_key = private_key
        self.candidate_quality_bps = candidate_quality_bps
        self.source_quality_bps = source_quality_bps
        self.status = status
        self.clock = clock or (lambda: datetime.now(UTC))

    def evaluate(self, request: CandidateEvalRequest, candidate_path: Path) -> CandidateEvalReceipt:
        try:
            _, candidate_sha256, _ = digest_path(candidate_path)
        except (ArtifactError, FileNotFoundError, OSError, TypeError, ValueError) as exc:
            raise CandidateEvalError(f"mock evaluator candidate is unavailable or unsafe: {exc}") from exc
        if candidate_sha256 != request.candidate_sha256:
            raise CandidateEvalError("mock evaluator candidate bytes contradict the requested digest")
        return sign_candidate_eval_receipt(
            request,
            self.private_key,
            status=self.status,
            candidate_quality_bps=self.candidate_quality_bps,
            source_quality_bps=self.source_quality_bps,
            completed_at=self.clock(),
        )


def verify_candidate_eval_receipt(
    receipt: CandidateEvalReceipt,
    request: CandidateEvalRequest,
    public_key: Ed25519PublicKey,
    *,
    now: datetime,
) -> dict[str, int]:
    receipt.validate_types()
    if receipt.signer_key_id != request.policy.evaluator_signer_key_id:
        raise CandidateEvalError("candidate-evaluation signer is not Charter-pinned")
    if public_key_id(public_key) != receipt.signer_key_id:
        raise CandidateEvalError("candidate-evaluation public key is not Charter-pinned")
    try:
        public_key.verify(base64.b64decode(receipt.signature), receipt.signed_bytes())
    except (InvalidSignature, ValueError) as exc:
        raise CandidateEvalError("candidate-evaluation signature is invalid") from exc
    expected = {
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
        "step": request.step,
        "source_policy_version": request.source_policy_version,
        "candidate_sha256": request.candidate_sha256,
        "source_policy_sha256": request.policy.source_policy_sha256,
        "evaluator_sha256": request.policy.evaluator_sha256,
        "suite_sha256": request.policy.suite_sha256,
        "config_sha256": request.policy.config_sha256,
        "evaluated_ledger_seq": request.evaluated_ledger_seq,
        "evaluated_ledger_head_sha256": request.evaluated_ledger_head_sha256,
    }
    for name, value in expected.items():
        if receipt.body.get(name) != value:
            raise CandidateEvalError(f"candidate-evaluation {name} binding mismatch")
    completed = _timestamp(receipt.body["completed_at"])
    age = (now.astimezone(UTC) - completed).total_seconds()
    if age < 0 or age > request.policy.maximum_receipt_age_seconds:
        raise CandidateEvalError("candidate-evaluation receipt is stale or future-dated")
    if receipt.body["status"] != "completed":
        raise CandidateEvalError("candidate evaluator reported failure")
    candidate = _integer(receipt.body["candidate_quality_bps"], "candidate_quality_bps")
    source = _integer(receipt.body["source_quality_bps"], "source_quality_bps")
    regression = max(0, source - candidate)
    if candidate < request.policy.minimum_quality_bps:
        raise CandidateEvalError("candidate quality is below the Charter threshold")
    if regression > request.policy.maximum_regression_bps:
        raise CandidateEvalError("candidate regression exceeds the Charter threshold")
    return {
        "candidate_quality_bps": candidate,
        "source_quality_bps": source,
        "regression_bps": regression,
    }
