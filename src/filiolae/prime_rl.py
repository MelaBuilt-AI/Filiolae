"""Narrow integration surface for a fail-closed prime-rl promotion barrier.

prime-rl v0.8.0's VersionObserver is telemetry-only: exceptions are swallowed and
Policy.version advances before observers run. Filiolae therefore requires the host
to call this adapter as an authorization barrier before changing version state or
loading weights. See adapters/prime-rl-v0.8.0-fail-closed.patch.
"""

from __future__ import annotations

import asyncio
import shutil
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path

from .gate import GateDecision, PromotionGate, PromotionRequest
from .store import ArtifactStore


class PrimeRLPromotionBarrier:
    """Adapter called by the patched WeightWatcher before policy promotion."""

    def __init__(
        self,
        gate: PromotionGate,
        request_for_step: Callable[[int, Path | None], PromotionRequest],
    ) -> None:
        self.gate = gate
        self.request_for_step = request_for_step
        self._pending: dict[int, tuple[PromotionRequest, GateDecision, Path]] = {}

    def _materialize_load_copy(self, request: PromotionRequest, decision: GateDecision) -> Path:
        """Copy approved bytes away from the immutable evidence store before host loading."""
        if decision.approved_checkpoint_path is None:
            raise RuntimeError("Gate approval omitted the staged checkpoint path")
        records = self.gate.ledger.records()
        if request.checkpoint_seq < 0 or request.checkpoint_seq >= len(records):
            raise RuntimeError("approved checkpoint record is unavailable")
        checkpoint = records[request.checkpoint_seq]
        if len(checkpoint.artifacts) != 1 or checkpoint.artifacts[0].name != "candidate_weights":
            raise RuntimeError("approved checkpoint record is malformed")
        artifact = checkpoint.artifacts[0]
        store = ArtifactStore(self.gate.ledger.artifact_root)
        approved = store.resolve(artifact)
        if approved != Path(decision.approved_checkpoint_path).resolve(strict=True):
            raise RuntimeError("Gate approval path differs from the attested checkpoint")
        destination = (
            self.gate.ledger.path.parent / "approved-loads" / f"step-{request.step}-{request.attempt_id}"
        )
        return store.materialize(artifact, destination)

    @staticmethod
    def _remove_load_copy(path: Path) -> None:
        # Cleanup is operational hygiene, not part of the committed promotion outcome.
        with suppress(OSError):
            if path.is_symlink() or path.is_file():
                path.unlink(missing_ok=True)
            elif path.is_dir():
                shutil.rmtree(path)

    def _authorize_sync(
        self,
        step: int,
        current_policy_version: int,
        weights_path: Path | None,
    ) -> Path:
        request = self.request_for_step(step, weights_path)
        if request.step != step:
            raise ValueError(f"promotion request step {request.step} does not match pending step {step}")
        decision = self.gate.require_authorized(
            request,
            current_policy_version=current_policy_version,
            pending_weights_path=weights_path,
        )
        load_copy = self._materialize_load_copy(request, decision)
        if self.gate.freezer.state().frozen:
            self._remove_load_copy(load_copy)
            raise RuntimeError("run froze while authorization was in progress")
        self._pending[step] = (request, decision, load_copy)
        return load_copy

    async def authorize_version(
        self,
        step: int,
        current_policy_version: int,
        weights_path: Path | None,
    ) -> Path:
        try:
            # Filesystem hashing/copying and Ledger locks must not block host cancellation/timeouts.
            return await asyncio.to_thread(self._authorize_sync, step, current_policy_version, weights_path)
        except Exception as exc:
            self.gate.fail_closed_control_error(
                step=step,
                source_policy_version=current_policy_version,
                reason=f"promotion barrier failure: {type(exc).__name__}: {exc}",
            )
            raise

    def _record_outcome_sync(
        self,
        step: int,
        *,
        success: bool,
        error: str | None = None,
    ) -> None:
        pending = self._pending.pop(step, None)
        if pending is None:
            self.gate.freezer.freeze("promotion outcome has no authorization intent", details={"step": step})
            raise RuntimeError(f"no pending authorization for step {step}")
        request, decision, load_copy = pending
        try:
            if not success:
                self.gate.freezer.freeze(
                    f"approved weight load failed: {error or 'unknown error'}",
                    details={"step": step, "attempt_id": request.attempt_id},
                )
                self.gate.ledger.append(
                    "tripwire.fired",
                    actor="service:filiolae-gate",
                    data={
                        "class": "T-REC",
                        "attempt_id": request.attempt_id,
                        "step": step,
                        "reason": error or "approved weight load failed",
                    },
                )
                self.gate.ledger.append(
                    "weights.load_failed",
                    actor="service:filiolae-gate",
                    data={
                        "attempt_id": request.attempt_id,
                        "step": step,
                        "gate_approval_seq": decision.ledger_seq,
                        "error": error or "unknown error",
                    },
                )
                self.gate.anchor_current_head()
                return
            try:
                self.gate.ledger.append(
                    "policy.promoted",
                    actor="service:prime-rl-adapter",
                    data={
                        "attempt_id": request.attempt_id,
                        "step": step,
                        "source_policy_version": request.source_policy_version,
                        "gate_approval_seq": decision.ledger_seq,
                    },
                )
                self.gate.anchor_current_head()
            except Exception as exc:
                self.gate.freezer.freeze(
                    f"promotion outcome commit failed: {type(exc).__name__}: {exc}",
                    details={"step": step, "attempt_id": request.attempt_id},
                )
                raise
        finally:
            self._remove_load_copy(load_copy)

    async def record_outcome(
        self,
        step: int,
        *,
        success: bool,
        error: str | None = None,
    ) -> None:
        await asyncio.to_thread(
            self._record_outcome_sync,
            step,
            success=success,
            error=error,
        )

    async def freeze_fatal(
        self,
        step: int,
        current_policy_version: int,
        error: BaseException,
    ) -> None:
        self.gate.freezer.freeze(
            f"fatal promotion control failure: {type(error).__name__}: {error}",
            details={"step": step, "source_policy_version": current_policy_version},
        )
