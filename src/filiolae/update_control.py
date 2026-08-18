"""Fail-closed control flow around an inference weight update."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import suppress
from pathlib import Path
from typing import Protocol


class PromotionBarrierProtocol(Protocol):
    async def authorize_version(
        self,
        step: int,
        current_policy_version: int,
        weights_path: Path | None,
    ) -> Path: ...

    async def record_outcome(
        self,
        step: int,
        *,
        success: bool,
        error: str | None = None,
    ) -> None: ...

    async def freeze_fatal(
        self,
        step: int,
        current_policy_version: int,
        error: BaseException,
    ) -> None: ...


class WeightUpdateController:
    """Authorize, load exact approved bytes, record outcome, then return.

    The caller may mutate policy/version state only after this method returns.
    """

    def __init__(
        self,
        barrier: PromotionBarrierProtocol,
        *,
        authorization_timeout: float = 30.0,
        outcome_timeout: float | None = None,
    ) -> None:
        resolved_outcome_timeout = authorization_timeout if outcome_timeout is None else outcome_timeout
        if authorization_timeout <= 0 or resolved_outcome_timeout <= 0:
            raise ValueError("promotion control timeouts must be positive")
        self.barrier = barrier
        self.authorization_timeout = authorization_timeout
        self.outcome_timeout = resolved_outcome_timeout

    async def _freeze_best_effort(
        self,
        step: int,
        current_policy_version: int,
        error: BaseException,
    ) -> None:
        # The external supervisor must treat unreadable/missing governance state as fatal too.
        with suppress(BaseException):
            await asyncio.shield(self.barrier.freeze_fatal(step, current_policy_version, error))

    async def apply(
        self,
        *,
        step: int,
        current_policy_version: int,
        trainer_weights_path: Path | None,
        update_weights: Callable[[Path], Awaitable[None]],
    ) -> Path:
        try:
            approved_path = await asyncio.wait_for(
                self.barrier.authorize_version(step, current_policy_version, trainer_weights_path),
                timeout=self.authorization_timeout,
            )
        except BaseException as exc:
            await self._freeze_best_effort(step, current_policy_version, exc)
            raise
        try:
            await update_weights(approved_path)
        except BaseException as exc:
            try:
                await asyncio.wait_for(
                    self.barrier.record_outcome(step, success=False, error=repr(exc)),
                    timeout=self.outcome_timeout,
                )
            finally:
                await self._freeze_best_effort(step, current_policy_version, exc)
            raise
        try:
            await asyncio.wait_for(
                self.barrier.record_outcome(step, success=True),
                timeout=self.outcome_timeout,
            )
        except BaseException as exc:
            # Bytes may be live but durable state is ambiguous: never return authority to advance.
            await self._freeze_best_effort(step, current_policy_version, exc)
            raise
        return approved_path
