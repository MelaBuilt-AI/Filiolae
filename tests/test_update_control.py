from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from filiolae.update_control import WeightUpdateController


class FakeBarrier:
    def __init__(self, approved: Path, *, error: BaseException | None = None, delay: float = 0.0) -> None:
        self.approved = approved
        self.error = error
        self.delay = delay
        self.outcomes: list[tuple[bool, str | None]] = []
        self.fatals: list[BaseException] = []
        self.outcome_error: BaseException | None = None
        self.outcome_delay = 0.0

    async def authorize_version(self, step: int, current: int, source: Path | None) -> Path:
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error:
            raise self.error
        return self.approved

    async def record_outcome(self, step: int, *, success: bool, error: str | None = None) -> None:
        if self.outcome_delay:
            await asyncio.sleep(self.outcome_delay)
        if self.outcome_error:
            raise self.outcome_error
        self.outcomes.append((success, error))

    async def freeze_fatal(self, step: int, current: int, error: BaseException) -> None:
        self.fatals.append(error)


def test_denial_or_fault_causes_zero_weight_loads(tmp_path: Path) -> None:
    barrier = FakeBarrier(tmp_path / "approved", error=RuntimeError("denied"))
    loaded: list[Path] = []

    async def update(path: Path) -> None:
        loaded.append(path)

    with pytest.raises(RuntimeError, match="denied"):
        asyncio.run(
            WeightUpdateController(barrier).apply(
                step=1,
                current_policy_version=0,
                trainer_weights_path=tmp_path / "trainer",
                update_weights=update,
            )
        )
    assert loaded == []
    assert len(barrier.fatals) == 1


def test_authorization_timeout_causes_zero_weight_loads(tmp_path: Path) -> None:
    barrier = FakeBarrier(tmp_path / "approved", delay=0.2)
    loaded: list[Path] = []

    async def update(path: Path) -> None:
        loaded.append(path)

    with pytest.raises(TimeoutError):
        asyncio.run(
            WeightUpdateController(barrier, authorization_timeout=0.01).apply(
                step=1,
                current_policy_version=0,
                trainer_weights_path=tmp_path / "trainer",
                update_weights=update,
            )
        )
    assert loaded == []
    assert len(barrier.fatals) == 1


def test_approval_loads_only_exact_returned_path(tmp_path: Path) -> None:
    approved = tmp_path / "gate-store" / "weights"
    barrier = FakeBarrier(approved)
    loaded: list[Path] = []

    async def update(path: Path) -> None:
        loaded.append(path)

    result = asyncio.run(
        WeightUpdateController(barrier).apply(
            step=1,
            current_policy_version=0,
            trainer_weights_path=tmp_path / "trainer" / "weights",
            update_weights=update,
        )
    )
    assert result == approved
    assert loaded == [approved]
    assert barrier.outcomes == [(True, None)]
    assert barrier.fatals == []


def test_load_failure_records_failure_and_freezes(tmp_path: Path) -> None:
    barrier = FakeBarrier(tmp_path / "approved")

    async def update(path: Path) -> None:
        raise OSError("load failed")

    with pytest.raises(OSError, match="load failed"):
        asyncio.run(
            WeightUpdateController(barrier).apply(
                step=1,
                current_policy_version=0,
                trainer_weights_path=tmp_path / "trainer",
                update_weights=update,
            )
        )
    assert barrier.outcomes and barrier.outcomes[0][0] is False
    assert len(barrier.fatals) == 1


def test_outcome_commit_failure_is_ambiguous_and_frozen(tmp_path: Path) -> None:
    barrier = FakeBarrier(tmp_path / "approved")
    barrier.outcome_error = OSError("ledger unavailable")
    loaded: list[Path] = []

    async def update(path: Path) -> None:
        loaded.append(path)

    with pytest.raises(OSError, match="ledger unavailable"):
        asyncio.run(
            WeightUpdateController(barrier).apply(
                step=1,
                current_policy_version=0,
                trainer_weights_path=tmp_path / "trainer",
                update_weights=update,
            )
        )
    assert loaded == [tmp_path / "approved"]
    assert len(barrier.fatals) == 1


def test_outcome_timeout_freezes_after_load_without_returning_authority(tmp_path: Path) -> None:
    barrier = FakeBarrier(tmp_path / "approved")
    barrier.outcome_delay = 0.1
    loaded: list[Path] = []

    async def update(path: Path) -> None:
        loaded.append(path)

    with pytest.raises(TimeoutError):
        asyncio.run(
            WeightUpdateController(barrier, outcome_timeout=0.01).apply(
                step=1,
                current_policy_version=0,
                trainer_weights_path=tmp_path / "trainer",
                update_weights=update,
            )
        )
    assert loaded == [tmp_path / "approved"]
    assert len(barrier.fatals) == 1
