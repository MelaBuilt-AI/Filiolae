from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from filiolae.prime_rl import PrimeRLPromotionBarrier

from .helpers import governed_run


def test_barrier_materializes_disposable_load_copy_and_records_outcome(tmp_path: Path, charter) -> None:
    ledger, store, files, request, _, gate = governed_run(tmp_path, charter)
    barrier = PrimeRLPromotionBarrier(gate, lambda step, path: request)
    approved = asyncio.run(barrier.authorize_version(1, 0, files["weights"]))
    assert approved.is_relative_to(ledger.path.parent / "approved-loads")
    assert not approved.is_relative_to(store.root)
    stored = store.resolve(ledger.records()[request.checkpoint_seq].artifacts[0])
    assert (approved / "weights.bin").read_bytes() == b"weights-v1"
    (approved / "weights.bin").write_bytes(b"consumer mutation")
    assert (stored / "weights.bin").read_bytes() == b"weights-v1"
    assert ledger.audit(verify_artifacts=True).ok
    asyncio.run(barrier.record_outcome(1, success=True))
    assert not approved.exists()
    assert [record.event for record in ledger.records()][-2:] == ["gate.approved", "policy.promoted"]


def test_barrier_exception_freezes(tmp_path: Path, charter) -> None:
    _, _, files, _, freezer, gate = governed_run(tmp_path, charter)

    def broken(step, path):
        raise RuntimeError("callback failure")

    barrier = PrimeRLPromotionBarrier(gate, broken)
    with pytest.raises(RuntimeError, match="callback failure"):
        asyncio.run(barrier.authorize_version(1, 0, files["weights"]))
    assert freezer.state().frozen
