from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from filiolae.audit import audit_governance
from filiolae.prime_rl import PrimeRLPromotionBarrier
from filiolae.update_control import WeightUpdateController

from .helpers import governed_run


def test_real_load_failure_freezes_and_is_auditable(tmp_path: Path, charter) -> None:
    """Exercise the real Gate/barrier failure outcome, not only the controller protocol fake."""
    ledger, store, files, request, freezer, gate = governed_run(tmp_path, charter)
    barrier = PrimeRLPromotionBarrier(gate, lambda step, path: request)
    attempted_loads: list[Path] = []

    async def fail_load(path: Path) -> None:
        attempted_loads.append(path)
        raise OSError("owner game-day injected load failure")

    with pytest.raises(OSError, match="injected load failure"):
        asyncio.run(
            WeightUpdateController(barrier).apply(
                step=1,
                current_policy_version=0,
                trainer_weights_path=files["weights"],
                update_weights=fail_load,
            )
        )

    assert len(attempted_loads) == 1
    assert attempted_loads[0].is_relative_to(ledger.path.parent / "approved-loads")
    assert not attempted_loads[0].is_relative_to(store.root)
    assert not attempted_loads[0].exists()
    assert attempted_loads[0] != files["weights"]
    assert freezer.state().frozen
    events = [record.event for record in ledger.records()]
    assert events[-3:] == ["gate.approved", "tripwire.fired", "weights.load_failed"]
    assert "policy.promoted" not in events
    assert audit_governance(ledger, charter, verify_artifacts=True).ok
