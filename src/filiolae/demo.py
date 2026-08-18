"""CPU-only governance game day used before the GPU integration run."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .audit import audit_governance
from .charter import Charter
from .freeze import FreezeController
from .gate import PromotionGate, PromotionRequest
from .ledger import Ledger
from .store import ArtifactStore


def run_demo(root: str | Path, *, charter_path: str | Path, tamper: bool = False) -> dict[str, Any]:
    run_root = Path(root)
    if run_root.exists():
        raise FileExistsError(f"demo root already exists; refusing destructive cleanup: {run_root}")
    workload = run_root / "workload"
    control = run_root / "control"
    workload.mkdir(parents=True)
    control.mkdir(parents=True)
    store = ArtifactStore(control / "artifacts")

    charter_target = control / "charter.yaml"
    shutil.copyfile(charter_path, charter_target)
    charter = Charter.load(charter_target)

    paths = {
        "config": workload / "resolved.toml",
        "rollout_batch": workload / "rollouts.jsonl",
        "eval_result": workload / "eval.json",
        "checkpoint": workload / "checkpoint",
    }
    paths["config"].write_text('model = "Qwen3-0.6B"\nmax_steps = 2\n')
    paths["rollout_batch"].write_text('{"reward":1,"sample":"ok"}\n')
    paths["eval_result"].write_text('{"pass_rate":1.0}\n')
    paths["checkpoint"].mkdir()
    (paths["checkpoint"] / "weights.bin").write_bytes(b"demo-weights-v1")

    ledger = Ledger.create(
        control / "ledger.jsonl",
        artifact_root=store.root,
        run_id="filiolae-prime-smoke",
        charter_sha256=charter.sha256,
        metadata={"host": "prime-rl@v0.8.0", "mode": "cpu-governance-simulation"},
    )
    config = ledger.append(
        "config.resolved",
        actor="service:prime-rl-adapter",
        data={"immutable": True},
        artifacts=[store.put("config", paths["config"])],
    )
    batch = ledger.append(
        "batch.committed",
        actor="service:prime-rl-adapter",
        data={"step": 1},
        artifacts=[store.put("rollout_batch", paths["rollout_batch"])],
    )
    evaluation = ledger.append(
        "source_eval.result",
        actor="service:prime-rl-adapter",
        data={"step": 1},
        artifacts=[store.put("source_eval_result", paths["eval_result"])],
    )
    checkpoint = ledger.append(
        "weights.published",
        actor="service:prime-rl-adapter",
        data={"step": 1, "source_policy_version": 0},
        artifacts=[store.put("candidate_weights", paths["checkpoint"])],
    )

    if tamper:
        # Corrupt the gate-owned copy, not merely the untrusted workload source.
        stored_batch = ledger.record(batch.seq).artifacts[0]
        store.resolve(stored_batch).write_text('{"reward":999,"sample":"tampered"}\n')

    request = PromotionRequest(
        attempt_id="demo-step-1",
        step=1,
        source_policy_version=0,
        config_seq=config.seq,
        rollout_batch_seq=batch.seq,
        eval_result_seq=evaluation.seq,
        checkpoint_seq=checkpoint.seq,
    )
    freezer = FreezeController(control / "freeze.json")
    decision = PromotionGate(ledger, charter, freezer).authorize(
        request,
        current_policy_version=0,
        pending_weights_path=paths["checkpoint"],
    )
    if decision.allowed:
        ledger.append(
            "policy.promoted",
            actor="service:prime-rl-adapter",
            data={
                "attempt_id": request.attempt_id,
                "step": 1,
                "source_policy_version": 0,
                "gate_approval_seq": decision.ledger_seq,
            },
        )
    return {
        "allowed": decision.allowed,
        "reason": decision.reason,
        "frozen": freezer.state().frozen,
        "ledger": str(ledger.path),
        "audit": audit_governance(ledger, charter, verify_artifacts=True).summary(),
    }
