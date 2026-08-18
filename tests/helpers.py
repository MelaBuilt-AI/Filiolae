from __future__ import annotations

from pathlib import Path

from filiolae.charter import Charter
from filiolae.freeze import FreezeController
from filiolae.gate import PromotionGate, PromotionRequest
from filiolae.ledger import Ledger
from filiolae.store import ArtifactStore


def governed_run(
    tmp_path: Path,
    charter: Charter,
    *,
    metadata: dict[str, object] | None = None,
):
    workload = tmp_path / "workload"
    workload.mkdir(parents=True)
    store = ArtifactStore(tmp_path / "control" / "artifacts")
    files = {
        "config": workload / "config.toml",
        "batch": workload / "batch.jsonl",
        "eval": workload / "eval.json",
        "weights": workload / "step_1",
    }
    files["config"].write_text("max_steps = 2\n")
    files["batch"].write_text('{"reward":1}\n')
    files["eval"].write_text('{"pass":true}\n')
    files["weights"].mkdir()
    (files["weights"] / "weights.bin").write_bytes(b"weights-v1")
    ledger = Ledger.create(
        tmp_path / "control" / "ledger.jsonl",
        artifact_root=store.root,
        run_id="test-run",
        charter_sha256=charter.sha256,
        metadata=metadata,
    )
    config = ledger.append(
        "config.resolved",
        actor="adapter",
        artifacts=[store.put("config", files["config"])],
    )
    batch = ledger.append(
        "batch.committed",
        actor="adapter",
        data={"step": 1},
        artifacts=[store.put("rollout_batch", files["batch"])],
    )
    evaluation = ledger.append(
        "source_eval.result",
        actor="adapter",
        data={"step": 1, "evaluated_policy_version": 0},
        artifacts=[store.put("source_eval_result", files["eval"])],
    )
    weights = ledger.append(
        "weights.published",
        actor="adapter",
        data={"step": 1, "source_policy_version": 0},
        artifacts=[store.put("candidate_weights", files["weights"])],
    )
    request = PromotionRequest(
        attempt_id="attempt-1",
        step=1,
        source_policy_version=0,
        config_seq=config.seq,
        rollout_batch_seq=batch.seq,
        eval_result_seq=evaluation.seq,
        checkpoint_seq=weights.seq,
    )
    freezer = FreezeController(tmp_path / "control" / "freeze.json")
    gate = PromotionGate(ledger, charter, freezer)
    return ledger, store, files, request, freezer, gate
