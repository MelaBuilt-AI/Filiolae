from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from filiolae.charter import Charter
from filiolae.freeze import FreezeController
from filiolae.gate import PromotionGate
from filiolae.ledger import Ledger
from filiolae.prime_rl import PrimeRLPromotionBarrier
from filiolae.prime_rl_entrypoint import PrimeRLEvidenceBuilder, PrimeRLIntegrationError
from filiolae.store import ArtifactStore
from filiolae.update_control import WeightUpdateController


def _integration(tmp_path: Path, charter_path: Path):
    output = tmp_path / "run"
    (output / "control").mkdir(parents=True)
    (output / "control" / "orch.toml").write_text("max_steps = 1\n")
    weights = output / "broadcasts" / "step_1"
    weights.mkdir(parents=True)
    (weights / "STABLE").write_text("ready\n")
    (weights / "model.safetensors").write_bytes(b"candidate-one")
    batch = output / "rollouts" / "step_1" / "train" / "effective" / "traces.jsonl"
    batch.parent.mkdir(parents=True)
    batch.write_text('{"reward":1}\n')
    governance = output / "control" / "filiolae"
    store = ArtifactStore(governance / "artifacts")
    charter = Charter.load(charter_path)
    ledger = Ledger.create(
        governance / "ledger.jsonl",
        artifact_root=store.root,
        run_id="integration-run",
        charter_sha256=charter.sha256,
    )
    freezer = FreezeController(governance / "freeze.json")
    gate = PromotionGate(ledger, charter, freezer)
    builder = PrimeRLEvidenceBuilder(output, ledger, store)
    return output, weights, ledger, freezer, PrimeRLPromotionBarrier(gate, builder.request_for_step)


def test_real_builder_and_gate_load_exact_gate_owned_path(tmp_path: Path, charter_path: Path) -> None:
    output, weights, ledger, freezer, barrier = _integration(tmp_path, charter_path)
    loaded: list[Path] = []

    async def load(path: Path) -> None:
        loaded.append(path)
        (path / "model.safetensors").write_bytes(b"consumer-mutated-load-copy")

    approved = asyncio.run(
        WeightUpdateController(barrier).apply(
            step=1,
            current_policy_version=0,
            trainer_weights_path=weights,
            update_weights=load,
        )
    )
    assert loaded == [approved]
    assert approved != weights
    assert approved.is_relative_to(output / "control" / "filiolae" / "approved-loads")
    assert not approved.exists()
    assert ledger.audit(verify_artifacts=True).ok
    assert not freezer.state().frozen
    events = [record.event for record in ledger.records()]
    assert events == [
        "run.genesis",
        "config.resolved",
        "batch.committed",
        "source_eval.result",
        "weights.published",
        "gate.approved",
        "policy.promoted",
    ]
    source_record = ledger.records()[3]
    source_report = json.loads((ledger.artifact_root / source_record.artifacts[0].path).read_bytes())
    assert source_report["candidate_quality_evaluated"] is False
    assert source_report["source_policy_version"] == 0


def test_builder_rejects_wrong_broadcast_path_before_evidence(tmp_path: Path, charter_path: Path) -> None:
    _, _, ledger, _, barrier = _integration(tmp_path, charter_path)
    wrong = tmp_path / "wrong"
    wrong.mkdir()
    (wrong / "STABLE").write_text("ready")
    with pytest.raises(PrimeRLIntegrationError, match="unexpected broadcast path"):
        asyncio.run(barrier.authorize_version(1, 0, wrong))
    assert [record.event for record in ledger.records()] == [
        "run.genesis",
        "tripwire.fired",
        "gate.denied",
    ]


def test_builder_rejects_symlink_component(tmp_path: Path, charter_path: Path) -> None:
    output, weights, _, _, barrier = _integration(tmp_path, charter_path)
    alias_parent = tmp_path / "alias-run"
    alias_parent.symlink_to(output, target_is_directory=True)
    aliased = alias_parent / "broadcasts" / "step_1"
    assert aliased.resolve() == weights.resolve()
    with pytest.raises(PrimeRLIntegrationError, match="symlink component rejected"):
        asyncio.run(barrier.authorize_version(1, 0, aliased))


def test_build_barrier_requires_filesystem_and_fresh_run(
    tmp_path: Path, charter_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    from filiolae.prime_rl_entrypoint import _build_barrier

    bad_transport = SimpleNamespace(
        output_dir=tmp_path / "a",
        weight_broadcast=SimpleNamespace(type="nccl"),
        ckpt=SimpleNamespace(resume_step=None),
    )
    with pytest.raises(PrimeRLIntegrationError, match="filesystem"):
        _build_barrier(bad_transport)

    resumed = SimpleNamespace(
        output_dir=tmp_path / "b",
        weight_broadcast=SimpleNamespace(type="filesystem"),
        ckpt=SimpleNamespace(resume_step=4),
    )
    with pytest.raises(PrimeRLIntegrationError, match="fresh runs only"):
        _build_barrier(resumed)

    monkeypatch.setenv("FILIOLAE_CHARTER", str(charter_path))
    fresh = SimpleNamespace(
        output_dir=tmp_path / "fresh",
        weight_broadcast=SimpleNamespace(type="filesystem"),
        ckpt=SimpleNamespace(resume_step=None),
    )
    barrier = _build_barrier(fresh)
    assert barrier.gate.ledger.audit(verify_artifacts=True).ok
    assert barrier.gate.ledger.records()[0].data["metadata"]["candidate_quality_evaluated"] is False
    with pytest.raises(FileExistsError):
        _build_barrier(fresh)


def test_real_barrier_timeout_freezes_and_never_loads(tmp_path: Path, charter_path: Path) -> None:
    import time

    _, weights, _, freezer, barrier = _integration(tmp_path, charter_path)
    original = barrier.request_for_step

    def slow_request(step: int, path: Path | None):
        time.sleep(0.1)
        return original(step, path)

    barrier.request_for_step = slow_request
    loaded: list[Path] = []

    async def load(path: Path) -> None:
        loaded.append(path)

    with pytest.raises(TimeoutError):
        asyncio.run(
            WeightUpdateController(barrier, authorization_timeout=0.01).apply(
                step=1,
                current_policy_version=0,
                trainer_weights_path=weights,
                update_weights=load,
            )
        )
    assert loaded == []
    assert freezer.state().frozen


def test_build_barrier_can_require_local_signed_head_checkpoints(
    tmp_path: Path, charter_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    from filiolae.anchor import (
        AnchorStore,
        generate_keypair,
        load_public_key,
        verify_anchor_store,
    )
    from filiolae.prime_rl_entrypoint import _build_barrier

    private = tmp_path / "protected" / "private.pem"
    public = tmp_path / "protected" / "public.pem"
    generate_keypair(private, public)
    anchor_dir = tmp_path / "protected" / "receipts"
    monkeypatch.setenv("FILIOLAE_CHARTER", str(charter_path))
    monkeypatch.setenv("FILIOLAE_LOCAL_ANCHOR_PRIVATE_KEY", str(private))
    monkeypatch.setenv("FILIOLAE_LOCAL_ANCHOR_DIR", str(anchor_dir))
    config = SimpleNamespace(
        output_dir=tmp_path / "run",
        weight_broadcast=SimpleNamespace(type="filesystem"),
        ckpt=SimpleNamespace(resume_step=None),
    )
    barrier = _build_barrier(config)
    genesis = barrier.gate.ledger.records()[0]
    assert genesis.data["metadata"]["head_anchors_required"] is True
    assert genesis.data["metadata"]["anchor_signer_key_id"].startswith("sha256:")
    report = verify_anchor_store(
        barrier.gate.ledger,
        AnchorStore(anchor_dir),
        load_public_key(public),
    )
    assert report.ok and report.current_head_anchored


def test_build_barrier_rejects_partial_or_in_output_anchor_config(
    tmp_path: Path, charter_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    from filiolae.anchor import generate_keypair
    from filiolae.prime_rl_entrypoint import _build_barrier

    output = tmp_path / "run"
    config = SimpleNamespace(
        output_dir=output,
        weight_broadcast=SimpleNamespace(type="filesystem"),
        ckpt=SimpleNamespace(resume_step=None),
    )
    monkeypatch.setenv("FILIOLAE_CHARTER", str(charter_path))
    monkeypatch.setenv("FILIOLAE_LOCAL_ANCHOR_DIR", str(tmp_path / "receipts"))
    with pytest.raises(PrimeRLIntegrationError, match="requires both"):
        _build_barrier(config)
    monkeypatch.delenv("FILIOLAE_LOCAL_ANCHOR_DIR")
    private = output / "unsafe-private.pem"
    public = tmp_path / "public.pem"
    generate_keypair(private, public)
    monkeypatch.setenv("FILIOLAE_LOCAL_ANCHOR_PRIVATE_KEY", str(private))
    monkeypatch.setenv("FILIOLAE_LOCAL_ANCHOR_DIR", str(tmp_path / "receipts"))
    with pytest.raises(PrimeRLIntegrationError, match="outside"):
        _build_barrier(config)


def test_orchestrator_constructor_failure_records_and_anchors_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys
    import types
    from types import SimpleNamespace

    import filiolae.prime_rl_entrypoint as entrypoint

    appended: list[tuple[str, dict]] = []
    anchored: list[bool] = []

    class Ledger:
        def append(self, event: str, *, actor: str, data: dict):
            appended.append((event, data))

    class Freezer:
        def freeze(self, reason: str):
            raise AssertionError(reason)

    gate = SimpleNamespace(
        ledger=Ledger(),
        freezer=Freezer(),
        anchor_current_head=lambda: anchored.append(True),
    )
    barrier = SimpleNamespace(gate=gate)
    monkeypatch.setattr(entrypoint, "_build_barrier", lambda config: barrier)

    orchestrator_module = types.ModuleType("prime_rl.orchestrator.orchestrator")

    class BrokenOrchestrator:
        def __init__(self, config, *, promotion_barrier):
            raise RuntimeError("constructor failed")

    orchestrator_module.Orchestrator = BrokenOrchestrator
    utils_module = types.ModuleType("prime_rl.utils.utils")
    utils_module.clean_exit = lambda function: function
    for name in ("prime_rl", "prime_rl.orchestrator", "prime_rl.utils"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, "prime_rl.orchestrator.orchestrator", orchestrator_module)
    monkeypatch.setitem(sys.modules, "prime_rl.utils.utils", utils_module)

    with pytest.raises(RuntimeError, match="constructor failed"):
        asyncio.run(entrypoint.run_governed_orchestrator(object()))
    assert appended == [
        (
            "run.exited",
            {"status": "failed", "error": "RuntimeError('constructor failed')"},
        )
    ]
    assert anchored == [True]


def test_build_barrier_uses_external_witness_without_loading_private_key(
    tmp_path: Path, charter_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os
    import threading
    import time
    from types import SimpleNamespace

    from filiolae.anchor import (
        UNIX_WITNESS_ANCHOR_KIND,
        AnchorStore,
        generate_keypair,
        load_private_key,
        load_public_key,
        verify_anchor_store,
    )
    from filiolae.enrollment import create_witness_enrollment, load_witness_enrollment
    from filiolae.ledger import Ledger, provision_ledger_lock
    from filiolae.prime_rl_entrypoint import _build_barrier
    from filiolae.witness import UnixAnchorWitnessServer

    output = tmp_path / "run"
    private = tmp_path / "witness" / "private.pem"
    public = tmp_path / "witness" / "public.pem"
    generate_keypair(private, public)
    lock_path = tmp_path / "shared" / "ledger.lock"
    provision_ledger_lock(lock_path, mode=0o660, gid=os.getgid())
    socket_dir = tmp_path / "witness" / "runtime"
    socket_dir.mkdir(mode=0o700)
    socket_path = socket_dir / "anchor.sock"
    authoritative = AnchorStore(tmp_path / "witness" / "receipts")
    enrollment_path = tmp_path / "witness" / "enrollment.json"
    enrollment = create_witness_enrollment(
        enrollment_path,
        ledger_path=output / "control" / "filiolae" / "ledger.jsonl",
        run_id="integration-witness-run",
        genesis_charter_sha256=Charter.load(charter_path).sha256,
        public_key=load_public_key(public),
    )
    server = UnixAnchorWitnessServer(
        socket_path,
        Ledger(
            output / "control" / "filiolae" / "ledger.jsonl",
            artifact_root=output / "control" / "filiolae" / "artifacts",
            lock_path=lock_path,
            require_existing_lock=True,
        ),
        authoritative,
        load_private_key(private),
        load_witness_enrollment(enrollment_path),
        allowed_uid=os.getuid(),
    )
    stop = threading.Event()
    errors: list[BaseException] = []

    def serve() -> None:
        try:
            server.serve(stop)
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    deadline = time.monotonic() + 2
    while not socket_path.exists() and not errors and time.monotonic() < deadline:
        time.sleep(0.01)
    assert socket_path.exists() and not errors

    mirror = tmp_path / "gate-mirror"
    monkeypatch.setenv("FILIOLAE_CHARTER", str(charter_path))
    monkeypatch.setenv("FILIOLAE_ANCHOR_WITNESS_SOCKET", str(socket_path))
    monkeypatch.setenv("FILIOLAE_ANCHOR_WITNESS_PUBLIC_KEY", str(public))
    monkeypatch.setenv("FILIOLAE_ANCHOR_WITNESS_MIRROR_DIR", str(mirror))
    monkeypatch.setenv("FILIOLAE_LEDGER_LOCK_PATH", str(lock_path))
    monkeypatch.setenv("FILIOLAE_LEDGER_SHARED_GID", str(os.getgid()))
    monkeypatch.setenv("FILIOLAE_RUN_ID", "integration-witness-run")
    monkeypatch.setenv("FILIOLAE_WITNESS_ENROLLMENT_SHA256", enrollment.sha256)
    config = SimpleNamespace(
        output_dir=output,
        weight_broadcast=SimpleNamespace(type="filesystem"),
        ckpt=SimpleNamespace(resume_step=None),
    )
    try:
        barrier = _build_barrier(config)
        genesis = barrier.gate.ledger.records()[0]
        metadata = genesis.data["metadata"]
        assert metadata["anchor_kind"] == UNIX_WITNESS_ANCHOR_KIND
        assert barrier.gate.ledger.path.stat().st_mode & 0o777 == 0o640
        for shared_directory in (output, output / "control", output / "control" / "filiolae"):
            assert shared_directory.stat().st_mode & 0o777 == 0o750
            assert shared_directory.stat().st_gid == os.getgid()
        assert "FILIOLAE_LOCAL_ANCHOR_PRIVATE_KEY" not in os.environ
        report = verify_anchor_store(
            barrier.gate.ledger,
            AnchorStore(mirror),
            load_public_key(public),
            expected_anchor_kind=UNIX_WITNESS_ANCHOR_KIND,
        )
        assert report.ok and report.current_head_anchored
    finally:
        stop.set()
        thread.join(2)
    assert not errors


def test_build_barrier_rejects_partial_or_mixed_witness_configuration(
    tmp_path: Path, charter_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    from filiolae.anchor import generate_keypair
    from filiolae.prime_rl_entrypoint import _build_barrier

    config = SimpleNamespace(
        output_dir=tmp_path / "run",
        weight_broadcast=SimpleNamespace(type="filesystem"),
        ckpt=SimpleNamespace(resume_step=None),
    )
    monkeypatch.setenv("FILIOLAE_CHARTER", str(charter_path))
    monkeypatch.setenv("FILIOLAE_ANCHOR_WITNESS_SOCKET", str(tmp_path / "missing.sock"))
    with pytest.raises(PrimeRLIntegrationError, match="requires socket"):
        _build_barrier(config)

    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    generate_keypair(private, public)
    monkeypatch.setenv("FILIOLAE_LOCAL_ANCHOR_PRIVATE_KEY", str(private))
    monkeypatch.setenv("FILIOLAE_LOCAL_ANCHOR_DIR", str(tmp_path / "local-receipts"))
    monkeypatch.setenv("FILIOLAE_ANCHOR_WITNESS_PUBLIC_KEY", str(public))
    monkeypatch.setenv("FILIOLAE_ANCHOR_WITNESS_MIRROR_DIR", str(tmp_path / "mirror"))
    monkeypatch.setenv("FILIOLAE_LEDGER_LOCK_PATH", str(tmp_path / "lock"))
    monkeypatch.setenv("FILIOLAE_LEDGER_SHARED_GID", "0")
    monkeypatch.setenv("FILIOLAE_RUN_ID", "mixed-mode-run")
    monkeypatch.setenv("FILIOLAE_WITNESS_ENROLLMENT_SHA256", "a" * 64)
    with pytest.raises(PrimeRLIntegrationError, match="mutually exclusive"):
        _build_barrier(config)
