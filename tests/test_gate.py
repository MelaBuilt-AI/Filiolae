from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from filiolae.artifacts import Artifact
from filiolae.audit import audit_governance

from .helpers import governed_run


def _record_promotion(ledger, request, decision) -> None:
    ledger.append(
        "policy.promoted",
        actor="adapter",
        data={
            "attempt_id": request.attempt_id,
            "step": request.step,
            "source_policy_version": request.source_policy_version,
            "gate_approval_seq": decision.ledger_seq,
        },
    )


def test_happy_path_returns_gate_owned_weights(tmp_path: Path, charter) -> None:
    ledger, store, files, request, freezer, gate = governed_run(tmp_path, charter)
    decision = gate.authorize(request, current_policy_version=0, pending_weights_path=files["weights"])
    assert decision.allowed
    assert decision.approved_checkpoint_path is not None
    assert Path(decision.approved_checkpoint_path).is_relative_to(store.root)
    assert not freezer.state().frozen
    _record_promotion(ledger, request, decision)
    report = audit_governance(ledger, charter)
    assert report.ok, report.summary()


def test_substitute_pending_weights_denied_and_frozen(tmp_path: Path, charter) -> None:
    ledger, _, files, request, freezer, gate = governed_run(tmp_path, charter)
    substitute = tmp_path / "substitute"
    substitute.mkdir()
    (substitute / "weights.bin").write_bytes(b"different")
    decision = gate.authorize(request, current_policy_version=0, pending_weights_path=substitute)
    assert not decision.allowed
    assert "pending weights differ" in decision.reason
    assert freezer.state().frozen
    assert not any(record.event == "gate.approved" for record in ledger.records())


def test_corrupt_gate_owned_artifact_denied(tmp_path: Path, charter) -> None:
    ledger, store, _, request, freezer, gate = governed_run(tmp_path, charter)
    batch_artifact = ledger.record(request.rollout_batch_seq).artifacts[0]
    store.resolve(batch_artifact).write_text("corrupt")
    decision = gate.authorize(
        request, current_policy_version=0, pending_weights_path=tmp_path / "workload/step_1"
    )
    assert not decision.allowed
    assert "artifact integrity failure" in decision.reason
    assert freezer.state().frozen
    assert [record.event for record in ledger.records()][-2:] == ["tripwire.fired", "gate.denied"]


def test_denial_is_committed_before_external_freeze_visibility(tmp_path: Path, charter, monkeypatch) -> None:
    ledger, store, files, request, freezer, gate = governed_run(tmp_path, charter)
    batch_artifact = ledger.record(request.rollout_batch_seq).artifacts[0]
    store.resolve(batch_artifact).write_text("corrupt")
    original_freeze = freezer.freeze

    def observe_freeze(reason, *, details=None):
        assert [record.event for record in ledger.records()][-2:] == [
            "tripwire.fired",
            "gate.denied",
        ]
        return original_freeze(reason, details=details)

    monkeypatch.setattr(freezer, "freeze", observe_freeze)
    decision = gate.authorize(
        request,
        current_policy_version=0,
        pending_weights_path=files["weights"],
    )
    assert not decision.allowed
    assert freezer.state().frozen


def test_false_source_version_denied(tmp_path: Path, charter) -> None:
    _, _, files, request, freezer, gate = governed_run(tmp_path, charter)
    decision = gate.authorize(
        replace(request, source_policy_version=9),
        current_policy_version=0,
        pending_weights_path=files["weights"],
    )
    assert not decision.allowed
    assert freezer.state().frozen


def test_unrelated_artifact_name_cannot_satisfy_evidence(tmp_path: Path, charter) -> None:
    ledger, _, files, request, freezer, gate = governed_run(tmp_path, charter)
    raw = ledger.record(request.rollout_batch_seq)
    wrong = Artifact(
        "unrelated",
        raw.artifacts[0].path,
        raw.artifacts[0].kind,
        raw.artifacts[0].sha256,
        raw.artifacts[0].size,
    )
    # Append an intact but semantically wrong evidence event, then point the request to it.
    wrong_record = ledger.append("batch.committed", actor="adapter", data={"step": 1}, artifacts=[wrong])
    decision = gate.authorize(
        replace(request, rollout_batch_seq=wrong_record.seq),
        current_policy_version=0,
        pending_weights_path=files["weights"],
    )
    assert not decision.allowed
    assert "rollout_batch artifact" in decision.reason
    assert freezer.state().frozen


def test_duplicate_approval_is_permanent_denial(tmp_path: Path, charter) -> None:
    ledger, _, files, request, freezer, gate = governed_run(tmp_path, charter)
    first = gate.authorize(request, current_policy_version=0, pending_weights_path=files["weights"])
    assert first.allowed
    second = gate.authorize(request, current_policy_version=0, pending_weights_path=files["weights"])
    assert not second.allowed
    assert freezer.state().frozen
    assert len([record for record in ledger.records() if record.event == "gate.approved"]) == 1


def test_deleted_freeze_marker_does_not_restore_authority(tmp_path: Path, charter) -> None:
    ledger, _, files, request, freezer, gate = governed_run(tmp_path, charter)
    denied = gate.authorize(
        replace(request, source_policy_version=5),
        current_policy_version=0,
        pending_weights_path=files["weights"],
    )
    assert not denied.allowed
    freezer.path.unlink()
    again = gate.authorize(request, current_policy_version=0, pending_weights_path=files["weights"])
    assert not again.allowed
    assert "run already frozen" in again.reason
    assert freezer.state().frozen
    assert any(record.event == "tripwire.fired" for record in ledger.records())


def test_boolean_or_malformed_request_fields_are_denied_and_frozen(tmp_path: Path, charter) -> None:
    ledger, _, files, request, freezer, gate = governed_run(tmp_path, charter)
    decision = gate.authorize(
        replace(request, step=True),
        current_policy_version=0,
        pending_weights_path=files["weights"],
    )
    assert not decision.allowed
    assert "must be integers" in decision.reason
    assert freezer.state().frozen
    assert not any(record.event == "gate.approved" for record in ledger.records())


def test_nonnumeric_step_is_safely_recorded_as_malformed(tmp_path: Path, charter) -> None:
    ledger, _, files, request, freezer, gate = governed_run(tmp_path, charter)
    decision = gate.authorize(
        replace(request, step=object()),
        current_policy_version=0,
        pending_weights_path=files["weights"],
    )
    assert not decision.allowed
    assert decision.step == -1
    assert freezer.state().frozen
    assert not any(record.event == "gate.approved" for record in ledger.records())


def test_freeze_during_authorization_prevents_late_approval(tmp_path: Path, charter, monkeypatch) -> None:
    import filiolae.gate as gate_module

    ledger, _, files, request, freezer, gate = governed_run(tmp_path, charter)
    original_digest = gate_module.digest_path

    def freeze_then_digest(path):
        freezer.freeze("authorization timed out")
        return original_digest(path)

    monkeypatch.setattr(gate_module, "digest_path", freeze_then_digest)
    decision = gate.authorize(
        request,
        current_policy_version=0,
        pending_weights_path=files["weights"],
    )
    assert not decision.allowed
    assert "froze before authorization commit" in decision.reason
    assert not any(record.event == "gate.approved" for record in ledger.records())
