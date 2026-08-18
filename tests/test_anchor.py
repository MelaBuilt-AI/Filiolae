from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from filiolae.anchor import (
    AnchorError,
    AnchorStore,
    anchor_ledger_head,
    generate_keypair,
    load_private_key,
    load_public_key,
    verify_anchor_store,
)
from filiolae.ledger import Ledger


def _setup(tmp_path: Path):
    ledger = Ledger.create(
        tmp_path / "run" / "ledger.jsonl",
        artifact_root=tmp_path / "run" / "artifacts",
        run_id="anchor-test-run",
        charter_sha256="a" * 64,
    )
    private = tmp_path / "keys" / "anchor-private.pem"
    public = tmp_path / "keys" / "anchor-public.pem"
    key_id = generate_keypair(private, public)
    store = AnchorStore(tmp_path / "external-anchor")
    return ledger, private, public, key_id, store


def _anchor_policy(anchor) -> dict[str, object]:
    return {
        "head_anchors_required": True,
        "anchor_kind": anchor.anchor_kind,
        "anchor_signer_key_id": anchor.signer_key_id,
    }


def test_anchor_current_head_and_verify_signature(tmp_path: Path) -> None:
    ledger, private, public, key_id, store = _setup(tmp_path)
    receipt = anchor_ledger_head(ledger, store, load_private_key(private))
    assert receipt.signer_key_id == key_id
    assert receipt.ledger_seq == 0
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    report = verify_anchor_store(ledger, store, load_public_key(public))
    assert report.ok
    assert report.current_head_anchored
    assert report.receipts == (receipt,)
    assert anchor_ledger_head(ledger, store, load_private_key(private)) == receipt
    assert len(list(store.receipts_dir.iterdir())) == 1


def test_chained_receipts_and_stale_head_detection(tmp_path: Path) -> None:
    ledger, private, public, _, store = _setup(tmp_path)
    first = anchor_ledger_head(ledger, store, load_private_key(private))
    ledger.append("test.event", actor="service:test", data={"value": 1})
    stale = verify_anchor_store(
        ledger,
        store,
        load_public_key(public),
        require_current=False,
    )
    assert stale.ok and not stale.current_head_anchored
    strict = verify_anchor_store(ledger, store, load_public_key(public))
    assert not strict.ok
    assert {issue.code for issue in strict.issues} == {"current_head_unanchored"}
    second = anchor_ledger_head(ledger, store, load_private_key(private))
    assert second.previous_receipt_sha256 == first.receipt_sha256()
    assert verify_anchor_store(ledger, store, load_public_key(public)).ok


def test_receipt_tampering_is_detected(tmp_path: Path) -> None:
    ledger, private, public, _, store = _setup(tmp_path)
    anchor_ledger_head(ledger, store, load_private_key(private))
    path = next(store.receipts_dir.iterdir())
    value = json.loads(path.read_bytes())
    value["signed_at"] = "2030-01-01T00:00:00Z"
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    report = verify_anchor_store(ledger, store, load_public_key(public))
    assert not report.ok
    assert "signature_invalid" in {issue.code for issue in report.issues}


def test_deleted_prefix_breaks_receipt_chain(tmp_path: Path) -> None:
    ledger, private, public, _, store = _setup(tmp_path)
    anchor_ledger_head(ledger, store, load_private_key(private))
    ledger.append("test.event", actor="service:test", data={"value": 1})
    anchor_ledger_head(ledger, store, load_private_key(private))
    files = sorted(store.receipts_dir.iterdir())
    files[0].unlink()
    report = verify_anchor_store(ledger, store, load_public_key(public))
    assert "receipt_chain_broken" in {issue.code for issue in report.issues}


def test_ledger_rewrite_or_truncation_conflicts_with_receipts(tmp_path: Path) -> None:
    ledger, private, public, _, store = _setup(tmp_path)
    anchor_ledger_head(ledger, store, load_private_key(private))
    ledger.append("test.event", actor="service:test", data={"value": 1})
    anchor_ledger_head(ledger, store, load_private_key(private))
    lines = ledger.path.read_bytes().splitlines(keepends=True)
    ledger.path.write_bytes(b"".join(lines[:1]))
    report = verify_anchor_store(ledger, store, load_public_key(public))
    codes = {issue.code for issue in report.issues}
    assert "ledger_seq_absent" in codes
    assert "current_head_unanchored" in codes


def test_wrong_key_and_unsafe_store_entry_fail_closed(tmp_path: Path) -> None:
    ledger, private, public, _, store = _setup(tmp_path)
    anchor_ledger_head(ledger, store, load_private_key(private))
    other_private = tmp_path / "other-private.pem"
    other_public = tmp_path / "other-public.pem"
    generate_keypair(other_private, other_public)
    wrong = verify_anchor_store(ledger, store, load_public_key(other_public))
    assert {"key_id_mismatch", "signature_invalid"} <= {issue.code for issue in wrong.issues}
    (store.receipts_dir / "unexpected.txt").write_text("unsafe")
    unsafe = verify_anchor_store(ledger, store, load_public_key(public))
    assert {issue.code for issue in unsafe.issues} == {"store_invalid"}


def test_private_key_permissions_and_symlinks_are_rejected(tmp_path: Path) -> None:
    _, private, _, _, _ = _setup(tmp_path)
    private.chmod(0o644)
    with pytest.raises(AnchorError, match="permissions"):
        load_private_key(private)
    private.chmod(0o600)
    alias = tmp_path / "alias.pem"
    alias.symlink_to(private)
    with pytest.raises(AnchorError, match="non-symlink"):
        load_private_key(alias)


def test_key_generation_refuses_overwrite(tmp_path: Path) -> None:
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    generate_keypair(private, public)
    before = private.read_bytes()
    with pytest.raises(FileExistsError):
        generate_keypair(private, tmp_path / "second-public.pem")
    assert private.read_bytes() == before
    assert not (tmp_path / "second-public.pem").exists()


def test_receipt_files_are_fsynced_regular_files(tmp_path: Path) -> None:
    ledger, private, _, _, store = _setup(tmp_path)
    anchor_ledger_head(ledger, store, load_private_key(private))
    receipt = next(store.receipts_dir.iterdir())
    assert receipt.is_file() and not receipt.is_symlink()
    assert os.stat(receipt).st_size > 0


def test_gate_requires_signed_evidence_head_and_outcome_is_checkpointed(tmp_path: Path, charter) -> None:
    import asyncio

    from filiolae.anchor import LocalEd25519HeadAnchor
    from filiolae.audit import audit_governance
    from filiolae.gate import PromotionGate
    from filiolae.prime_rl import PrimeRLPromotionBarrier

    from .helpers import governed_run

    private = tmp_path / "gate-private.pem"
    public = tmp_path / "gate-public.pem"
    generate_keypair(private, public)
    store = AnchorStore(tmp_path / "anchor-store")
    anchor = LocalEd25519HeadAnchor(store, load_private_key(private))
    ledger, _, files, request, freezer, _ = governed_run(
        tmp_path / "governed",
        charter,
        metadata=_anchor_policy(anchor),
    )
    gate = PromotionGate(
        ledger,
        charter,
        freezer,
        head_anchor=anchor,
        anchor_store=store,
        anchor_public_key=load_public_key(public),
        require_head_anchor=True,
    )
    barrier = PrimeRLPromotionBarrier(gate, lambda step, path: request)
    approved = asyncio.run(barrier.authorize_version(1, 0, files["weights"]))
    assert approved != files["weights"]
    approval = ledger.records()[-1]
    assert approval.event == "gate.approved"
    assert approval.data["anchor_ack"]["ledger_seq"] == approval.seq - 1
    after_approval = verify_anchor_store(
        ledger,
        store,
        load_public_key(public),
        require_current=False,
    )
    assert after_approval.ok
    assert after_approval.unanchored_tail_records == 1
    stale_governance = audit_governance(
        ledger,
        charter,
        verify_artifacts=True,
        anchor_report=after_approval,
    )
    assert "current_head_unanchored" in {issue.code for issue in stale_governance.issues}
    asyncio.run(barrier.record_outcome(1, success=True))
    final_anchors = verify_anchor_store(ledger, store, load_public_key(public))
    assert final_anchors.ok and final_anchors.current_head_anchored
    other_private = tmp_path / "other-gate-private.pem"
    other_public = tmp_path / "other-gate-public.pem"
    generate_keypair(other_private, other_public)
    wrong_policy_key = verify_anchor_store(
        ledger,
        store,
        load_public_key(other_public),
    )
    assert "anchor_policy_key_mismatch" in {issue.code for issue in wrong_policy_key.issues}
    assert audit_governance(
        ledger,
        charter,
        verify_artifacts=True,
        anchor_report=final_anchors,
    ).ok
    without_signatures = audit_governance(ledger, charter, verify_artifacts=True)
    assert "approval_anchor_unverified" in {issue.code for issue in without_signatures.issues}


def test_required_anchor_unavailable_or_failing_denies_before_approval(tmp_path: Path, charter) -> None:
    from filiolae.gate import PromotionGate

    from .helpers import governed_run

    policy = {
        "head_anchors_required": True,
        "anchor_kind": "local_ed25519_checkpoint",
        "anchor_signer_key_id": "sha256:" + "0" * 64,
    }
    ledger, _, files, request, freezer, _ = governed_run(tmp_path / "missing", charter, metadata=policy)
    gate = PromotionGate(ledger, charter, freezer, require_head_anchor=True)
    decision = gate.authorize(request, current_policy_version=0, pending_weights_path=files["weights"])
    assert not decision.allowed
    assert "anchor is unavailable" in decision.reason
    assert "gate.approved" not in [record.event for record in ledger.records()]

    class BrokenAnchor:
        anchor_kind = "local_ed25519_checkpoint"
        signer_key_id = "sha256:" + "0" * 64

        def acknowledge(self, ledger, *, expected_seq: int, expected_head: str):
            raise OSError("signer offline")

        def verify_acknowledgement(self, ledger, receipt, *, expected_seq: int, expected_head: str) -> None:
            raise AssertionError("unreachable")

    ledger2, _, files2, request2, freezer2, _ = governed_run(tmp_path / "broken", charter, metadata=policy)
    verifier_private = tmp_path / "broken-verifier-private.pem"
    verifier_public = tmp_path / "broken-verifier-public.pem"
    generate_keypair(verifier_private, verifier_public)
    gate2 = PromotionGate(
        ledger2,
        charter,
        freezer2,
        head_anchor=BrokenAnchor(),
        anchor_store=AnchorStore(tmp_path / "broken-anchor-store"),
        anchor_public_key=load_public_key(verifier_public),
        require_head_anchor=True,
    )
    decision2 = gate2.authorize(
        request2,
        current_policy_version=0,
        pending_weights_path=files2["weights"],
    )
    assert not decision2.allowed
    assert "signer offline" in decision2.reason
    assert "gate.approved" not in [record.event for record in ledger2.records()]


def test_anchor_then_concurrent_ledger_append_loses_gate_cas(
    tmp_path: Path, charter, monkeypatch: pytest.MonkeyPatch
) -> None:
    from filiolae.anchor import LocalEd25519HeadAnchor
    from filiolae.gate import PromotionGate

    from .helpers import governed_run

    private = tmp_path / "race-private.pem"
    public = tmp_path / "race-public.pem"
    generate_keypair(private, public)
    base = LocalEd25519HeadAnchor(AnchorStore(tmp_path / "race-store"), load_private_key(private))
    ledger, _, files, request, freezer, _ = governed_run(
        tmp_path / "race",
        charter,
        metadata=_anchor_policy(base),
    )

    class RacingAnchor:
        anchor_kind = base.anchor_kind
        signer_key_id = base.signer_key_id

        def acknowledge(self, target, *, expected_seq: int, expected_head: str):
            return base.acknowledge(
                target,
                expected_seq=expected_seq,
                expected_head=expected_head,
            )

    import filiolae.gate as gate_module

    real_verify = gate_module.verify_anchor_store

    def verify_then_race(*args, **kwargs):
        report = real_verify(*args, **kwargs)
        ledger.append("test.race", actor="service:test", data={"race": True})
        return report

    monkeypatch.setattr(gate_module, "verify_anchor_store", verify_then_race)
    gate = PromotionGate(
        ledger,
        charter,
        freezer,
        head_anchor=RacingAnchor(),
        anchor_store=base.store,
        anchor_public_key=base.private_key.public_key(),
        require_head_anchor=True,
    )
    decision = gate.authorize(request, current_policy_version=0, pending_weights_path=files["weights"])
    assert not decision.allowed
    assert "authorization commit failed" in decision.reason
    assert "gate.approved" not in [record.event for record in ledger.records()]
    assert freezer.state().frozen


def test_fixed_ed25519_receipt_vector(tmp_path: Path) -> None:
    from datetime import UTC, datetime

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from filiolae.anchor import public_key_id

    fixed = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    ledger = Ledger.create(
        tmp_path / "vector-ledger.jsonl",
        artifact_root=tmp_path / "artifacts",
        run_id="vector-run",
        charter_sha256="b" * 64,
        clock=lambda: fixed,
    )
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    receipt = anchor_ledger_head(
        ledger,
        AnchorStore(tmp_path / "vector-anchors"),
        key,
        clock=lambda: fixed,
    )
    assert public_key_id(key.public_key()) == (
        "sha256:be337e171e64ddcc5596b1c21266b5c52ad88fadfad4b28e1496b48c20c2e9e7"
    )
    assert receipt.signature == (
        "kM7akvlg4xBpTM+q8o3/yfyghzP01ZByyp14LUuwiJtJcYDuF94h/OsqfZiv+3L7q6GNyfW0R2uzfv6r/C4uCQ=="
    )
    assert receipt.receipt_sha256() == ("ef3c40b169c396bef9d686b65607e80ba5708052503f0045080fe5edb754ce17")


def test_concurrent_signers_commit_one_idempotent_receipt(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor

    ledger, private, public, _, store = _setup(tmp_path)
    key = load_private_key(private)
    with ThreadPoolExecutor(max_workers=6) as pool:
        receipts = list(pool.map(lambda _: anchor_ledger_head(ledger, store, key), range(12)))
    assert len({receipt.receipt_sha256() for receipt in receipts}) == 1
    assert len(list(store.receipts_dir.iterdir())) == 1
    assert verify_anchor_store(ledger, store, load_public_key(public)).ok


def test_anchor_timeout_causes_zero_loads_and_no_late_approval(tmp_path: Path, charter) -> None:
    import asyncio
    import time

    from filiolae.anchor import LocalEd25519HeadAnchor
    from filiolae.gate import PromotionGate
    from filiolae.prime_rl import PrimeRLPromotionBarrier
    from filiolae.update_control import WeightUpdateController

    from .helpers import governed_run

    private = tmp_path / "timeout-private.pem"
    public = tmp_path / "timeout-public.pem"
    generate_keypair(private, public)
    base = LocalEd25519HeadAnchor(AnchorStore(tmp_path / "timeout-store"), load_private_key(private))
    ledger, _, files, request, freezer, _ = governed_run(
        tmp_path / "timeout",
        charter,
        metadata=_anchor_policy(base),
    )

    class SlowAnchor:
        anchor_kind = base.anchor_kind
        signer_key_id = base.signer_key_id

        def acknowledge(self, target, *, expected_seq: int, expected_head: str):
            time.sleep(0.1)
            return base.acknowledge(
                target,
                expected_seq=expected_seq,
                expected_head=expected_head,
            )

        def verify_acknowledgement(self, target, receipt, *, expected_seq: int, expected_head: str) -> None:
            base.verify_acknowledgement(
                target,
                receipt,
                expected_seq=expected_seq,
                expected_head=expected_head,
            )

    gate = PromotionGate(
        ledger,
        charter,
        freezer,
        head_anchor=SlowAnchor(),
        anchor_store=base.store,
        anchor_public_key=base.private_key.public_key(),
        require_head_anchor=True,
    )
    barrier = PrimeRLPromotionBarrier(gate, lambda step, path: request)
    loaded: list[Path] = []

    async def load(path: Path) -> None:
        loaded.append(path)

    with pytest.raises(TimeoutError):
        asyncio.run(
            WeightUpdateController(barrier, authorization_timeout=0.01).apply(
                step=1,
                current_policy_version=0,
                trainer_weights_path=files["weights"],
                update_weights=load,
            )
        )
    assert loaded == []
    assert freezer.state().frozen
    assert "gate.approved" not in [record.event for record in ledger.records()]


def test_forged_anchor_callback_cannot_grant_authority(tmp_path: Path, charter) -> None:
    from dataclasses import replace

    from filiolae.anchor import ANCHOR_KIND, LocalEd25519HeadAnchor
    from filiolae.gate import PromotionGate

    from .helpers import governed_run

    private = tmp_path / "forged-private.pem"
    public = tmp_path / "forged-public.pem"
    generate_keypair(private, public)
    store = AnchorStore(tmp_path / "forged-store")
    real_anchor = LocalEd25519HeadAnchor(store, load_private_key(private))
    policy = _anchor_policy(real_anchor)
    ledger, _, files, request, freezer, _ = governed_run(tmp_path / "forged", charter, metadata=policy)

    class ForgedAnchor:
        anchor_kind = ANCHOR_KIND
        signer_key_id = real_anchor.signer_key_id

        def acknowledge(self, target, *, expected_seq: int, expected_head: str):
            real_receipt = real_anchor.acknowledge(
                target,
                expected_seq=expected_seq,
                expected_head=expected_head,
            )
            return replace(real_receipt, ledger_head_sha256="f" * 64)

    gate = PromotionGate(
        ledger,
        charter,
        freezer,
        head_anchor=ForgedAnchor(),
        anchor_store=store,
        anchor_public_key=load_public_key(public),
        require_head_anchor=True,
    )
    decision = gate.authorize(
        request,
        current_policy_version=0,
        pending_weights_path=files["weights"],
    )
    assert not decision.allowed
    assert "does not bind" in decision.reason
    assert "gate.approved" not in [record.event for record in ledger.records()]


def test_readonly_anchor_verification_never_provisions_missing_lock(tmp_path: Path, charter) -> None:
    from filiolae.anchor import (
        AnchorError,
        AnchorStore,
        anchor_ledger_head,
        generate_keypair,
        load_private_key,
        load_public_key,
        verify_anchor_store_readonly,
    )

    from .helpers import governed_run

    ledger, _, _, _, _, _ = governed_run(tmp_path / "run", charter)
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    generate_keypair(private, public)
    store = AnchorStore(tmp_path / "anchors")
    anchor_ledger_head(ledger, store, load_private_key(private))
    store.lock_path.unlink()

    with pytest.raises((AnchorError, FileNotFoundError)):
        verify_anchor_store_readonly(ledger, store, load_public_key(public))
    assert not store.lock_path.exists()


def test_governance_audit_rejects_anchor_report_for_an_older_ledger_snapshot(tmp_path: Path, charter) -> None:
    from filiolae.audit import audit_governance

    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    key_id = generate_keypair(private, public)
    ledger = Ledger.create(
        tmp_path / "ledger.jsonl",
        artifact_root=tmp_path / "artifacts",
        run_id="snapshot-bound",
        charter_sha256=charter.sha256,
        metadata={
            "head_anchors_required": True,
            "anchor_kind": "local_ed25519_checkpoint",
            "anchor_signer_key_id": key_id,
        },
    )
    store = AnchorStore(tmp_path / "anchors")
    anchor_ledger_head(ledger, store, load_private_key(private))
    stale_report = verify_anchor_store(ledger, store, load_public_key(public))
    assert stale_report.current_head_anchored
    ledger.append("run.exited", actor="service:test", data={"status": "success", "error": None})

    report = audit_governance(ledger, charter, anchor_report=stale_report)

    assert "anchor_snapshot_mismatch" in {issue.code for issue in report.issues}
