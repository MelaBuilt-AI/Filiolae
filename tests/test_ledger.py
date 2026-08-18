from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from filiolae.ledger import Ledger, LedgerIntegrityError


def test_hash_chain_detects_content_edit(tmp_path: Path) -> None:
    ledger = Ledger.create(
        tmp_path / "ledger.jsonl",
        artifact_root=tmp_path,
        run_id="r1",
        charter_sha256="a" * 64,
    )
    ledger.append("run.exited", actor="supervisor", data={"code": 0})
    lines = ledger.path.read_text().splitlines()
    value = json.loads(lines[0])
    value["run_id"] = "rewritten"
    lines[0] = json.dumps(value, sort_keys=True, separators=(",", ":"))
    ledger.path.write_text("\n".join(lines) + "\n")
    report = ledger.audit()
    assert not report.ok
    assert {issue.code for issue in report.issues} >= {"record_hash_mismatch", "run_id_mismatch"}
    with pytest.raises(LedgerIntegrityError):
        ledger.append("run.exited", actor="supervisor")


def test_noncanonical_physical_record_rejected(tmp_path: Path) -> None:
    ledger = Ledger.create(
        tmp_path / "ledger.jsonl",
        artifact_root=tmp_path,
        run_id="r1",
        charter_sha256="a" * 64,
    )
    value = json.loads(ledger.path.read_text())
    ledger.path.write_text(json.dumps(value, sort_keys=True, separators=(", ", ": ")) + "\n")
    assert "noncanonical_record" in {issue.code for issue in ledger.audit().issues}


def test_truncated_record_rejected(tmp_path: Path) -> None:
    ledger = Ledger.create(
        tmp_path / "ledger.jsonl",
        artifact_root=tmp_path,
        run_id="r1",
        charter_sha256="a" * 64,
    )
    ledger.path.write_bytes(ledger.path.read_bytes()[:-1])
    assert "truncated_line" in {issue.code for issue in ledger.audit().issues}


def test_concurrent_cooperating_appends_remain_a_single_chain(tmp_path: Path) -> None:
    ledger = Ledger.create(
        tmp_path / "ledger.jsonl",
        artifact_root=tmp_path,
        run_id="r1",
        charter_sha256="a" * 64,
    )
    with ThreadPoolExecutor(max_workers=8) as pool:
        records = list(
            pool.map(
                lambda index: ledger.append("batch.committed", actor="worker", data={"index": index}),
                range(32),
            )
        )
    report = ledger.audit()
    assert report.ok, report.summary()
    assert len(report.records) == 33
    assert {record.seq for record in records} == set(range(1, 33))


def test_ledger_symlink_or_hardlink_substitution_is_rejected(tmp_path: Path) -> None:
    real = Ledger.create(
        tmp_path / "real.jsonl",
        artifact_root=tmp_path,
        run_id="r1",
        charter_sha256="a" * 64,
    )
    original = real.path.read_bytes()
    alias = tmp_path / "alias.jsonl"
    alias.symlink_to(real.path)
    substituted = Ledger(alias, artifact_root=tmp_path)
    assert "unsafe_ledger" in {issue.code for issue in substituted.audit().issues}
    with pytest.raises(LedgerIntegrityError):
        substituted.append("run.exited", actor="worker")
    alias.unlink()
    alias.hardlink_to(real.path)
    assert "unsafe_ledger" in {issue.code for issue in substituted.audit().issues}
    with pytest.raises(LedgerIntegrityError):
        substituted.append("run.exited", actor="worker")
    assert real.path.read_bytes() == original


def test_noncooperating_write_during_append_is_detected_before_return(tmp_path: Path, monkeypatch) -> None:
    ledger = Ledger.create(
        tmp_path / "ledger.jsonl",
        artifact_root=tmp_path,
        run_id="r1",
        charter_sha256="a" * 64,
    )
    original_read = ledger._read_descriptor
    reads = 0

    def inject_after_commit(descriptor: int) -> bytes:
        nonlocal reads
        reads += 1
        if reads == 2:
            with ledger.path.open("ab") as attacker:
                attacker.write(b"\n")
                attacker.flush()
        return original_read(descriptor)

    monkeypatch.setattr(ledger, "_read_descriptor", inject_after_commit)
    with pytest.raises(LedgerIntegrityError, match="changed concurrently"):
        ledger.append("batch.committed", actor="worker", data={"step": 1})
    assert "blank_line" in {issue.code for issue in ledger.audit().issues}
