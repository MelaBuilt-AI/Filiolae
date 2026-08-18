from __future__ import annotations

import hashlib
import json
from pathlib import Path

from filiolae.anchor import load_public_key
from filiolae.audit import audit_governance
from filiolae.charter import Charter
from filiolae.ledger import Ledger
from filiolae.paired_eval import load_request, request_sha256, verify_terminal_evidence

ROOT = Path(__file__).parents[1]
EVIDENCE = ROOT / "evidence" / "acceptance" / "priority-6-v2-distinct-uid-fixture-20260813"
PACKAGE = EVIDENCE / "package"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_priority6_v2_hosted_distinct_uid_package_is_complete_and_reverifies() -> None:
    inventory: dict[str, str] = {}
    for line in (PACKAGE / "SHA256SUMS").read_text().splitlines():
        digest, relative = line.split("  ", 1)
        inventory[relative] = digest
    actual = {
        path.relative_to(PACKAGE).as_posix()
        for path in PACKAGE.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    assert set(inventory) == actual
    assert all(_sha256(PACKAGE / relative) == digest for relative, digest in inventory.items())
    assert _sha256(PACKAGE / "SHA256SUMS") == (
        "3c86d2b6239d0e9969db6a074b17e91fc1da9aa7c4afd02729a104327d853d11"
    )
    assert not any(path.is_symlink() for path in PACKAGE.rglob("*"))
    assert not any("private" in path.name.lower() for path in PACKAGE.rglob("*"))

    manifest = json.loads((PACKAGE / "PACKAGE.json").read_text())
    assert manifest["file_count_excluding_manifests"] == 33
    assert set(manifest["files"]) == actual - {"PACKAGE.json"}
    summary = json.loads((PACKAGE / "SUMMARY.json").read_text())
    cleanup = json.loads((PACKAGE / "CLEANUP.json").read_text())
    service = json.loads((PACKAGE / "EVALUATOR-SERVICE.json").read_text())
    assert summary["controller_uid"] == 999
    assert summary["evaluator_uid"] == 997
    assert summary["separate_os_credential"] is True
    assert summary["request_allowlist_mode"] == "0400"
    assert summary["private_key_unreadable_to_controller"] is True
    assert summary["terminal_unwritable_by_controller"] is True
    assert summary["exact_approvals"] == 1
    assert summary["exact_promotions"] == 1
    assert cleanup["evaluator_private_key_absent"] is True
    assert cleanup["evaluator_processes_remaining"] == 0
    assert service["evaluator_uid"] == summary["evaluator_uid"]
    assert service["request_sha256"] == summary["request_sha256"]

    request = load_request(PACKAGE / "request.json")
    assert request_sha256(request) == summary["request_sha256"]
    receipt = verify_terminal_evidence(
        PACKAGE / "terminal",
        request,
        load_public_key(PACKAGE / "evaluator-public.pem"),
        PACKAGE / "inputs" / "suite.jsonl",
    )
    assert receipt.body["candidate_quality_bps"] == 10_000
    assert receipt.body["source_quality_bps"] == 10_000

    ledger = Ledger(
        PACKAGE / "governance" / "ledger.jsonl",
        artifact_root=PACKAGE / "governance" / "artifacts",
    )
    report = audit_governance(
        ledger,
        Charter.load(PACKAGE / "charter.yaml"),
        verify_artifacts=True,
        candidate_eval_public_key=load_public_key(PACKAGE / "evaluator-public.pem"),
    )
    assert report.ok, report.summary()
    assert report.record_count == 9
    assert report.promotion_count == 1
