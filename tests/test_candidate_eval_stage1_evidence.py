from __future__ import annotations

import hashlib
import json
from pathlib import Path

from filiolae.anchor import load_public_key
from filiolae.paired_eval import load_request, request_sha256, verify_terminal_evidence

ROOT = Path(__file__).parents[1]
EVIDENCE = ROOT / "evidence" / "acceptance" / "candidate-eval-stage1-20260813"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_stage1_evidence_inventory_and_signed_complete_outputs_verify() -> None:
    entries = {}
    for line in (EVIDENCE / "SHA256SUMS").read_text().splitlines():
        digest, relative = line.split("  ", 1)
        entries[relative] = digest
    actual = {
        path.relative_to(EVIDENCE).as_posix()
        for path in EVIDENCE.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    assert set(entries) == actual
    assert all(_sha(EVIDENCE / relative) == digest for relative, digest in entries.items())
    assert _sha(EVIDENCE / "SHA256SUMS") == (
        "85372cb022989f513c4fc9d3de5990c88e70bcd001ef3c8d2849fc4af4e40dd9"
    )
    package = json.loads((EVIDENCE / "PACKAGE.json").read_text())
    assert package["status"] == "process-passed-separate-credential-pending"
    assert package["private_key_retained"] is False
    assert not any("private" in path.name.lower() for path in EVIDENCE.rglob("*"))

    request_path = next((EVIDENCE / "requests").glob("*.json"))
    request = load_request(request_path)
    assert request_sha256(request) == request_path.stem
    receipt = verify_terminal_evidence(
        EVIDENCE / "terminal",
        request,
        load_public_key(EVIDENCE / "evaluator-public.pem"),
        EVIDENCE / "reverse-text-held-out-v1.jsonl",
    )
    assert receipt.body["candidate_quality_bps"] == 10_000
    assert receipt.body["source_quality_bps"] == 10_000
    summary = json.loads((EVIDENCE / "controller-summary.json").read_text())
    assert summary["separate_process"] is True
    assert summary["separate_os_credential"] is False
    assert summary["lost_response_recovered"] is True
