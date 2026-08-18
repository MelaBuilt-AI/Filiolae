from __future__ import annotations

from pathlib import Path

import pytest

from filiolae.charter import Charter


@pytest.fixture
def charter_path(tmp_path: Path) -> Path:
    path = tmp_path / "charter.yaml"
    path.write_text(
        """version: 1
clauses:
  - id: C-DEMO-001
    severity: hard
    statement: Ledgered artifacts are immutable.
    rule: immutable_artifacts
    parameters: {}
  - id: C-DEMO-002
    severity: hard
    statement: Promotions require evidence.
    rule: promotion_evidence_required
    parameters:
      events: [config.resolved, batch.committed, source_eval.result, weights.published]
  - id: C-DEMO-003
    severity: hard
    statement: Integrity failure freezes the run.
    rule: freeze_on_integrity_failure
    parameters: {}
"""
    )
    return path


@pytest.fixture
def charter(charter_path: Path) -> Charter:
    return Charter.load(charter_path)
