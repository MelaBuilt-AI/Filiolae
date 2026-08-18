from __future__ import annotations

from pathlib import Path

import pytest

from filiolae.charter import Charter, CharterError


def test_charter_digest_stable(charter_path: Path) -> None:
    assert Charter.load(charter_path).sha256 == Charter.load(charter_path).sha256


def test_duplicate_yaml_key_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("version: 1\nversion: 1\nclauses: []\n")
    with pytest.raises(CharterError, match="duplicate Charter key"):
        Charter.load(path)


def test_unknown_clause_rule_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        """version: 1
clauses:
  - id: X
    severity: hard
    statement: nope
    rule: execute_python
    parameters: {}
"""
    )
    with pytest.raises(CharterError, match="unknown Charter rule"):
        Charter.load(path)


def test_boolean_version_is_not_accepted_as_integer_one(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("version: true\nclauses: []\n")
    with pytest.raises(CharterError, match="unsupported Charter version"):
        Charter.load(path)


def test_clause_required_strings_are_not_coerced(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        """version: 1
clauses:
  - id: 7
    severity: hard
    statement: nope
    rule: immutable_artifacts
"""
    )
    with pytest.raises(CharterError, match="id must be a non-empty string"):
        Charter.load(path)
