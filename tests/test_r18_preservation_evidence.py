from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "acceptance" / "r18-preservation-20260813"


def _rows(name: str) -> list[dict[str, str]]:
    with (EVIDENCE / name).open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _restore_inventory(rows: list[dict[str, str]]) -> dict[str, int]:
    marker = "\\Filiolae Evidence\\"
    return {row["File"].split(marker, 1)[1]: int(row["Size"]) for row in rows}


def _backup_paths(rows: list[dict[str, str]]) -> set[str]:
    prefix = "D:\\Filiolae Evidence\\"
    return {row["File"].removeprefix(prefix) for row in rows if row["File"] != "Detailed report"}


def test_r18_preservation_evidence_inventory_and_results() -> None:
    if not EVIDENCE.is_dir():
        pytest.skip("canonical private-checkout preservation evidence is absent")

    inventory = (EVIDENCE / "SHA256SUMS").read_bytes()
    assert hashlib.sha256(inventory).hexdigest() == (
        "449b00c638178744a53d8d5442057f0e02dd84ca22faa16c1f2f58a0fdcf51e4"
    )
    for line in inventory.decode().splitlines():
        expected, name = line.split("  ", 1)
        assert hashlib.sha256((EVIDENCE / name).read_bytes()).hexdigest() == expected

    package = json.loads((EVIDENCE / "PACKAGE.json").read_text())
    assert package["package_sha256sums_sha256"] == (
        "deec38be4eb295aa6594732bfb92a9a00b5e50f19d4e8ec903655e3699aca50c"
    )
    assert package["aws"]["msp360_object_lock_immutability"] == "enabled"
    assert package["backblaze_b2"]["msp360_object_lock_immutability"] == "disabled"

    reports = {
        name: _rows(name)
        for name in (
            "aws-backup-report.csv",
            "b2-backup-report.csv",
            "aws-restore-report.csv",
            "b2-restore-report.csv",
        )
    }
    assert all(
        row["Result"] == "Success" and not row["Error Message"] for rows in reports.values() for row in rows
    )
    assert len(reports["aws-backup-report.csv"]) == 34
    assert len(reports["b2-backup-report.csv"]) == 34
    assert len(reports["aws-restore-report.csv"]) == 33
    assert len(reports["b2-restore-report.csv"]) == 33

    aws_restore = _restore_inventory(reports["aws-restore-report.csv"])
    b2_restore = _restore_inventory(reports["b2-restore-report.csv"])
    assert aws_restore == b2_restore
    assert len(aws_restore) == 33
    assert sum(aws_restore.values()) == 12_074_156_520
    package_inventory = {
        name: size for name, size in aws_restore.items() if name.startswith("Filiolae-r18-preservation\\")
    }
    assert len(package_inventory) == 32
    assert sum(package_inventory.values()) == 12_074_083_151
    assert _backup_paths(reports["aws-backup-report.csv"]) == set(aws_restore)
    assert _backup_paths(reports["b2-backup-report.csv"]) == set(aws_restore)
