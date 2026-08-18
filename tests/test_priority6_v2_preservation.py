from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).parents[1]
CLOSEOUT = ROOT / "evidence" / "acceptance" / "priority-6-v2-closeout-20260814"
CLOUD = ROOT / "evidence" / "acceptance" / "priority-6-v2-aws-object-lock-restore-20260814"
EXPECTED_SIZE = 2_385_167_636
EXPECTED_SHA256 = "ffe77bc5f4b6f7c65dc7c2a7ff44eeb5335789431b389ed0eedb3d5f1adb57ab"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verify_inventory(root: Path) -> None:
    expected: dict[str, str] = {}
    for line in (root / "SHA256SUMS").read_text().splitlines():
        digest, relative = line.split("  ", 1)
        expected[relative] = digest
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    assert set(expected) == actual
    assert all(_sha256(root / relative) == digest for relative, digest in expected.items())


def test_owner_supplied_aws_restore_proof_is_complete_and_self_consistent() -> None:
    _verify_inventory(CLOUD)
    record = json.loads((CLOUD / "evidence.json").read_text())
    assert record["archive"]["canonical_size_bytes"] == EXPECTED_SIZE
    assert record["archive"]["canonical_sha256"] == EXPECTED_SHA256
    assert record["reported_backup_configuration"]["object_lock_immutability"] == "Enabled"
    assert record["reported_backup_configuration"]["retention_days"] == 1095
    assert record["reported_backup"]["result"] == "Success"
    assert record["reported_restore"]["result"] == "Success"
    assert record["reported_restore"]["archive_reported_size_bytes"] == EXPECTED_SIZE
    assert record["reported_restore"]["size_matches_canonical"] is True
    assert record["reported_post_restore_hash"]["sha256"] == EXPECTED_SHA256
    assert record["reported_post_restore_hash"]["matches_canonical"] is True
    for source in record["source"]["files"]:
        path = CLOUD / source["path"]
        assert path.stat().st_size == source["size_bytes"]
        assert _sha256(path) == source["sha256"]


def test_closeout_inventory_links_exact_cloud_record_without_claiming_direct_access() -> None:
    _verify_inventory(CLOSEOUT)
    inventory = json.loads((CLOSEOUT / "preservation-inventory.json").read_text())
    cloud = inventory["owner_supplied_cloud_recovery_verification"]
    assert cloud["record_sha256"] == _sha256(CLOUD / "evidence.json")
    assert cloud["reported_object_lock_enabled"] is True
    assert cloud["reported_restored_size_bytes"] == EXPECTED_SIZE
    assert cloud["reported_restored_sha256"] == EXPECTED_SHA256
    assert cloud["matches_expected"] is True
    assert "did not directly access" in cloud["evidence_boundary"]
    assert not any(path.name.endswith(".tar.gz") for path in CLOUD.rglob("*"))
