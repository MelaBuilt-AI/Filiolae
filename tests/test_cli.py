from __future__ import annotations

import sys
from pathlib import Path

from filiolae.cli import main


def test_demo_and_audit_cli(tmp_path: Path, charter_path: Path) -> None:
    run = tmp_path / "demo"
    assert main(["demo", str(run), "--charter", str(charter_path)]) == 0
    assert (
        main(
            [
                "audit",
                str(run / "control" / "ledger.jsonl"),
                "--artifact-root",
                str(run / "control" / "artifacts"),
                "--charter",
                str(run / "control" / "charter.yaml"),
            ]
        )
        == 0
    )


def test_supervise_cli_zero_exit(tmp_path: Path) -> None:
    assert (
        main(
            [
                "supervise",
                "--freeze-marker",
                str(tmp_path / "freeze.json"),
                "--term-grace",
                "0.1",
                "--",
                sys.executable,
                "-c",
                "raise SystemExit(0)",
            ]
        )
        == 0
    )


def test_anchor_cli_round_trip(tmp_path: Path, charter_path: Path) -> None:
    run = tmp_path / "demo-anchor"
    assert main(["demo", str(run), "--charter", str(charter_path)]) == 0
    private = tmp_path / "keys" / "private.pem"
    public = tmp_path / "keys" / "public.pem"
    anchors = tmp_path / "external" / "anchors"
    ledger = run / "control" / "ledger.jsonl"
    artifacts = run / "control" / "artifacts"
    charter = run / "control" / "charter.yaml"
    assert (
        main(
            [
                "anchor-keygen",
                "--private-key",
                str(private),
                "--public-key",
                str(public),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "anchor-head",
                str(ledger),
                "--artifact-root",
                str(artifacts),
                "--anchor-dir",
                str(anchors),
                "--private-key",
                str(private),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "verify-anchors",
                str(ledger),
                "--anchor-dir",
                str(anchors),
                "--public-key",
                str(public),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "audit",
                str(ledger),
                "--artifact-root",
                str(artifacts),
                "--charter",
                str(charter),
                "--anchor-dir",
                str(anchors),
                "--anchor-public-key",
                str(public),
            ]
        )
        == 0
    )


def test_cli_reports_package_version(capsys) -> None:
    import pytest

    with pytest.raises(SystemExit) as stopped:
        main(["--version"])
    assert stopped.value.code == 0
    assert capsys.readouterr().out.strip() == "filiolae 0.1.0"


def test_cli_help_displays_agpl_legal_notice(capsys) -> None:
    import pytest

    with pytest.raises(SystemExit) as stopped:
        main(["--help"])
    assert stopped.value.code == 0
    output = capsys.readouterr().out
    assert "AGPL-3.0-only" in output
    assert "ABSOLUTELY NO WARRANTY" in output
    assert "https://github.com/MelaBuilt-AI/Filiolae" in output


def test_chain_only_rejects_misleading_anchor_flags(tmp_path: Path, charter_path: Path) -> None:
    import pytest

    with pytest.raises(SystemExit, match="cannot be combined"):
        main(
            [
                "audit",
                str(tmp_path / "ledger.jsonl"),
                "--artifact-root",
                str(tmp_path / "artifacts"),
                "--charter",
                str(charter_path),
                "--chain-only",
                "--anchor-dir",
                str(tmp_path / "anchors"),
                "--anchor-public-key",
                str(tmp_path / "public.pem"),
            ]
        )


def test_ledger_lock_provision_cli(tmp_path: Path) -> None:
    lock_path = tmp_path / "shared" / "ledger.lock"
    assert main(["ledger-lock-provision", str(lock_path), "--mode", "0600"]) == 0
    assert lock_path.is_file()
    assert lock_path.stat().st_mode & 0o777 == 0o600
    assert lock_path.parent.stat().st_mode & 0o777 == 0o750
