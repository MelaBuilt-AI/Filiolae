from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
DEPLOY = ROOT / "deploy" / "systemd"


def _directives(name: str) -> dict[str, list[str]]:
    section = ""
    values: dict[str, list[str]] = {}
    for raw in (DEPLOY / name).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line
            continue
        key, value = line.split("=", 1)
        values.setdefault(f"{section}:{key}", []).append(value)
    return values


def _one(values: dict[str, list[str]], section: str, key: str) -> str:
    found = values[f"[{section}]:{key}"]
    assert len(found) == 1
    return found[0]


def test_sysusers_and_tmpfiles_enforce_separate_least_privilege_owners() -> None:
    sysusers = (DEPLOY / "filiolae.sysusers").read_text().splitlines()
    assert any(re.fullmatch(r"u filiolae-witness .+", line) for line in sysusers)
    assert any(re.fullmatch(r"u filiolae-orchestrator .+", line) for line in sysusers)
    assert "m filiolae-witness filiolae-ledger" in sysusers
    assert "m filiolae-orchestrator filiolae-ledger" in sysusers

    tmpfiles = (DEPLOY / "filiolae.tmpfiles").read_text()
    assert "d /etc/filiolae-witness 0710 root filiolae-witness" in tmpfiles
    assert "d /var/lib/filiolae-witness 0700 filiolae-witness filiolae-witness" in tmpfiles
    assert "d /var/lib/filiolae-gate-mirrors 0700 filiolae-orchestrator filiolae-orchestrator" in tmpfiles
    assert "d /run/filiolae-locks 0710 root filiolae-ledger" in tmpfiles
    assert "d /run/filiolae-witness 0750 filiolae-witness filiolae-ledger" in tmpfiles
    assert " 0777 " not in tmpfiles and " 0775 " not in tmpfiles


def test_witness_unit_pins_paths_uid_and_a_strict_sandbox() -> None:
    unit = _directives("filiolae-witness@.service")
    assert _one(unit, "Service", "User") == "filiolae-witness"
    assert _one(unit, "Service", "Group") == "filiolae-witness"
    assert _one(unit, "Service", "SupplementaryGroups") == "filiolae-ledger"
    command = _one(unit, "Service", "ExecStart")
    expected = {
        "/srv/filiolae/runs/%i/control/filiolae/ledger.jsonl",
        "/run/filiolae-locks/%i/ledger.lock",
        "/run/filiolae-witness/%i.sock",
        "/var/lib/filiolae-witness/%i",
        "/var/lib/filiolae-witness/%i/enrollment.json",
        "/etc/filiolae-witness/ed25519-private.pem",
        "${FILIOLAE_ORCHESTRATOR_UID}",
        "${FILIOLAE_LEDGER_SHARED_GID}",
    }
    assert expected <= set(command.split())
    assert "--socket-mode 0660" in command
    assert "/var/lib/filiolae-witness/%i/enrollment.json" in unit["[Unit]:ConditionPathExists"]
    for key, value in {
        "NoNewPrivileges": "yes",
        "PrivateDevices": "yes",
        "PrivateNetwork": "yes",
        "ProtectSystem": "strict",
        "ProtectHome": "yes",
        "ProtectControlGroups": "yes",
        "RestrictAddressFamilies": "AF_UNIX",
        "RestrictNamespaces": "yes",
        "KillMode": "control-group",
        "SendSIGKILL": "yes",
        "Restart": "no",
    }.items():
        assert _one(unit, "Service", key) == value
    assert _one(unit, "Service", "CapabilityBoundingSet") == ""
    writable = _one(unit, "Service", "ReadWritePaths").split()
    assert "/srv/filiolae/runs/%i" not in writable
    assert "/etc/filiolae-witness" not in writable


def test_orchestrator_is_bound_to_witness_and_kills_the_complete_cgroup() -> None:
    unit = _directives("filiolae-orchestrator@.service")
    assert _one(unit, "Service", "User") == "filiolae-orchestrator"
    assert _one(unit, "Service", "SupplementaryGroups") == "filiolae-ledger"
    assert _one(unit, "Unit", "BindsTo") == "filiolae-witness@%i.service"
    assert _one(unit, "Unit", "After") == "filiolae-witness@%i.service"
    assert _one(unit, "Service", "KillMode") == "control-group"
    assert _one(unit, "Service", "TimeoutStopFailureMode") == "kill"
    assert _one(unit, "Service", "SendSIGKILL") == "yes"
    assert _one(unit, "Service", "OOMPolicy") == "stop"
    assert _one(unit, "Service", "Restart") == "no"
    assert _one(unit, "Service", "ProtectSystem") == "strict"
    assert _one(unit, "Service", "CapabilityBoundingSet") == ""
    environments = unit["[Service]:Environment"]
    assert "FILIOLAE_ANCHOR_WITNESS_SOCKET=/run/filiolae-witness/%i.sock" in environments
    assert "FILIOLAE_ANCHOR_WITNESS_PUBLIC_KEY=/etc/filiolae/ed25519-public.pem" in environments
    assert "FILIOLAE_ANCHOR_WITNESS_MIRROR_DIR=/var/lib/filiolae-gate-mirrors/%i" in environments
    assert "FILIOLAE_LEDGER_LOCK_PATH=/run/filiolae-locks/%i/ledger.lock" in environments
    assert "FILIOLAE_RUN_ID=%i" in environments
    assert not any("PRIVATE" in value or "private" in value for value in environments)


def test_provisioner_preserves_evidence_and_checks_identity_permission_contracts() -> None:
    path = DEPLOY / "provision-unix-witness"
    assert path.stat().st_mode & 0o111
    script = path.read_text()
    assert '[ "$wuid" != "$ouid" ]' in script
    assert 'id -nG "$witness_user"' in script
    assert 'id -nG "$orchestrator_user"' in script
    assert "f $lock 0660 root $shared_group" in script
    provision = script.split("provision)", 1)[1].split(";;", 1)[0]
    assert 'systemd-tmpfiles --create "$tmpfiles"' not in provision
    assert provision.index('install -o root -g root -m 0644 "$t" "$tmpfiles"') < provision.index(
        'ledger-lock-provision "$lock" --mode 0660 --gid "$gid"'
    )
    assert 'ledger-lock-provision "$lock" --mode 0660 --gid "$gid"' in script
    assert "anchor-witness-enroll" in script
    assert "FILIOLAE_WITNESS_ENROLLMENT_SHA256" in script
    assert "refusing retroactive enrollment after Ledger creation" in script
    assert "already enrolled; use validate instead of reprovisioning" in script
    uninstall = script.split("uninstall)", 1)[1]
    assert '"$charter_target"' not in uninstall.split(";;", 1)[0]
    assert "regular file:600:$wuid:$wuid" in script
    assert "directory:700:$wuid:$wuid" in script
    assert "directory:700:$ouid:$ouid" in script
    uninstall = script.split("uninstall)", 1)[1]
    for protected in ('"$output"', '"$anchors"', '"$mirror"'):
        assert f"rm -rf -- {protected}" not in uninstall
    completed = subprocess.run([str(path)], text=True, capture_output=True)
    assert completed.returncode == 64
    assert "usage:" in completed.stderr


def test_units_pass_systemd_parser_when_available(tmp_path: Path) -> None:
    analyzer = shutil.which("systemd-analyze")
    if analyzer is None:
        pytest.skip("systemd-analyze is unavailable")
    names = [
        "filiolae-witness@.service",
        "filiolae-orchestrator@.service",
        "filiolae-governed.slice",
    ]
    for name in names:
        text = (DEPLOY / name).read_text()
        text = text.replace("/usr/libexec/filiolae-witness-ready", str(DEPLOY / "filiolae-witness-ready"))
        (tmp_path / name).write_text(text)
    completed = subprocess.run(
        [analyzer, "verify", *(str(tmp_path / name) for name in names)],
        text=True,
        capture_output=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
