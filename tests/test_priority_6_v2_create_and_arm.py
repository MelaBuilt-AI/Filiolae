from __future__ import annotations

import datetime as dt
import importlib.util
import sys
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).parents[1] / "ops" / "priority-6-v2" / "create_and_arm_pod.py"
SPEC = importlib.util.spec_from_file_location("priority_6_v2_create_and_arm", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
creator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = creator
SPEC.loader.exec_module(creator)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-08-13 21:44:46 UTC", dt.datetime(2026, 8, 13, 21, 44, 46, tzinfo=dt.UTC)),
        ("2026-08-13T21:44:46Z", dt.datetime(2026, 8, 13, 21, 44, 46, tzinfo=dt.UTC)),
        (
            "2026-08-13T17:44:46-04:00",
            dt.datetime(2026, 8, 13, 21, 44, 46, tzinfo=dt.UTC),
        ),
    ],
)
def test_parse_created_at_accepts_actual_prime_and_iso_forms(raw, expected):
    assert creator.parse_created_at(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [None, 123, "2026-08-13 21:44:46", "not-a-time"],
)
def test_parse_created_at_rejects_missing_ambiguous_or_invalid_values(raw):
    with pytest.raises(creator.CreatorError):
        creator.parse_created_at(raw)


def test_parse_created_pod_id_requires_one_full_success_record():
    pod_id = "24b80331e5234775a3ce789f66465087"
    output = f"Creating pod...\n\nSuccessfully created pod {pod_id}\n"
    assert creator.parse_created_pod_id(output) == pod_id


@pytest.mark.parametrize(
    "output",
    [
        "Successfully created pod short id with spaces\n",
        "Successfully created pod a\nSuccessfully created pod b\n",
        "created 24b80331e5234775a3ce789f66465087\n",
    ],
)
def test_parse_created_pod_id_rejects_missing_or_ambiguous_output(output):
    with pytest.raises(creator.CreatorError):
        creator.parse_created_pod_id(output)


def test_atomic_write_replaces_complete_owner_only_file(tmp_path):
    target = tmp_path / "state" / "record.json"
    creator.atomic_write(target, b"first\n")
    assert target.read_bytes() == b"first\n"
    assert target.stat().st_mode & 0o777 == 0o600
    assert target.parent.stat().st_mode & 0o777 == 0o700
    creator.atomic_write(target, b"second\n")
    assert target.read_bytes() == b"second\n"
    assert list(target.parent.glob(".*-" + "*")) == []


def test_main_arms_exact_watchdog_from_actual_prime_timestamp(tmp_path, monkeypatch):
    pod_id = "replacementpod123"
    controller_path = tmp_path / "controller.py"
    template_path = tmp_path / "watchdog.service"
    controller_path.write_text("controller bytes\n")
    template_path.write_text("unit bytes\n")
    controller_digest = creator.sha256_file(controller_path)
    template_digest = creator.sha256_file(template_path)
    active_calls = iter(
        [
            [],
            [
                {
                    "created_at": "2026-08-13 21:44:46 UTC",
                    "id": pod_id,
                    "name": "replacement-name",
                    "status": "PROVISIONING",
                }
            ],
        ]
    )
    monkeypatch.setattr(creator, "list_active", lambda _prime: next(active_calls))

    def fake_run(argv, *, timeout=180, check=True):
        del timeout, check
        if argv[:4] == ["prime", "--plain", "pods", "create"]:
            return creator.subprocess.CompletedProcess(
                argv,
                0,
                f"Successfully created pod {pod_id}\n",
                "",
            )
        if argv[:4] == ["systemctl", "--user", "enable", "--now"]:
            return creator.subprocess.CompletedProcess(argv, 0, "", "")
        if "ActiveState" in argv:
            return creator.subprocess.CompletedProcess(argv, 0, "active\n", "")
        if "MainPID" in argv:
            return creator.subprocess.CompletedProcess(argv, 0, "4321\n", "")
        if argv[0] == str(controller_path.resolve()) and "status" in argv:
            return creator.subprocess.CompletedProcess(argv, 0, f'{{"id":"{pod_id}"}}\n', "")
        raise AssertionError(f"unexpected command: {argv}")

    monkeypatch.setattr(creator, "run", fake_run)
    life = tmp_path / "life"
    result = creator.main(
        [
            "--prime-bin",
            "prime",
            "--controller",
            str(controller_path),
            "--controller-sha256",
            controller_digest,
            "--watchdog-template",
            str(template_path),
            "--watchdog-template-sha256",
            template_digest,
            "--watchdog-environment-dir",
            str(tmp_path / "env"),
            "--state-dir",
            str(tmp_path / "state"),
            "--life-dir",
            str(life),
            "--availability-id",
            "availability123",
            "--name",
            "replacement-name",
        ]
    )

    assert result == 0
    assert (life / "POD_ID").read_text() == f"{pod_id}\n"
    armed = creator.json.loads((life / "ARMED.json").read_text())
    assert armed["pod_id"] == pod_id
    assert armed["main_pid"] == 4321
    assert armed["deadline"] == "2026-08-14T00:44:46Z"
    assert (tmp_path / "env" / f"{pod_id}.env").read_text() == ("DEADLINE_UTC=2026-08-14T00:44:46Z\n")
