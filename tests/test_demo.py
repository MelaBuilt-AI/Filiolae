from __future__ import annotations

from pathlib import Path

import pytest

from filiolae.demo import run_demo


def test_demo_happy_and_tamper_paths(tmp_path: Path, charter_path: Path) -> None:
    happy = run_demo(tmp_path / "happy", charter_path=charter_path)
    assert happy["allowed"] and not happy["frozen"]
    assert happy["audit"].startswith("Governance audit valid")
    tamper = run_demo(tmp_path / "tamper", charter_path=charter_path, tamper=True)
    assert not tamper["allowed"] and tamper["frozen"]


def test_demo_refuses_existing_root(tmp_path: Path, charter_path: Path) -> None:
    existing = tmp_path / "existing"
    existing.mkdir()
    marker = existing / "keep.txt"
    marker.write_text("do not delete")
    with pytest.raises(FileExistsError):
        run_demo(existing, charter_path=charter_path)
    assert marker.read_text() == "do not delete"
