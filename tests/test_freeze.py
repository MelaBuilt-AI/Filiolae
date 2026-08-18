from pathlib import Path

from filiolae.freeze import FreezeController


def test_new_controller_reads_and_latches_marker_after_deletion(tmp_path: Path) -> None:
    path = tmp_path / "freeze.json"
    FreezeController(path).freeze("durable reason", details={"step": 2})
    reader = FreezeController(path)
    state = reader.state()
    assert state.frozen and state.reason == "durable reason"
    path.unlink()
    assert reader.state() == state


def test_symlink_marker_is_invalid_and_latched(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("not trusted")
    marker = tmp_path / "freeze.json"
    marker.symlink_to(target)
    reader = FreezeController(marker)
    assert reader.state().reason == "invalid freeze marker"
    marker.unlink()
    assert reader.state().frozen


def test_malformed_regular_marker_is_fail_closed(tmp_path: Path) -> None:
    marker = tmp_path / "freeze.json"
    marker.write_text('{"details":{},"reason":7,"schema":"wrong","ts":"not-a-time"}\n')
    state = FreezeController(marker).state()
    assert state.frozen
    assert state.reason == "invalid freeze marker"
