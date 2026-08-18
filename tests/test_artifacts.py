from __future__ import annotations

from pathlib import Path

import pytest

from filiolae.artifacts import Artifact, ArtifactError, attest_path, verify_artifact
from filiolae.store import ArtifactStore


def test_store_stages_content_addressed_copy(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"trusted bytes")
    store = ArtifactStore(tmp_path / "store")
    artifact = store.put("weights", source)
    stored = store.resolve(artifact)
    source.write_bytes(b"mutated untrusted source")
    assert stored.read_bytes() == b"trusted bytes"
    assert verify_artifact(artifact, root=store.root) is None


def test_store_materializes_independent_verified_file(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"approved")
    store = ArtifactStore(tmp_path / "store")
    artifact = store.put("weights", source)
    load_copy = store.materialize(artifact, tmp_path / "loads" / "weights.bin")
    load_copy.write_bytes(b"consumer mutation")
    assert store.resolve(artifact).read_bytes() == b"approved"
    assert verify_artifact(artifact, root=store.root) is None
    with pytest.raises(FileExistsError):
        store.materialize(artifact, load_copy)


def test_store_rejects_symlink(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"x")
    link = tmp_path / "link.bin"
    link.symlink_to(source)
    with pytest.raises(ArtifactError, match="symlinks"):
        ArtifactStore(tmp_path / "store").put("x", link)


def test_stored_corruption_detected(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"x")
    store = ArtifactStore(tmp_path / "store")
    artifact = store.put("x", source)
    store.resolve(artifact).write_bytes(b"y")
    assert verify_artifact(artifact, root=store.root) is not None


def test_verifier_rejects_malformed_or_missing_paths_without_raising(tmp_path: Path) -> None:
    malformed = Artifact("x", "../escape", "file", "0" * 64, 0)
    missing = Artifact("x", "missing", "file", "0" * 64, 0)
    assert "canonical relative" in (verify_artifact(malformed, root=tmp_path) or "")
    assert verify_artifact(missing, root=tmp_path) is not None


def test_verifier_rejects_symlink_substitution_even_when_bytes_match(tmp_path: Path) -> None:
    root = tmp_path / "store"
    root.mkdir()
    real = root / "real"
    real.write_bytes(b"same")
    artifact = attest_path("x", real, root=root)
    alias = root / "alias"
    alias.symlink_to(real)
    substituted = Artifact(
        artifact.name,
        "alias",
        artifact.kind,
        artifact.sha256,
        artifact.size,
    )
    assert "symlinks are rejected" in (verify_artifact(substituted, root=root) or "")
    with pytest.raises(ArtifactError, match="symlinks are rejected"):
        attest_path("x", alias, root=root)
