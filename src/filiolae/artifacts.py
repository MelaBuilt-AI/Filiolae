"""Deterministic artifact manifests and digests."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_json


class ArtifactError(ValueError):
    """An artifact cannot be safely or deterministically attested."""


@dataclass(frozen=True)
class Artifact:
    name: str
    path: str
    kind: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _digest_file(path: Path) -> tuple[str, int]:
    before = path.stat(follow_symlinks=False)
    if not path.is_file() or path.is_symlink():
        raise ArtifactError(f"only regular files are supported: {path}")
    if before.st_nlink != 1:
        raise ArtifactError(f"multiply-linked files are rejected: {path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    after = path.stat(follow_symlinks=False)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or size != after.st_size:
        raise ArtifactError(f"artifact changed while hashing: {path}")
    return digest.hexdigest(), size


def _directory_manifest(path: Path) -> tuple[list[dict[str, Any]], int]:
    entries: list[dict[str, Any]] = []
    total_size = 0
    for candidate in sorted(path.rglob("*"), key=lambda item: item.relative_to(path).as_posix()):
        relative = candidate.relative_to(path).as_posix()
        if candidate.is_symlink():
            raise ArtifactError(f"symlinks are rejected in attested directories: {candidate}")
        if candidate.is_dir():
            entries.append({"path": relative, "kind": "directory"})
        elif candidate.is_file():
            digest, size = _digest_file(candidate)
            entries.append({"path": relative, "kind": "file", "sha256": digest, "size": size})
            total_size += size
        else:
            raise ArtifactError(f"unsupported filesystem entry: {candidate}")
    return entries, total_size


def digest_path(path: str | Path) -> tuple[str, str, int]:
    supplied = Path(path)
    if supplied.is_symlink():
        raise ArtifactError(f"symlinks are rejected: {supplied}")
    target = supplied.resolve(strict=True)
    if target.is_file():
        digest, size = _digest_file(target)
        return "file", digest, size
    if target.is_dir():
        entries, size = _directory_manifest(target)
        digest = hashlib.sha256(canonical_json({"kind": "directory", "entries": entries})).hexdigest()
        return "directory", digest, size
    raise ArtifactError(f"unsupported artifact type: {target}")


def _relative_artifact_path(value: str) -> Path:
    """Parse the portable relative path stored in an artifact descriptor."""
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ArtifactError("artifact path is not a non-empty string or contains NUL")
    path = Path(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ArtifactError("artifact path is not a canonical relative POSIX path")
    return path


def _reject_symlinks_beneath(root: Path, relative: Path) -> Path:
    """Return a lexical target after rejecting symlinks in every in-root component."""
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ArtifactError(f"symlinks are rejected: {current}")
    return current


def attest_path(name: str, path: str | Path, *, root: str | Path) -> Artifact:
    root_path = Path(root).resolve(strict=True)
    supplied = Path(path).absolute()
    try:
        relative_path = supplied.relative_to(root_path)
    except ValueError as exc:
        raise ArtifactError(f"artifact escapes the declared root: {supplied}") from exc
    relative = _relative_artifact_path(relative_path.as_posix())
    target = _reject_symlinks_beneath(root_path, relative)
    kind, digest, size = digest_path(target)
    return Artifact(name=name, path=relative.as_posix(), kind=kind, sha256=digest, size=size)


def verify_artifact(artifact: Artifact, *, root: str | Path) -> str | None:
    try:
        if not artifact.name:
            raise ArtifactError("artifact name is empty")
        relative = _relative_artifact_path(artifact.path)
        if artifact.kind not in {"file", "directory"}:
            raise ArtifactError(f"unsupported artifact kind: {artifact.kind}")
        if len(artifact.sha256) != 64 or any(char not in "0123456789abcdef" for char in artifact.sha256):
            raise ArtifactError("artifact sha256 is not a lowercase SHA-256 digest")
        if isinstance(artifact.size, bool) or not isinstance(artifact.size, int) or artifact.size < 0:
            raise ArtifactError("artifact size is not a non-negative integer")
        root_path = Path(root).resolve(strict=True)
        target = _reject_symlinks_beneath(root_path, relative)
        kind, digest, size = digest_path(target)
    except (ArtifactError, FileNotFoundError, OSError, TypeError, ValueError) as exc:
        return str(exc)
    if kind != artifact.kind:
        return f"kind changed: expected {artifact.kind}, got {kind}"
    if size != artifact.size:
        return f"size changed: expected {artifact.size}, got {size}"
    if digest != artifact.sha256:
        return f"digest changed: expected {artifact.sha256}, got {digest}"
    return None
