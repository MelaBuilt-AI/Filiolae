"""Gate-owned content-addressed artifact storage."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from .artifacts import Artifact, ArtifactError, digest_path


class ArtifactStore:
    """Stage exact bytes into a gate-owned content-addressed directory.

    The source is digested before and after copying; the staged copy must match.
    Symlinks and special files are rejected by ``digest_path``.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, name: str, source: str | Path) -> Artifact:
        supplied = Path(source)
        if supplied.is_symlink():
            raise ArtifactError(f"symlinks are rejected: {supplied}")
        source_path = supplied.resolve(strict=True)
        kind_before, digest_before, size_before = digest_path(source_path)
        namespace = "files" if kind_before == "file" else "trees"
        destination = self.root / "sha256" / namespace / digest_before[:2] / digest_before
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            kind_stored, digest_stored, size_stored = digest_path(destination)
            if (kind_stored, digest_stored, size_stored) != (kind_before, digest_before, size_before):
                raise ArtifactError(f"content-address collision or corrupt stored artifact: {destination}")
        else:
            temporary_parent = destination.parent
            if kind_before == "file":
                descriptor, temporary_name = tempfile.mkstemp(prefix=".stage-", dir=temporary_parent)
                os.close(descriptor)
                temporary = Path(temporary_name)
                try:
                    shutil.copyfile(source_path, temporary, follow_symlinks=False)
                    with temporary.open("rb") as stream:
                        os.fsync(stream.fileno())
                    kind_staged, digest_staged, size_staged = digest_path(temporary)
                    kind_after, digest_after, size_after = digest_path(source_path)
                    expected = (kind_before, digest_before, size_before)
                    if (kind_staged, digest_staged, size_staged) != expected or (
                        kind_after,
                        digest_after,
                        size_after,
                    ) != expected:
                        raise ArtifactError(f"artifact changed while staging: {source_path}")
                    os.replace(temporary, destination)
                finally:
                    temporary.unlink(missing_ok=True)
            else:
                temporary = Path(tempfile.mkdtemp(prefix=".stage-", dir=temporary_parent))
                try:
                    shutil.rmtree(temporary)
                    shutil.copytree(source_path, temporary, symlinks=False)
                    kind_staged, digest_staged, size_staged = digest_path(temporary)
                    kind_after, digest_after, size_after = digest_path(source_path)
                    expected = (kind_before, digest_before, size_before)
                    if (kind_staged, digest_staged, size_staged) != expected or (
                        kind_after,
                        digest_after,
                        size_after,
                    ) != expected:
                        raise ArtifactError(f"artifact changed while staging: {source_path}")
                    os.replace(temporary, destination)
                finally:
                    if temporary.exists():
                        shutil.rmtree(temporary)
            directory_fd = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        relative = destination.relative_to(self.root).as_posix()
        return Artifact(name=name, path=relative, kind=kind_before, sha256=digest_before, size=size_before)

    def materialize(self, artifact: Artifact, destination: str | Path) -> Path:
        """Create a verified disposable copy without exposing the immutable store to consumers."""
        source = self.resolve(artifact)
        expected = (artifact.kind, artifact.sha256, artifact.size)
        if digest_path(source) != expected:
            raise ArtifactError(f"stored artifact no longer matches its descriptor: {source}")
        supplied = Path(destination).absolute()
        if supplied.exists() or supplied.is_symlink():
            raise FileExistsError(f"materialized artifact destination exists: {supplied}")
        supplied.parent.mkdir(parents=True, exist_ok=True)
        parent = supplied.parent.resolve(strict=True)
        target = parent / supplied.name
        temporary: Path
        if artifact.kind == "file":
            descriptor, temporary_name = tempfile.mkstemp(prefix=".load-", dir=parent)
            os.close(descriptor)
            temporary = Path(temporary_name)
            try:
                shutil.copyfile(source, temporary, follow_symlinks=False)
                with temporary.open("rb") as stream:
                    os.fsync(stream.fileno())
                if digest_path(temporary) != expected or digest_path(source) != expected:
                    raise ArtifactError(f"artifact changed while materializing: {source}")
                os.replace(temporary, target)
            finally:
                temporary.unlink(missing_ok=True)
        elif artifact.kind == "directory":
            temporary = Path(tempfile.mkdtemp(prefix=".load-", dir=parent))
            try:
                shutil.rmtree(temporary)
                shutil.copytree(source, temporary, symlinks=False)
                if digest_path(temporary) != expected or digest_path(source) != expected:
                    raise ArtifactError(f"artifact changed while materializing: {source}")
                os.replace(temporary, target)
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary)
        else:
            raise ArtifactError(f"unsupported artifact kind: {artifact.kind}")
        directory_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return target

    def resolve(self, artifact: Artifact) -> Path:
        target = (self.root / artifact.path).resolve(strict=True)
        try:
            target.relative_to(self.root.resolve(strict=True))
        except ValueError as exc:
            raise ArtifactError("stored artifact path escapes the store") from exc
        return target
