"""Controller adapter for a separately operated one-shot external evaluator."""

from __future__ import annotations

import time
from pathlib import Path

from .anchor import load_public_key
from .paired_eval import (
    PairedEvalProtocolError,
    _absolute_without_symlinks,
    _digest,
    _fsync_directory,
    _write_file,
    load_terminal_receipt,
    request_bytes,
    request_sha256,
    verify_terminal_evidence,
)
from .shadow_eval import CandidateEvalReceipt, CandidateEvalRequest


class ExternalTerminalShadowEvaluator:
    """Production controller seam for a separately operated one-shot evaluator.

    The controller publishes only a digest-bound request and waits for an evaluator-owned
    terminal store. It has no evaluator private key, source path, configuration path, fixture,
    or worker command. Candidate staging into the evaluator's immutable content store and the
    separately credentialed evaluator service lifecycle are deployment responsibilities.
    """

    def __init__(
        self,
        *,
        request_root: Path,
        terminal_root: Path,
        public_key_path: Path,
        suite_path: Path,
        timeout_seconds: float = 30,
        poll_interval_seconds: float = 0.25,
    ) -> None:
        if (
            timeout_seconds <= 0
            or timeout_seconds > 3600
            or poll_interval_seconds <= 0
            or poll_interval_seconds > min(timeout_seconds, 5)
        ):
            raise PairedEvalProtocolError("external terminal evaluator timing is invalid")
        self.request_root = _absolute_without_symlinks(Path(request_root), allow_missing_leaf=True)
        self.terminal_root = _absolute_without_symlinks(Path(terminal_root), allow_missing_leaf=True)
        self.public_key_path = _absolute_without_symlinks(Path(public_key_path))
        self.suite_path = _absolute_without_symlinks(Path(suite_path))
        self.timeout_seconds = timeout_seconds
        self.poll_interval_seconds = poll_interval_seconds

    def _publish_request(self, request: CandidateEvalRequest) -> Path:
        digest = request_sha256(request)
        self.request_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.request_root / f"{digest}.json"
        raw = request_bytes(request)
        if path.exists() or path.is_symlink():
            if path.is_symlink() or not path.is_file() or path.read_bytes() != raw:
                raise PairedEvalProtocolError(
                    "existing external evaluator request contradicts the request digest"
                )
        else:
            _write_file(path, raw, mode=0o444)
            _fsync_directory(self.request_root)
        return path

    def terminal_evidence_path(self, request: CandidateEvalRequest) -> Path:
        """Return the exact verified terminal directory for evidence retention."""
        verify_terminal_evidence(
            self.terminal_root,
            request,
            load_public_key(self.public_key_path),
            self.suite_path,
        )
        digest = request_sha256(request)
        return self.terminal_root / digest[:2] / digest

    def terminal_evidence_root(self, request: CandidateEvalRequest) -> Path:
        """Return a verified one-request root suitable for content-addressed staging."""
        terminal = self.terminal_evidence_path(request)
        digest = request_sha256(request)
        expected = {
            Path(digest[:2]),
            Path(digest[:2]) / digest,
            Path(digest[:2]) / digest / "evidence.json",
            Path(digest[:2]) / digest / "receipt.json",
        }
        actual = set()
        for path in self.terminal_root.rglob("*"):
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise PairedEvalProtocolError("external terminal evidence inventory is unsafe")
            actual.add(path.relative_to(self.terminal_root))
        if actual != expected or terminal != self.terminal_root / digest[:2] / digest:
            raise PairedEvalProtocolError("external terminal store is not an exact one-request package")
        return self.terminal_root

    def evaluate(self, request: CandidateEvalRequest, candidate_path: Path) -> CandidateEvalReceipt:
        if _digest(candidate_path) != request.candidate_sha256:
            raise PairedEvalProtocolError(
                "controller candidate bytes contradict the external evaluator request"
            )
        self._publish_request(request)
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            if load_terminal_receipt(self.terminal_root, request) is not None:
                return verify_terminal_evidence(
                    self.terminal_root,
                    request,
                    load_public_key(self.public_key_path),
                    self.suite_path,
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PairedEvalProtocolError("external evaluator deadline expired without a terminal result")
            time.sleep(min(self.poll_interval_seconds, remaining))
