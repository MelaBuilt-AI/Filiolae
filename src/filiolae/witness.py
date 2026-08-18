"""Unix-domain-socket client/server for a separately credentialed head witness.

The transport is local and availability-only: authority comes from signed receipts and a pinned
public key. Independent rollback resistance additionally requires separate credentials and retained
witness storage.
"""

from __future__ import annotations

import json
import os
import re
import socket
import stat
import struct
import threading
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .anchor import (
    UNIX_WITNESS_ANCHOR_KIND,
    AnchorError,
    AnchorReceipt,
    AnchorStore,
    anchor_ledger_head,
    import_anchor_receipt,
    public_key_id,
    verify_anchor_store,
)
from .canonical import canonical_json
from .enrollment import EnrollmentError, WitnessEnrollment
from .ledger import Ledger

REQUEST_SCHEMA = "filiolae.anchor-witness-request.v2"
RESPONSE_SCHEMA = "filiolae.anchor-witness-response.v2"
_REQUEST_FIELDS = {
    "schema",
    "enrollment_sha256",
    "run_id",
    "ledger_seq",
    "ledger_head_sha256",
}
_RESPONSE_FIELDS = {"schema", "ok", "enrollment_sha256", "receipts", "error"}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 16 * 1024 * 1024


def _receive_one_message(
    connection: socket.socket,
    maximum: int,
    *,
    total_timeout: float,
) -> bytes:
    chunks: list[bytes] = []
    size = 0
    deadline = time.monotonic() + total_timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("witness protocol message deadline expired")
        connection.settimeout(remaining)
        chunk = connection.recv(min(65536, maximum + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > maximum:
            raise AnchorError("witness protocol message exceeds the size limit")
    raw = b"".join(chunks)
    if not raw.endswith(b"\n") or b"\n" in raw[:-1] or len(raw) == 1:
        raise AnchorError("witness protocol requires exactly one newline-terminated message")
    return raw[:-1]


def _strict_object(raw: bytes, fields: set[str]) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AnchorError("witness protocol message is invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != fields:
        raise AnchorError("witness protocol message has invalid fields")
    if canonical_json(value) != raw:
        raise AnchorError("witness protocol message is not canonical JSON")
    return value


def _send_message(connection: socket.socket, value: dict[str, Any]) -> None:
    connection.sendall(canonical_json(value) + b"\n")


class UnixSocketHeadAnchor:
    """HeadAnchor client that imports signed witness receipts into a local verified mirror."""

    anchor_kind = UNIX_WITNESS_ANCHOR_KIND

    def __init__(
        self,
        socket_path: str | Path,
        mirror_store: AnchorStore,
        public_key: Ed25519PublicKey,
        *,
        timeout: float = 10.0,
    ) -> None:
        if timeout <= 0:
            raise ValueError("witness timeout must be positive")
        self.socket_path = Path(socket_path).absolute()
        self.store = mirror_store
        self.public_key = public_key
        self.timeout = timeout

    @property
    def signer_key_id(self) -> str:
        return public_key_id(self.public_key)

    def acknowledge(
        self,
        ledger: Ledger,
        *,
        expected_seq: int,
        expected_head: str,
    ) -> AnchorReceipt:
        report = ledger.audit(verify_artifacts=False)
        if not report.ok:
            raise AnchorError(report.summary())
        genesis = report.records[0]
        run_id = genesis.run_id
        metadata = genesis.data.get("metadata", {})
        enrollment_sha256 = metadata.get("witness_enrollment_sha256") if isinstance(metadata, dict) else None
        if not isinstance(enrollment_sha256, str) or _HEX64.fullmatch(enrollment_sha256) is None:
            raise AnchorError("Ledger genesis lacks an explicit witness enrollment digest")
        request = {
            "schema": REQUEST_SCHEMA,
            "enrollment_sha256": enrollment_sha256,
            "run_id": run_id,
            "ledger_seq": expected_seq,
            "ledger_head_sha256": expected_head,
        }
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout)
                connection.connect(str(self.socket_path))
                _send_message(connection, request)
                connection.shutdown(socket.SHUT_WR)
                raw = _receive_one_message(
                    connection,
                    MAX_RESPONSE_BYTES,
                    total_timeout=self.timeout,
                )
        except OSError as exc:
            raise AnchorError("witness transport failed") from exc
        response = _strict_object(raw, _RESPONSE_FIELDS)
        if response["schema"] != RESPONSE_SCHEMA or not isinstance(response["ok"], bool):
            raise AnchorError("witness response schema/status is invalid")
        if not response["ok"]:
            if (
                response["enrollment_sha256"] is not None
                or response["receipts"] != []
                or not isinstance(response["error"], str)
            ):
                raise AnchorError("witness error response is invalid")
            raise AnchorError(f"witness rejected checkpoint: {response['error']}")
        if (
            response["enrollment_sha256"] != enrollment_sha256
            or response["error"] is not None
            or not isinstance(response["receipts"], list)
        ):
            raise AnchorError("witness success response enrollment/status is invalid")
        receipt_values = response["receipts"]
        if not receipt_values:
            raise AnchorError("witness returned no signed receipts")
        receipts: list[AnchorReceipt] = []
        for value in receipt_values:
            if not isinstance(value, dict):
                raise AnchorError("witness returned an invalid receipt")
            receipts.append(AnchorReceipt.from_bytes(canonical_json(value) + b"\n"))
        if receipts[-1].anchor_kind != self.anchor_kind:
            raise AnchorError("witness returned the wrong anchor kind")
        for index, receipt in enumerate(receipts):
            final = index == len(receipts) - 1
            import_anchor_receipt(
                ledger,
                self.store,
                self.public_key,
                receipt,
                expected_anchor_kind=self.anchor_kind,
                expected_seq=expected_seq if final else None,
                expected_head=expected_head if final else None,
            )
        return receipts[-1]


class UnixAnchorWitnessServer:
    """Sequential witness service for one allowlisted Ledger and one allowed peer UID."""

    def __init__(
        self,
        socket_path: str | Path,
        ledger: Ledger,
        store: AnchorStore,
        private_key: Ed25519PrivateKey,
        enrollment: WitnessEnrollment,
        *,
        allowed_uid: int,
        connection_timeout: float = 10.0,
        socket_mode: int = 0o600,
        socket_gid: int | None = None,
    ) -> None:
        if allowed_uid < 0:
            raise ValueError("allowed UID must be nonnegative")
        if connection_timeout <= 0:
            raise ValueError("connection timeout must be positive")
        if socket_mode not in {0o600, 0o660}:
            raise ValueError("witness socket mode must be 0600 or 0660")
        if socket_gid is not None and socket_gid < 0:
            raise ValueError("witness socket GID must be nonnegative")
        self.socket_path = Path(socket_path).absolute()
        self.ledger = ledger
        self.store = store
        self.private_key = private_key
        self.enrollment = enrollment
        self.enrollment.validate_configuration(ledger, private_key.public_key())
        self.allowed_uid = allowed_uid
        self.connection_timeout = connection_timeout
        self.socket_mode = socket_mode
        self.socket_gid = socket_gid
        self._ledger_identity: tuple[int, int] | None = None

    def _validate_socket_parent(self) -> None:
        parent = self.socket_path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or parent.is_symlink():
            raise AnchorError("witness socket parent must be a real directory")
        if info.st_mode & 0o022:
            raise AnchorError("witness socket parent must not be group/other writable")
        try:
            self.socket_path.lstat()
        except FileNotFoundError:
            return
        raise AnchorError("witness socket path already exists; refusing replacement")

    def _peer_uid(self, connection: socket.socket) -> int:
        if not hasattr(socket, "SO_PEERCRED"):
            raise AnchorError("SO_PEERCRED is unavailable on this platform")
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _, uid, _ = struct.unpack("3i", raw)
        return uid

    def _pin_ledger_identity(self) -> tuple[int, int]:
        try:
            info = self.ledger.path.lstat()
        except FileNotFoundError as exc:
            raise AnchorError("allowlisted Ledger does not exist") from exc
        if not stat.S_ISREG(info.st_mode) or self.ledger.path.is_symlink():
            raise AnchorError("allowlisted Ledger must be a real regular file")
        self.enrollment.validate_ledger(self.ledger)
        identity = (info.st_dev, info.st_ino)
        if self._ledger_identity is None:
            self._ledger_identity = identity
        elif self._ledger_identity != identity:
            raise AnchorError("allowlisted Ledger inode changed")
        return identity

    def _handle(self, connection: socket.socket) -> None:
        connection.settimeout(self.connection_timeout)
        if self._peer_uid(connection) != self.allowed_uid:
            raise AnchorError("peer UID is not authorized")
        raw = _receive_one_message(
            connection,
            MAX_REQUEST_BYTES,
            total_timeout=self.connection_timeout,
        )
        request = _strict_object(raw, _REQUEST_FIELDS)
        if (
            request["schema"] != REQUEST_SCHEMA
            or request["enrollment_sha256"] != self.enrollment.sha256
            or not isinstance(request["run_id"], str)
            or not request["run_id"]
            or not isinstance(request["ledger_seq"], int)
            or isinstance(request["ledger_seq"], bool)
            or request["ledger_seq"] < 0
            or not isinstance(request["ledger_head_sha256"], str)
            or _HEX64.fullmatch(request["ledger_head_sha256"]) is None
        ):
            raise AnchorError("witness request values are invalid")
        ledger_identity = self._pin_ledger_identity()
        ledger_report = self.ledger.audit(verify_artifacts=False)
        if not ledger_report.ok:
            raise AnchorError("allowlisted Ledger is invalid")
        if ledger_report.records[0].run_id != request["run_id"]:
            raise AnchorError("request run ID differs from the allowlisted Ledger")
        anchor_ledger_head(
            self.ledger,
            self.store,
            self.private_key,
            expected_seq=request["ledger_seq"],
            expected_head=request["ledger_head_sha256"],
            anchor_kind=UNIX_WITNESS_ANCHOR_KIND,
        )
        verified = verify_anchor_store(
            self.ledger,
            self.store,
            self.private_key.public_key(),
            require_current=True,
            expected_anchor_kind=UNIX_WITNESS_ANCHOR_KIND,
        )
        if not verified.ok:
            raise AnchorError(verified.summary())
        if self._pin_ledger_identity() != ledger_identity:
            raise AnchorError("allowlisted Ledger inode changed while signing")
        _send_message(
            connection,
            {
                "schema": RESPONSE_SCHEMA,
                "ok": True,
                "enrollment_sha256": self.enrollment.sha256,
                "receipts": [receipt.to_dict() for receipt in verified.receipts],
                "error": None,
            },
        )

    def serve(self, stop_event: threading.Event) -> None:
        self._validate_socket_parent()
        # Pin an already-created Ledger before exposing the socket. A not-yet-created Ledger
        # is accepted only because the reviewed enrollment precommits its exact genesis tuple.
        try:
            self._pin_ledger_identity()
        except AnchorError as exc:
            if "does not exist" not in str(exc):
                raise
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        bound_identity: tuple[int, int] | None = None
        try:
            listener.bind(str(self.socket_path))
            os.chmod(self.socket_path, self.socket_mode, follow_symlinks=False)
            if self.socket_gid is not None:
                os.chown(self.socket_path, -1, self.socket_gid, follow_symlinks=False)
            info = self.socket_path.lstat()
            bound_identity = (info.st_dev, info.st_ino)
            listener.listen(16)
            listener.settimeout(0.1)
            while not stop_event.is_set():
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    try:
                        self._handle(connection)
                    except (AnchorError, EnrollmentError, OSError, TimeoutError, ValueError):
                        with suppress(OSError):
                            _send_message(
                                connection,
                                {
                                    "schema": RESPONSE_SCHEMA,
                                    "ok": False,
                                    "enrollment_sha256": None,
                                    "receipts": [],
                                    "error": "request rejected",
                                },
                            )
        finally:
            listener.close()
            try:
                info = self.socket_path.lstat()
            except FileNotFoundError:
                info = None
            if (
                info is not None
                and bound_identity == (info.st_dev, info.st_ino)
                and stat.S_ISSOCK(info.st_mode)
            ):
                self.socket_path.unlink()
