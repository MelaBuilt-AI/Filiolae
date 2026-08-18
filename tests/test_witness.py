from __future__ import annotations

import os
import socket
import threading
import time
from contextlib import suppress
from pathlib import Path

import pytest

from filiolae.anchor import (
    UNIX_WITNESS_ANCHOR_KIND,
    AnchorError,
    AnchorStore,
    generate_keypair,
    load_private_key,
    load_public_key,
    public_key_id,
    verify_anchor_store,
)
from filiolae.canonical import canonical_json
from filiolae.enrollment import EnrollmentError, WitnessEnrollment
from filiolae.gate import PromotionGate
from filiolae.ledger import Ledger, LedgerError, provision_ledger_lock
from filiolae.witness import REQUEST_SCHEMA, UnixAnchorWitnessServer, UnixSocketHeadAnchor

from .helpers import governed_run


def _ledger_and_keys(tmp_path: Path):
    private = tmp_path / "keys" / "private.pem"
    public = tmp_path / "keys" / "public.pem"
    key_id = generate_keypair(private, public)
    lock_path = tmp_path / "locks" / "ledger.lock"
    provision_ledger_lock(lock_path, mode=0o600)
    ledger_path = tmp_path / "run" / "ledger.jsonl"
    planned = WitnessEnrollment(
        run_id="witness-run",
        genesis_charter_sha256="a" * 64,
        signer_key_id=public_key_id(load_public_key(public)),
        ledger_path=str(ledger_path.absolute()),
    )
    ledger = Ledger.create(
        ledger_path,
        artifact_root=tmp_path / "run",
        lock_path=lock_path,
        require_existing_lock=True,
        run_id="witness-run",
        charter_sha256="a" * 64,
        metadata={
            "head_anchors_required": True,
            "anchor_kind": UNIX_WITNESS_ANCHOR_KIND,
            "anchor_signer_key_id": key_id,
            "witness_enrollment_sha256": planned.sha256,
        },
    )
    return ledger, lock_path, private, public


def _enrollment(tmp_path: Path, ledger: Ledger, private: Path):
    del tmp_path  # Protocol tests use the already precommitted genesis tuple directly.
    genesis = ledger.records()[0]
    return WitnessEnrollment(
        run_id=genesis.run_id,
        genesis_charter_sha256=genesis.data["charter_sha256"],
        signer_key_id=public_key_id(load_private_key(private).public_key()),
        ledger_path=str(ledger.path.absolute()),
    )


def _start_server(
    tmp_path: Path,
    ledger: Ledger,
    private: Path,
    *,
    allowed_uid: int | None = None,
    server_class=UnixAnchorWitnessServer,
    enrollment=None,
):
    socket_dir = tmp_path / "socket"
    socket_dir.mkdir(parents=True, mode=0o700)
    socket_path = socket_dir / "witness.sock"
    authoritative = AnchorStore(tmp_path / "authoritative")
    server = server_class(
        socket_path,
        ledger,
        authoritative,
        load_private_key(private),
        enrollment or _enrollment(tmp_path / "authoritative", ledger, private),
        allowed_uid=os.getuid() if allowed_uid is None else allowed_uid,
        connection_timeout=1.0,
    )
    stop = threading.Event()
    errors: list[BaseException] = []

    def serve() -> None:
        try:
            server.serve(stop)
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    deadline = time.monotonic() + 2
    while not socket_path.exists() and not errors and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not errors
    assert socket_path.exists()
    return socket_path, authoritative, stop, thread, errors


def _stop(stop: threading.Event, thread: threading.Thread, errors: list[BaseException]) -> None:
    stop.set()
    thread.join(2)
    assert not thread.is_alive()
    assert not errors


def test_witness_signs_actual_heads_and_catches_up_empty_mirror(tmp_path: Path) -> None:
    ledger, _, private, public = _ledger_and_keys(tmp_path)
    socket_path, authoritative, stop, thread, errors = _start_server(tmp_path, ledger, private)
    try:
        first_mirror = AnchorStore(tmp_path / "mirror-one")
        client = UnixSocketHeadAnchor(socket_path, first_mirror, load_public_key(public))
        genesis = ledger.records()[-1]
        receipt0 = client.acknowledge(
            ledger,
            expected_seq=genesis.seq,
            expected_head=genesis.hash,
        )
        ledger.append("test.observed", actor="service:test", data={"n": 1})
        head = ledger.records()[-1]
        receipt1 = client.acknowledge(ledger, expected_seq=head.seq, expected_head=head.hash)
        assert receipt1.anchor_seq == 1
        assert receipt1.previous_receipt_sha256 == receipt0.receipt_sha256()

        second_mirror = AnchorStore(tmp_path / "mirror-two")
        recovered = UnixSocketHeadAnchor(
            socket_path,
            second_mirror,
            load_public_key(public),
        ).acknowledge(ledger, expected_seq=head.seq, expected_head=head.hash)
        assert recovered.receipt_sha256() == receipt1.receipt_sha256()
        for store in (authoritative, first_mirror, second_mirror):
            report = verify_anchor_store(
                ledger,
                store,
                load_public_key(public),
                expected_anchor_kind=UNIX_WITNESS_ANCHOR_KIND,
            )
            assert report.ok and len(report.receipts) == 2
    finally:
        _stop(stop, thread, errors)


def test_witness_rejects_wrong_peer_uid_without_a_receipt(tmp_path: Path) -> None:
    ledger, _, private, public = _ledger_and_keys(tmp_path)
    socket_path, authoritative, stop, thread, errors = _start_server(
        tmp_path,
        ledger,
        private,
        allowed_uid=os.getuid() + 1,
    )
    try:
        head = ledger.records()[-1]
        client = UnixSocketHeadAnchor(socket_path, AnchorStore(tmp_path / "mirror"), load_public_key(public))
        with pytest.raises(AnchorError, match="rejected|transport failed"):
            client.acknowledge(ledger, expected_seq=head.seq, expected_head=head.hash)
        assert not authoritative.receipts_dir.exists() or list(authoritative.receipts_dir.iterdir()) == []
    finally:
        _stop(stop, thread, errors)


def test_witness_rejects_a_noncurrent_claim_without_signing(tmp_path: Path) -> None:
    ledger, _, private, public = _ledger_and_keys(tmp_path)
    socket_path, authoritative, stop, thread, errors = _start_server(tmp_path, ledger, private)
    try:
        head = ledger.records()[-1]
        client = UnixSocketHeadAnchor(socket_path, AnchorStore(tmp_path / "mirror"), load_public_key(public))
        with pytest.raises(AnchorError, match="rejected"):
            client.acknowledge(ledger, expected_seq=head.seq, expected_head="f" * 64)
        assert not authoritative.receipts_dir.exists() or list(authoritative.receipts_dir.iterdir()) == []
    finally:
        _stop(stop, thread, errors)


def test_wrong_client_public_key_cannot_import_witness_receipt(tmp_path: Path) -> None:
    ledger, _, private, _ = _ledger_and_keys(tmp_path)
    wrong_private = tmp_path / "wrong-private.pem"
    wrong_public = tmp_path / "wrong-public.pem"
    generate_keypair(wrong_private, wrong_public)
    socket_path, authoritative, stop, thread, errors = _start_server(tmp_path, ledger, private)
    mirror = AnchorStore(tmp_path / "mirror")
    try:
        head = ledger.records()[-1]
        client = UnixSocketHeadAnchor(socket_path, mirror, load_public_key(wrong_public))
        with pytest.raises(AnchorError, match="genesis anchor policy|signer key"):
            client.acknowledge(ledger, expected_seq=head.seq, expected_head=head.hash)
        assert len(list(authoritative.receipts_dir.iterdir())) == 1
        assert list(mirror.receipts_dir.iterdir()) == []
    finally:
        _stop(stop, thread, errors)


def test_client_holds_no_ledger_lock_while_waiting_for_witness(tmp_path: Path) -> None:
    ledger, _, private, public = _ledger_and_keys(tmp_path)
    entered = threading.Event()
    release = threading.Event()

    class DelayedServer(UnixAnchorWitnessServer):
        def _handle(self, connection: socket.socket) -> None:
            entered.set()
            assert release.wait(2)
            super()._handle(connection)

    socket_path, authoritative, stop, thread, errors = _start_server(
        tmp_path,
        ledger,
        private,
        server_class=DelayedServer,
    )
    client_error: list[BaseException] = []
    old_head = ledger.records()[-1]

    def request() -> None:
        try:
            UnixSocketHeadAnchor(
                socket_path,
                AnchorStore(tmp_path / "mirror"),
                load_public_key(public),
            ).acknowledge(ledger, expected_seq=old_head.seq, expected_head=old_head.hash)
        except BaseException as exc:
            client_error.append(exc)

    requester = threading.Thread(target=request)
    requester.start()
    try:
        assert entered.wait(1)
        started = time.monotonic()
        ledger.append("test.race", actor="service:test", data={})
        assert time.monotonic() - started < 0.5
        release.set()
        requester.join(2)
        assert client_error and isinstance(client_error[0], AnchorError)
        assert not authoritative.receipts_dir.exists() or list(authoritative.receipts_dir.iterdir()) == []
    finally:
        release.set()
        requester.join(2)
        _stop(stop, thread, errors)


def test_witness_receipt_is_independently_verified_by_gate(tmp_path: Path, charter) -> None:
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    key_id = generate_keypair(private, public)
    governed_root = tmp_path / "governed"
    planned = WitnessEnrollment(
        run_id="test-run",
        genesis_charter_sha256=charter.sha256,
        signer_key_id=key_id,
        ledger_path=str((governed_root / "control" / "ledger.jsonl").absolute()),
    )
    policy = {
        "head_anchors_required": True,
        "anchor_kind": UNIX_WITNESS_ANCHOR_KIND,
        "anchor_signer_key_id": key_id,
        "witness_enrollment_sha256": planned.sha256,
    }
    ledger, _, files, request, freezer, _ = governed_run(governed_root, charter, metadata=policy)
    socket_path, _, stop, thread, errors = _start_server(tmp_path / "service", ledger, private)
    mirror = AnchorStore(tmp_path / "gate-mirror")
    client = UnixSocketHeadAnchor(socket_path, mirror, load_public_key(public))
    try:
        head = ledger.records()[-1]
        client.acknowledge(ledger, expected_seq=head.seq, expected_head=head.hash)
        gate = PromotionGate(
            ledger,
            charter,
            freezer,
            head_anchor=client,
            anchor_store=mirror,
            anchor_public_key=load_public_key(public),
            require_head_anchor=True,
        )
        decision = gate.authorize(
            request,
            current_policy_version=0,
            pending_weights_path=files["weights"],
        )
        assert decision.allowed
        assert not freezer.state().frozen
    finally:
        _stop(stop, thread, errors)


def test_fixed_lock_must_be_preprovisioned_and_regular(tmp_path: Path) -> None:
    missing = Ledger(
        tmp_path / "ledger.jsonl",
        artifact_root=tmp_path,
        lock_path=tmp_path / "missing.lock",
        require_existing_lock=True,
    )
    with pytest.raises(FileNotFoundError), missing.locked():
        pass
    directory = tmp_path / "directory-lock"
    directory.mkdir()
    invalid = Ledger(
        tmp_path / "ledger.jsonl",
        artifact_root=tmp_path,
        lock_path=directory,
        require_existing_lock=True,
    )
    with pytest.raises((LedgerError, OSError), match="regular file|directory"), invalid.locked():
        pass


def test_server_refuses_an_existing_socket_path(tmp_path: Path) -> None:
    ledger, _, private, _ = _ledger_and_keys(tmp_path)
    socket_dir = tmp_path / "socket"
    socket_dir.mkdir(parents=True, mode=0o700)
    socket_path = socket_dir / "witness.sock"
    socket_path.write_text("do not replace")
    server = UnixAnchorWitnessServer(
        socket_path,
        ledger,
        AnchorStore(tmp_path / "anchors"),
        load_private_key(private),
        _enrollment(tmp_path / "anchors", ledger, private),
        allowed_uid=os.getuid(),
    )
    with pytest.raises(AnchorError, match="already exists"):
        server.serve(threading.Event())
    assert socket_path.read_text() == "do not replace"


def test_concurrent_identical_witness_requests_converge_on_one_receipt(tmp_path: Path) -> None:
    ledger, _, private, public = _ledger_and_keys(tmp_path)
    socket_path, authoritative, stop, thread, errors = _start_server(tmp_path, ledger, private)
    head = ledger.records()[-1]
    barrier = threading.Barrier(3)
    results: list[str] = []
    failures: list[BaseException] = []

    def request(index: int) -> None:
        try:
            client = UnixSocketHeadAnchor(
                socket_path,
                AnchorStore(tmp_path / f"mirror-{index}"),
                load_public_key(public),
            )
            barrier.wait()
            receipt = client.acknowledge(
                ledger,
                expected_seq=head.seq,
                expected_head=head.hash,
            )
            results.append(receipt.receipt_sha256())
        except BaseException as exc:
            failures.append(exc)

    requesters = [threading.Thread(target=request, args=(index,)) for index in range(2)]
    for requester in requesters:
        requester.start()
    barrier.wait()
    for requester in requesters:
        requester.join(2)
    try:
        assert not failures
        assert len(set(results)) == 1
        assert len(list(authoritative.receipts_dir.iterdir())) == 1
    finally:
        _stop(stop, thread, errors)


def test_witness_protocol_rejects_cross_enrollment_digest(tmp_path: Path) -> None:
    import json

    ledger, _, private, _ = _ledger_and_keys(tmp_path)
    socket_path, authoritative, stop, thread, errors = _start_server(tmp_path, ledger, private)
    head = ledger.records()[-1]
    request = {
        "schema": REQUEST_SCHEMA,
        "enrollment_sha256": "f" * 64,
        "run_id": head.run_id,
        "ledger_seq": head.seq,
        "ledger_head_sha256": head.hash,
    }
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(str(socket_path))
            connection.sendall(canonical_json(request) + b"\n")
            connection.shutdown(socket.SHUT_WR)
            response = b""
            while chunk := connection.recv(4096):
                response += chunk
        value = json.loads(response)
        assert value["ok"] is False
        assert value["enrollment_sha256"] is None
        assert not authoritative.receipts_dir.exists()
    finally:
        _stop(stop, thread, errors)


def test_witness_protocol_rejects_noncanonical_duplicate_fields(tmp_path: Path) -> None:
    import json

    ledger, _, private, _ = _ledger_and_keys(tmp_path)
    socket_path, authoritative, stop, thread, errors = _start_server(tmp_path, ledger, private)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(str(socket_path))
            connection.sendall(b'{"schema":"x","schema":"y"}\n')
            connection.shutdown(socket.SHUT_WR)
            response = b""
            while chunk := connection.recv(4096):
                response += chunk
        value = json.loads(response)
        assert value["ok"] is False and value["receipts"] == []
        assert not authoritative.receipts_dir.exists()
    finally:
        _stop(stop, thread, errors)


def test_witness_kind_is_pinned_by_genesis_and_verifier(tmp_path: Path) -> None:
    from filiolae.anchor import anchor_ledger_head

    ledger, _, private, public = _ledger_and_keys(tmp_path)
    store = AnchorStore(tmp_path / "anchors")
    with pytest.raises(AnchorError, match="genesis policy|different anchor kind"):
        anchor_ledger_head(ledger, store, load_private_key(private))
    assert (
        verify_anchor_store(
            ledger,
            store,
            load_public_key(public),
            expected_anchor_kind=UNIX_WITNESS_ANCHOR_KIND,
        ).ok
        is False
    )


def test_server_shutdown_does_not_unlink_a_replacement_path(tmp_path: Path) -> None:
    ledger, _, private, _ = _ledger_and_keys(tmp_path)
    socket_path, _, stop, thread, errors = _start_server(tmp_path, ledger, private)
    socket_path.unlink()
    socket_path.write_text("replacement")
    _stop(stop, thread, errors)
    assert socket_path.read_text() == "replacement"


def test_witness_refuses_a_symlinked_allowlisted_ledger(tmp_path: Path) -> None:
    ledger, _, private, _ = _ledger_and_keys(tmp_path)
    enrollment = _enrollment(tmp_path / "authoritative", ledger, private)
    real = ledger.path.with_name("moved-ledger.jsonl")
    ledger.path.rename(real)
    ledger.path.symlink_to(real)
    with pytest.raises(EnrollmentError, match="symlink component rejected"):
        _start_server(tmp_path, ledger, private, enrollment=enrollment)


def test_wrong_uid_is_rejected_before_reading_a_request(tmp_path: Path) -> None:
    ledger, _, private, _ = _ledger_and_keys(tmp_path)
    socket_path, authoritative, stop, thread, errors = _start_server(
        tmp_path,
        ledger,
        private,
        allowed_uid=os.getuid() + 1,
    )
    try:
        started = time.monotonic()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(0.5)
            connection.connect(str(socket_path))
            with suppress(ConnectionResetError):
                connection.recv(4096)
        assert time.monotonic() - started < 0.5
        assert not authoritative.receipts_dir.exists()
    finally:
        _stop(stop, thread, errors)


def test_bind_failure_propagates_instead_of_returning_success(tmp_path: Path) -> None:
    ledger, _, private, _ = _ledger_and_keys(tmp_path)
    socket_dir = tmp_path / "unwritable"
    socket_dir.mkdir(mode=0o500)
    server = UnixAnchorWitnessServer(
        socket_dir / "witness.sock",
        ledger,
        AnchorStore(tmp_path / "anchors"),
        load_private_key(private),
        _enrollment(tmp_path / "anchors", ledger, private),
        allowed_uid=os.getuid(),
    )
    try:
        with pytest.raises(PermissionError):
            server.serve(threading.Event())
    finally:
        socket_dir.chmod(0o700)
