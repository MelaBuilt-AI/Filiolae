#!/usr/bin/env python3
"""S2 Monitor A: strict Filiolae/Python complete loopback mirror."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from filiolae.transparency import (
    consistency_proof,
    merkle_root,
    parse_receipt_transparency_leaf,
    verify_checkpoint,
    verify_consistency_proof,
)

MAX_LEAF = 64 * 1024
STATE_SCHEMA = "filiolae.transparency-s2-monitor-state.v1"
REPORT_SCHEMA = "filiolae.transparency-s2-monitor-report.v1"


class MonitorFailure(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):  # noqa: ANN001
        raise MonitorFailure("redirect refused")


class LoopbackFetcher:
    def __init__(self, base_url: str):
        parsed = urllib.parse.urlsplit(base_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or parsed.port is None
        ):
            raise MonitorFailure("base URL must be literal IPv4 loopback HTTP")
        self.base = f"http://127.0.0.1:{parsed.port}"
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def get(self, path: str, limit: int) -> bytes:
        if not path.startswith("/") or ".." in path:
            raise MonitorFailure("unsafe resource path")
        request = urllib.request.Request(self.base + path, method="GET")
        try:
            with self.opener.open(request, timeout=5) as response:
                peer = response.fp.raw._sock.getpeername()  # noqa: SLF001
                if peer[0] != "127.0.0.1":
                    raise MonitorFailure("response peer is not IPv4 loopback")
                data = response.read(limit + 1)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise FileNotFoundError(path) from error
            raise MonitorFailure(f"resource returned status {error.code}") from error
        except (OSError, urllib.error.URLError) as error:
            raise MonitorFailure("resource fetch failed") from error
        if len(data) > limit:
            raise MonitorFailure("resource exceeds bound")
        return data


def _fmt_n(value: int) -> str:
    groups = [f"{value % 1000:03d}"]
    value //= 1000
    while value:
        groups.append(f"x{value % 1000:03d}")
        value //= 1000
    return "/".join(reversed(groups))


def _entry_path(index: int, partial: int) -> str:
    suffix = f".p/{partial}" if partial else ""
    return f"/tile/entries/{_fmt_n(index)}{suffix}"


def _bundle_ranges(tree_size: int):
    for bundle_index in range((tree_size + 255) // 256):
        count = min(256, tree_size - bundle_index * 256)
        yield bundle_index, 0 if count == 256 else count


def _parse_bundle(raw: bytes) -> list[bytes]:
    entries: list[bytes] = []
    offset = 0
    while offset < len(raw):
        if offset + 2 > len(raw):
            raise MonitorFailure("entry resource is truncated or malformed")
        size = int.from_bytes(raw[offset : offset + 2], "big")
        offset += 2
        if size > MAX_LEAF or offset + size > len(raw):
            raise MonitorFailure("entry resource is truncated or malformed")
        entries.append(raw[offset : offset + size])
        offset += size
    return entries


def _strict_verifier(path: Path) -> tuple[str, Ed25519PublicKey]:
    text = path.read_text().strip()
    try:
        name, identifier, encoded = text.split("+", 2)
        material = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as error:
        raise MonitorFailure("invalid synthetic checkpoint verifier") from error
    if (
        name != "filiolae.invalid/synthetic-s2/v1"
        or len(identifier) != 8
        or len(material) != 33
        or material[0] != 1
    ):
        raise MonitorFailure("invalid synthetic checkpoint verifier")
    return name, Ed25519PublicKey.from_public_bytes(material[1:])


def _write_json(path: Path, value: object, mode: int = 0o600) -> None:
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        os.unlink(temporary)
        raise


def _load_prior(path: Path) -> dict[str, object]:
    if not path.exists():
        return {
            "schema": STATE_SCHEMA,
            "tree_size": 0,
            "root_hex": hashlib.sha256(b"").hexdigest(),
            "checkpoint_b64": "",
            "leaves_b64": [],
            "resources": {},
        }
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise MonitorFailure("prior monitor state is invalid") from error
    if value.get("schema") != STATE_SCHEMA:
        raise MonitorFailure("prior monitor state is invalid")
    return value


def execute(args: argparse.Namespace) -> dict[str, object]:
    mirror = args.mirror.absolute()
    if mirror.is_symlink() or not mirror.is_dir() or mirror.stat().st_mode & 0o777 != 0o700:
        raise MonitorFailure("mirror root must be an existing mode-0700 directory")
    trust = json.loads(args.trust.read_bytes())
    if trust != {
        "schema": "filiolae.transparency-s2-trust.v1",
        "signer_public_key_b64": "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=",
        "run_id_prefix": "synthetic-s2-",
    }:
        raise MonitorFailure("unapproved synthetic trust fixture")
    origin, public_key = _strict_verifier(args.verifier)
    fetcher = LoopbackFetcher(args.base_url)
    checkpoint_raw = fetcher.get("/checkpoint", 65536)
    checkpoint = verify_checkpoint(checkpoint_raw, origin, public_key)
    if checkpoint.tree_size != args.expected_size:
        raise MonitorFailure(
            f"checkpoint size {checkpoint.tree_size} does not equal expected {args.expected_size}"
        )

    state_path = mirror / "state.json"
    prior = _load_prior(state_path)
    prior_resources = dict(prior["resources"])
    for path, digest in prior_resources.items():
        raw = fetcher.get(path, 256 * (MAX_LEAF + 2))
        actual = hashlib.sha256(raw).hexdigest()
        if actual != digest:
            conflict_dir = mirror / "conflicts"
            conflict_dir.mkdir(mode=0o700, exist_ok=True)
            (conflict_dir / f"{actual}.bin").write_bytes(raw)
            os.chmod(conflict_dir / f"{actual}.bin", 0o600)
            raise MonitorFailure("previously immutable resource changed")

    leaves: list[bytes] = []
    resources = dict(prior_resources)
    current_resource_bytes: dict[str, bytes] = {}
    for index, partial in _bundle_ranges(checkpoint.tree_size):
        path = _entry_path(index, partial)
        try:
            raw = fetcher.get(path, 256 * (MAX_LEAF + 2))
        except FileNotFoundError:
            if not partial:
                raise MonitorFailure("entry resource fetch failed") from None
            path = _entry_path(index, 0)
            raw = fetcher.get(path, 256 * (MAX_LEAF + 2))
        digest = hashlib.sha256(raw).hexdigest()
        if path in resources and resources[path] != digest:
            raise MonitorFailure("current immutable resource changed")
        resources[path] = digest
        current_resource_bytes[path] = raw
        leaves.extend(_parse_bundle(raw))
    if len(leaves) != checkpoint.tree_size:
        raise MonitorFailure("complete mirror entry count mismatch")
    for leaf in leaves:
        parsed = parse_receipt_transparency_leaf(leaf)
        if not parsed.receipt.run_id.startswith("synthetic-s2-"):
            raise MonitorFailure("entry leaf is not synthetic S2 material")
        raw_key = parsed.signer_public_key.public_bytes_raw()
        if base64.b64encode(raw_key).decode() != trust["signer_public_key_b64"]:
            raise MonitorFailure("entry leaf signer is not the synthetic fixture")
    root = merkle_root(leaves)
    if root != checkpoint.root_hash:
        raise MonitorFailure("complete mirror root differs from checkpoint")

    old_size = prior["tree_size"]
    old_leaves = [base64.b64decode(item, validate=True) for item in prior["leaves_b64"]]
    if old_size > checkpoint.tree_size or leaves[: len(old_leaves)] != old_leaves:
        raise MonitorFailure("checkpoint rollback or complete-mirror prefix change detected")
    proof = consistency_proof(leaves, old_size) if old_size else ()
    if old_size and not verify_consistency_proof(
        old_size,
        checkpoint.tree_size,
        bytes.fromhex(prior["root_hex"]),
        root,
        proof,
    ):
        raise MonitorFailure("append-only consistency verification failed")

    resource_dir = mirror / "resources"
    resource_dir.mkdir(mode=0o700, exist_ok=True)
    for path, digest in resources.items():
        raw = current_resource_bytes.get(path)
        if raw is None:
            raw = fetcher.get(path, 256 * (MAX_LEAF + 2))
        if hashlib.sha256(raw).hexdigest() != digest:
            raise MonitorFailure("resource changed before atomic state commit")
        target = resource_dir / f"{digest}.bin"
        target.write_bytes(raw)
        os.chmod(target, 0o600)
    leaf_dir = mirror / "leaves"
    leaf_dir.mkdir(mode=0o700, exist_ok=True)
    for index, leaf in enumerate(leaves):
        target = leaf_dir / f"{index:020d}.leaf"
        target.write_bytes(leaf)
        os.chmod(target, 0o600)
    new_state = {
        "schema": STATE_SCHEMA,
        "tree_size": checkpoint.tree_size,
        "root_hex": root.hex(),
        "checkpoint_b64": base64.b64encode(checkpoint_raw).decode(),
        "leaves_b64": [base64.b64encode(leaf).decode() for leaf in leaves],
        "resources": resources,
    }
    _write_json(state_path, new_state)
    return {
        "schema": REPORT_SCHEMA,
        "monitor": "filiolae-python",
        "status": "healthy",
        "tree_size": checkpoint.tree_size,
        "root_hex": root.hex(),
        "consistency_proof_hex": [item.hex() for item in proof],
        "resources": resources,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--mirror", required=True, type=Path)
    parser.add_argument("--verifier", required=True, type=Path)
    parser.add_argument("--trust", required=True, type=Path)
    parser.add_argument("--expected-size", required=True, type=int)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    report: dict[str, object] = {
        "schema": REPORT_SCHEMA,
        "monitor": "filiolae-python",
        "status": "suspect",
    }
    try:
        if args.expected_size < 1:
            raise MonitorFailure("expected size must be positive")
        report = execute(args)
    except Exception as error:  # deliberate monitor fail-closed boundary
        report["reason"] = str(error) if isinstance(error, MonitorFailure) else "monitor internal failure"
        _write_json(args.report, report)
        print(report["reason"], file=sys.stderr)
        return 2
    _write_json(args.report, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
