#!/usr/bin/env python3
"""Deterministic, domain-bounded data generation for Priority 6 v2.

Public training/development seeds may be passed on the command line. Custodied
readiness/final seeds must be supplied through ``--seed-env`` so they are not
placed in argv, logs, or repository bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any

SCHEMA = "filiolae.priority6-v2-reversal-case.v1"
GENERATOR_SCHEMA = "filiolae.priority6-v2-data-generator.v1"
ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789"
MIN_SYMBOLS = 6
MAX_SYMBOLS = 20
SEPARATOR = " "
PROMPT_RE = re.compile(r"[a-z2-9](?: [a-z2-9]){5,19}\Z")


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def derive_prompt(seed: bytes, candidate_index: int) -> str:
    """Derive one prompt using SHAKE-256; independent of Python PRNG versions."""
    stream = hashlib.shake_256(
        b"filiolae-priority6-v2-case-v1\0" + seed + candidate_index.to_bytes(16, "big")
    ).digest(1 + MAX_SYMBOLS)
    length = MIN_SYMBOLS + stream[0] % (MAX_SYMBOLS - MIN_SYMBOLS + 1)
    symbols = [ALPHABET[value % len(ALPHABET)] for value in stream[1 : length + 1]]
    return SEPARATOR.join(symbols)


def generate_cases(*, seed: bytes, count: int, prefix: str, forbidden: set[str]) -> list[dict[str, Any]]:
    if len(seed) < 32:
        raise ValueError("seed must contain at least 256 bits")
    if not 1 <= count <= 100_000:
        raise ValueError("count must be between 1 and 100000")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", prefix):
        raise ValueError("invalid case prefix")
    rows: list[dict[str, Any]] = []
    selected = set(forbidden)
    candidate_index = 0
    while len(rows) < count:
        prompt = derive_prompt(seed, candidate_index)
        candidate_index += 1
        prompt_digest = sha256_bytes(prompt.encode())
        if prompt_digest in selected:
            continue
        if not PROMPT_RE.fullmatch(prompt):
            raise AssertionError("generator produced an out-of-domain prompt")
        selected.add(prompt_digest)
        rows.append(
            {
                "answer": prompt[::-1],
                "case_id": f"{prefix}-{len(rows):06d}",
                "prompt": prompt,
                "schema": SCHEMA,
            }
        )
    return rows


def inventory(rows: list[dict[str, Any]]) -> dict[str, Any]:
    digests = [sha256_bytes(row["prompt"].encode()) for row in rows]
    if len(set(digests)) != len(digests):
        raise ValueError("duplicate prompt digest")
    return {
        "case_count": len(rows),
        "prompt_hashes": digests,
        "prompt_inventory_root_sha256": sha256_bytes(canonical_json(digests)),
        "schema": "filiolae.priority6-v2-prompt-inventory.v1",
    }


def read_forbidden(paths: list[Path]) -> set[str]:
    values: set[str] = set()
    for path in paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("schema") != "filiolae.priority6-v2-prompt-inventory.v1":
            raise ValueError(f"unexpected inventory schema: {path}")
        hashes = data.get("prompt_hashes")
        if not isinstance(hashes, list) or not all(
            isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item) for item in hashes
        ):
            raise ValueError(f"invalid prompt hashes: {path}")
        values.update(hashes)
    return values


def write_atomic(path: Path, payload: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def validate_output_path(path: Path) -> Path:
    resolved = path.expanduser().resolve(strict=False)
    if resolved.exists() and (resolved.is_symlink() or not stat.S_ISREG(resolved.lstat().st_mode)):
        raise ValueError("output must be a regular file or absent")
    return resolved


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    seed_group = parser.add_mutually_exclusive_group(required=True)
    seed_group.add_argument("--seed-hex", help="public seed; forbidden for custodied suites")
    seed_group.add_argument("--seed-env", help="environment variable containing a secret hex seed")
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--forbid-inventory", action="append", type=Path, default=[])
    parser.add_argument("--output", type=Path, help="write canonical JSONL; omit for commitment-only")
    parser.add_argument("--inventory-output", type=Path)
    parser.add_argument("--summary-output", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.seed_env:
        raw_seed = os.environ.get(args.seed_env)
        if raw_seed is None:
            raise SystemExit(f"required seed environment variable is absent: {args.seed_env}")
    else:
        raw_seed = args.seed_hex
    try:
        seed = bytes.fromhex(raw_seed)
    except (TypeError, ValueError) as exc:
        raise SystemExit("seed must be hexadecimal") from exc
    forbidden = read_forbidden(args.forbid_inventory)
    rows = generate_cases(seed=seed, count=args.count, prefix=args.prefix, forbidden=forbidden)
    inv = inventory(rows)
    jsonl = b"".join(canonical_json(row) + b"\n" for row in rows)
    summary = {
        "alphabet": ALPHABET,
        "answer_rule": "unicode-code-point-reversal-of-exact-prompt",
        "case_count": len(rows),
        "forbidden_prompt_count": len(forbidden),
        "generator_schema": GENERATOR_SCHEMA,
        "jsonl_sha256": sha256_bytes(jsonl),
        "maximum_symbols": MAX_SYMBOLS,
        "minimum_symbols": MIN_SYMBOLS,
        "prompt_inventory_root_sha256": inv["prompt_inventory_root_sha256"],
        "prompt_regex": PROMPT_RE.pattern,
        "schema": "filiolae.priority6-v2-data-summary.v1",
        "seed_commitment_sha256": sha256_bytes(seed),
        "separator": SEPARATOR,
    }
    if args.output:
        write_atomic(validate_output_path(args.output), jsonl)
    if args.inventory_output:
        write_atomic(validate_output_path(args.inventory_output), canonical_json(inv) + b"\n")
    if args.summary_output:
        write_atomic(validate_output_path(args.summary_output), canonical_json(summary) + b"\n")
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
