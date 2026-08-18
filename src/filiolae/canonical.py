"""Canonical serialization and hashing helpers."""

from __future__ import annotations

import hashlib
import json
from typing import Any


class CanonicalValueError(ValueError):
    pass


def _validate(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        raise CanonicalValueError(f"floats are not allowed in canonical values: {path}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalValueError(f"object key is not a string: {path}")
            _validate(item, f"{path}.{key}")
        return
    raise CanonicalValueError(f"unsupported canonical value at {path}: {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Return version-stable UTF-8 JSON bytes suitable for hashing."""
    _validate(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_json(value: Any, *, domain: bytes = b"") -> str:
    return hashlib.sha256(domain + canonical_json(value)).hexdigest()
