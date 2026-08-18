#!/usr/bin/env python3
"""Generate or check the exact Priority 6 CPU evaluator code bundle."""

from __future__ import annotations

import argparse
from pathlib import Path

from filiolae.canonical import canonical_json
from filiolae.paired_eval import evaluator_bundle_body


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).parents[1] / "examples" / "candidate-eval" / "cpu-evaluator-bundle-v1.json",
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    raw = canonical_json(evaluator_bundle_body()) + b"\n"
    if args.check:
        try:
            return 0 if args.output.read_bytes() == raw else 1
        except OSError:
            return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
