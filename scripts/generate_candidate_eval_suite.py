#!/usr/bin/env python3
"""Generate the frozen Priority 6 reverse-text paired-evaluation suite."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

SEED = b"filiolae-priority-6-reverse-text-held-out-v1"
CASE_COUNT = 128
ADJECTIVES = (
    "amber",
    "bronze",
    "cobalt",
    "coral",
    "crimson",
    "golden",
    "indigo",
    "ivory",
    "jade",
    "lilac",
    "marble",
    "ochre",
    "pearl",
    "scarlet",
    "silver",
    "violet",
)
NOUNS = (
    "badger",
    "comet",
    "falcon",
    "garden",
    "harbor",
    "lantern",
    "otter",
    "planet",
    "quartz",
    "robot",
    "sailor",
    "temple",
    "valley",
    "willow",
    "yarrow",
    "zephyr",
)
VERBS = (
    "balances",
    "carries",
    "counts",
    "draws",
    "guards",
    "maps",
    "measures",
    "packs",
    "records",
    "sketches",
    "sorts",
    "stacks",
    "tracks",
    "visits",
    "weighs",
    "writes",
)
OBJECTS = (
    "arches",
    "beacons",
    "bridges",
    "clocks",
    "crates",
    "feathers",
    "islands",
    "keys",
    "letters",
    "mirrors",
    "rivers",
    "signals",
    "stones",
    "towers",
    "trails",
    "windows",
)
PLACES = (
    "before dawn",
    "beside the western gate",
    "during the quiet watch",
    "near the old station",
    "on the northern quay",
    "under a clear sky",
    "within the lower hall",
    "without delay",
)
NAMES = ("Ari", "Bea", "Cato", "Dara", "Enzo", "Faye", "Gita", "Hugo")


def _indexes(case_id: int, count: int) -> list[int]:
    raw = hashlib.shake_256(SEED + b"\0" + str(case_id).encode("ascii")).digest(count)
    return list(raw)


def build_cases() -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []
    for case_id in range(CASE_COUNT):
        values = _indexes(case_id, 8)
        adjective = ADJECTIVES[values[0] % len(ADJECTIVES)]
        noun = NOUNS[values[1] % len(NOUNS)]
        verb = VERBS[values[2] % len(VERBS)]
        obj = OBJECTS[values[3] % len(OBJECTS)]
        place = PLACES[values[4] % len(PLACES)]
        name = NAMES[values[5] % len(NAMES)]
        number = 10 + ((values[6] * 256 + values[7]) % 90)
        alternate = 10 + ((number + 36) % 90)
        prefix = f"Case {case_id:03d}"
        template = case_id % 4
        if template == 0:
            prompt = f"{prefix}: The {adjective} {noun} {verb} {number} {obj} {place}."
        elif template == 1:
            prompt = f"{prefix}: Did the {adjective} {noun} {verb} {number} {obj} {place}?"
        elif template == 2:
            prompt = f'{prefix}: "The {adjective} {noun} {verb} {number} {obj}," wrote {name}.'
        else:
            prompt = f"{prefix}: Pack {number} {adjective} {obj} (not {alternate}) {place}!"
        cases.append(
            {
                "answer": prompt[::-1],
                "case_id": f"reverse-text-held-out-v1-{case_id:03d}",
                "prompt": prompt,
                "schema": "filiolae.reverse-text-eval-case.v1",
            }
        )
    return cases


def render() -> bytes:
    return b"".join(
        json.dumps(case, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
        for case in build_cases()
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).parents[1] / "examples" / "candidate-eval" / "reverse-text-held-out-v1.jsonl",
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render()
    if args.check:
        try:
            actual = args.output.read_bytes()
        except OSError:
            return 1
        return 0 if actual == expected else 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
