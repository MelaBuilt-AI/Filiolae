"""CLI worker for the one-shot CPU paired-evaluator protocol rehearsal."""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

from .paired_eval import run_cpu_fixture_evaluator


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--evaluator-bundle", required=True, type=Path)
    parser.add_argument("--suite", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--source-manifest", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--allow-request-file", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--terminal-root", required=True, type=Path)
    parser.add_argument("--simulate", choices=("lost-response", "crash-before-terminal", "hang"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.simulate == "crash-before-terminal":
        os._exit(70)
    if args.simulate == "hang":
        time.sleep(3600)
    run_cpu_fixture_evaluator(
        request_path=args.request,
        source_path=args.source,
        candidate_path=args.candidate,
        evaluator_bundle=args.evaluator_bundle,
        suite_path=args.suite,
        config_path=args.config,
        source_manifest_path=args.source_manifest,
        private_key_path=args.private_key,
        allowed_request_path=args.allow_request_file,
        fixture_path=args.fixture,
        terminal_root=args.terminal_root,
    )
    if args.simulate == "lost-response":
        os._exit(75)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
