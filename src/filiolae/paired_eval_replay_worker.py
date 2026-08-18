"""CLI worker for the bounded post-hoc completion-replay evaluator."""

from __future__ import annotations

import argparse
from pathlib import Path

from .paired_eval_replay import run_completion_replay_evaluator


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
    parser.add_argument("--replay", required=True, type=Path)
    parser.add_argument("--terminal-root", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    run_completion_replay_evaluator(
        request_path=args.request,
        source_path=args.source,
        candidate_path=args.candidate,
        evaluator_bundle=args.evaluator_bundle,
        suite_path=args.suite,
        config_path=args.config,
        source_manifest_path=args.source_manifest,
        private_key_path=args.private_key,
        allowed_request_path=args.allow_request_file,
        replay_path=args.replay,
        terminal_root=args.terminal_root,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
