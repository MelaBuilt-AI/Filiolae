#!/usr/bin/env python3
"""Pinned Gate D SFT and complete visible/readiness evaluation runtime.

This file is transferred by digest to a fresh development GPU. Dependencies and
model metadata are staged before the caller disables outbound inference access.
The answer is produced only by model tokens; host code parses and scores it.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import random
import re
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SYSTEM_PROMPT = "Reverse the text character-by-character. Put your answer in <reversed_text> tags."
TAG = re.compile(r"<reversed_text>(.*?)</reversed_text>", re.DOTALL)
CASE_SCHEMA = "filiolae.priority6-v2-reversal-case.v1"


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def tree_digest(directory: Path) -> tuple[str, int]:
    entries: list[dict[str, Any]] = []
    total = 0
    for path in sorted(directory.rglob("*"), key=lambda item: item.relative_to(directory).as_posix()):
        relative = path.relative_to(directory).as_posix()
        if path.is_symlink():
            raise RuntimeError(f"symlink forbidden in tree: {relative}")
        if path.is_dir():
            entries.append({"kind": "directory", "path": relative})
        elif path.is_file():
            size = path.stat().st_size
            total += size
            entries.append({"kind": "file", "path": relative, "sha256": sha256_file(path), "size": size})
        else:
            raise RuntimeError(f"special object forbidden in tree: {relative}")
    body = {"entries": entries, "kind": "directory"}
    return hashlib.sha256(canonical_json(body)).hexdigest(), total


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("wb") as handle:
        handle.write(canonical_json(value) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def load_cases(path: Path, expected_count: int | None = None) -> list[dict[str, Any]]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    if expected_count is not None and len(rows) != expected_count:
        raise RuntimeError(f"{path} has {len(rows)} cases, expected {expected_count}")
    if not rows:
        raise RuntimeError(f"{path} is empty")
    ids: list[str] = []
    prompts: set[str] = set()
    for row in rows:
        if row.get("schema") != CASE_SCHEMA:
            raise RuntimeError(f"unexpected case schema in {path}")
        case_id = row.get("case_id")
        prompt = row.get("prompt")
        answer = row.get("answer")
        if not all(isinstance(item, str) for item in (case_id, prompt, answer)):
            raise RuntimeError(f"malformed case in {path}")
        if answer != prompt[::-1]:
            raise RuntimeError(f"incorrect label in {path}: {case_id}")
        if prompt in prompts:
            raise RuntimeError(f"duplicate prompt in {path}")
        prompts.add(prompt)
        ids.append(case_id)
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        raise RuntimeError(f"case IDs must be unique and sorted in {path}")
    return rows


def verify_manifest(root: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != "filiolae.priority6-v2-gate-d-execution.v1":
        raise RuntimeError("unexpected execution manifest schema")
    files = manifest.get("staged_files")
    if not isinstance(files, dict):
        raise RuntimeError("execution manifest lacks staged_files")
    observed: dict[str, str] = {}
    for relative, expected in files.items():
        if not isinstance(relative, str) or relative.startswith("/") or ".." in Path(relative).parts:
            raise RuntimeError("unsafe manifest path")
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"staged regular file absent: {relative}")
        observed[relative] = sha256_file(path)
        if observed[relative] != expected:
            raise RuntimeError(f"staged file digest mismatch: {relative}")
    for directory_name in ("source", "model-meta"):
        directory = root / directory_name
        expected_paths = {name for name in files if name.startswith(f"{directory_name}/")}
        actual_paths: set[str] = set()
        for path in directory.rglob("*"):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink() or (not path.is_dir() and not path.is_file()):
                raise RuntimeError(f"unsafe staged tree object: {relative}")
            if path.is_file():
                actual_paths.add(relative)
        if actual_paths != expected_paths:
            raise RuntimeError(f"unexpected files in staged {directory_name} tree")
    return {"manifest_sha256": sha256_file(manifest_path), "observed": observed}


def load_runtime(source: Path, metadata: Path) -> tuple[Any, Any]:
    import torch
    from safetensors.torch import load_file
    from transformers import AutoConfig, AutoModelForCausalLM, AutoTokenizer

    config = AutoConfig.from_pretrained(metadata, local_files_only=True, trust_remote_code=False)
    config.use_cache = False
    tokenizer = AutoTokenizer.from_pretrained(metadata, local_files_only=True, trust_remote_code=False)
    tokenizer.padding_side = "right"
    model = AutoModelForCausalLM.from_config(config, trust_remote_code=False, torch_dtype=torch.float32)
    state = load_file(str(source / "model.safetensors"), device="cpu")
    missing, unexpected = model.load_state_dict(state, strict=True)
    if missing or unexpected:
        raise RuntimeError(f"state mismatch: missing={missing}, unexpected={unexpected}")
    del state
    return model, tokenizer


def encoded_training_examples(tokenizer: Any, rows: list[dict[str, Any]]) -> tuple[list[Any], int]:
    import torch

    examples: list[Any] = []
    maximum = 0
    for row in rows:
        prompt_messages = [
            {"content": SYSTEM_PROMPT, "role": "system"},
            {"content": row["prompt"], "role": "user"},
        ]
        full_messages = [
            *prompt_messages,
            {
                "content": f"<reversed_text>{row['answer']}</reversed_text>",
                "role": "assistant",
            },
        ]
        prefix = tokenizer.apply_chat_template(
            prompt_messages, tokenize=True, add_generation_prompt=True, enable_thinking=False
        )
        full = tokenizer.apply_chat_template(
            full_messages, tokenize=True, add_generation_prompt=False, enable_thinking=False
        )
        if full[: len(prefix)] != prefix:
            raise RuntimeError("chat-template prefix mismatch")
        labels = [-100] * len(prefix) + full[len(prefix) :]
        if len(full) > 256:
            raise RuntimeError(f"tokenized training row exceeds 256 tokens: {row['case_id']}")
        maximum = max(maximum, len(full))
        examples.append((torch.tensor(full, dtype=torch.long), torch.tensor(labels, dtype=torch.long)))
    return examples, maximum


@dataclass
class Collator:
    pad_token_id: int

    def __call__(self, examples: list[Any]) -> dict[str, Any]:
        import torch

        width = max(item[0].numel() for item in examples)
        width = (width + 7) // 8 * 8
        input_ids = torch.full((len(examples), width), self.pad_token_id, dtype=torch.long)
        attention_mask = torch.zeros((len(examples), width), dtype=torch.long)
        labels = torch.full((len(examples), width), -100, dtype=torch.long)
        for index, (tokens, token_labels) in enumerate(examples):
            length = tokens.numel()
            input_ids[index, :length] = tokens
            attention_mask[index, :length] = 1
            labels[index, :length] = token_labels
        return {"attention_mask": attention_mask, "input_ids": input_ids, "labels": labels}


def evaluate_model(
    model: Any,
    tokenizer: Any,
    rows: list[dict[str, Any]],
    output: Path,
    *,
    batch_size: int,
) -> dict[str, Any]:
    import torch

    model.eval()
    tokenizer.padding_side = "left"
    results: list[dict[str, Any]] = []
    started = utc_now()
    with torch.inference_mode():
        for offset in range(0, len(rows), batch_size):
            batch = rows[offset : offset + batch_size]
            rendered = [
                tokenizer.apply_chat_template(
                    [
                        {"content": SYSTEM_PROMPT, "role": "system"},
                        {"content": row["prompt"], "role": "user"},
                    ],
                    tokenize=False,
                    add_generation_prompt=True,
                    enable_thinking=False,
                )
                for row in batch
            ]
            encoded = tokenizer(rendered, padding=True, return_tensors="pt")
            input_width = encoded.input_ids.shape[1]
            encoded = {key: value.to("cuda:0") for key, value in encoded.items()}
            generated = model.generate(
                **encoded,
                do_sample=False,
                max_new_tokens=96,
                pad_token_id=tokenizer.eos_token_id,
                use_cache=True,
            )
            completions = tokenizer.batch_decode(generated[:, input_width:], skip_special_tokens=True)
            for row, completion in zip(batch, completions, strict=True):
                match = TAG.search(completion)
                parsed = match.group(1).strip() if match else ""
                results.append(
                    {
                        "case_id": row["case_id"],
                        "completion": completion,
                        "exact": parsed == row["answer"],
                        "parsed": parsed,
                    }
                )
    write_json(output, results)
    exact_matches = sum(bool(row["exact"]) for row in results)
    return {
        "case_count": len(results),
        "complete": len(results) == len(rows),
        "exact_matches": exact_matches,
        "finished_at": utc_now(),
        "outputs_sha256": sha256_file(output),
        "quality_bps": 10_000 * exact_matches // len(results),
        "started_at": started,
    }


def save_model_tree(model: Any, directory: Path, provenance: dict[str, Any]) -> dict[str, Any]:
    import torch
    from safetensors.torch import save_file

    if directory.exists():
        raise RuntimeError(f"refusing to overwrite model directory: {directory}")
    directory.mkdir(parents=True)
    state = {
        name: tensor.detach().to(dtype=torch.bfloat16, device="cpu").contiguous()
        for name, tensor in model.state_dict().items()
    }
    save_file(state, str(directory / "model.safetensors"))
    del state
    provenance = {**provenance, "model_safetensors_sha256": sha256_file(directory / "model.safetensors")}
    write_json(directory / "STABLE", provenance)
    os.chmod(directory / "model.safetensors", 0o444)
    os.chmod(directory / "STABLE", 0o444)
    digest, size = tree_digest(directory)
    return {"size": size, "tree_sha256": digest}


def train_one_epoch(
    model: Any,
    examples: list[Any],
    collator: Collator,
    optimizer: Any,
    *,
    batch_size: int,
    accumulation_steps: int,
    epoch_seed: int,
    learning_rate: float,
) -> dict[str, Any]:
    import torch
    from torch.utils.data import DataLoader

    generator = torch.Generator()
    generator.manual_seed(epoch_seed)
    loader = DataLoader(
        examples,
        batch_size=batch_size,
        shuffle=True,
        collate_fn=collator,
        generator=generator,
        num_workers=0,
        pin_memory=True,
    )
    model.train()
    optimizer.zero_grad(set_to_none=True)
    losses: list[float] = []
    started = time.monotonic()
    total_batches = len(loader)
    for batch_index, batch in enumerate(loader):
        batch = {key: value.to("cuda:0", non_blocking=True) for key, value in batch.items()}
        with torch.autocast(device_type="cuda", dtype=torch.bfloat16):
            output = model(**batch)
            loss = output.loss / accumulation_steps
        loss.backward()
        losses.append(float(loss.detach().cpu()) * accumulation_steps)
        should_step = (batch_index + 1) % accumulation_steps == 0 or batch_index + 1 == total_batches
        if should_step:
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            optimizer.zero_grad(set_to_none=True)
        if batch_index % 100 == 0 or batch_index + 1 == total_batches:
            print(
                json.dumps(
                    {
                        "batch": batch_index + 1,
                        "epoch_seed": epoch_seed,
                        "loss": losses[-1],
                        "total_batches": total_batches,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
    return {
        "batch_count": total_batches,
        "duration_seconds": int(time.monotonic() - started),
        "learning_rate": learning_rate,
        "mean_loss": sum(losses) / len(losses),
    }


def command_train(args: argparse.Namespace) -> int:
    import torch

    root = args.root.resolve()
    output = args.output.resolve()
    if output.exists():
        raise RuntimeError(f"refusing to overwrite output root: {output}")
    output.mkdir(parents=True)
    validation = verify_manifest(root, args.manifest.resolve())
    train_rows = load_cases(root / "training.jsonl", 50_000)
    visible_rows = load_cases(root / "visible-development.jsonl", 512)
    if {row["prompt"] for row in train_rows} & {row["prompt"] for row in visible_rows}:
        raise RuntimeError("training and visible development prompts overlap")
    os.environ.update({"HF_DATASETS_OFFLINE": "1", "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"})
    random.seed(args.seed)
    torch.manual_seed(args.seed)
    torch.cuda.manual_seed_all(args.seed)
    torch.backends.cuda.matmul.allow_tf32 = True
    model, tokenizer = load_runtime(root / "source", root / "model-meta")
    if tokenizer.eos_token_id is None:
        raise RuntimeError("tokenizer lacks EOS token")
    examples, maximum_tokens = encoded_training_examples(tokenizer, train_rows)
    if len(examples) != 50_000:
        raise RuntimeError("training example count changed during encoding")
    model.to("cuda:0")
    source_eval = evaluate_model(
        model,
        tokenizer,
        visible_rows,
        output / "source-visible-outputs.json",
        batch_size=args.eval_batch_size,
    )
    optimizer = torch.optim.AdamW(
        model.parameters(), lr=args.learning_rate, betas=(0.9, 0.95), weight_decay=0.1, fused=True
    )
    run = {
        "batch_size": args.batch_size,
        "candidate_selection_rule": (
            "freeze-round-1-if-visible-exact-at-least-486-else-run-round-2; round-2-must-be-at-least-461"
        ),
        "gradient_accumulation_steps": args.accumulation_steps,
        "learning_rate": args.learning_rate,
        "manifest_validation": validation,
        "maximum_rounds": 2,
        "maximum_training_tokens_per_row": maximum_tokens,
        "schema": "filiolae.priority6-v2-gate-d-training-run.v1",
        "seed": args.seed,
        "source_visible": source_eval,
        "started_at": utc_now(),
        "training_case_count": len(train_rows),
        "visible_case_count": len(visible_rows),
    }
    rounds: list[dict[str, Any]] = []
    selected_round: int | None = None
    for round_number in (1, 2):
        training = train_one_epoch(
            model,
            examples,
            collator=Collator(tokenizer.pad_token_id),
            optimizer=optimizer,
            batch_size=args.batch_size,
            accumulation_steps=args.accumulation_steps,
            epoch_seed=args.seed + round_number,
            learning_rate=args.learning_rate,
        )
        visible = evaluate_model(
            model,
            tokenizer,
            visible_rows,
            output / f"round-{round_number}-visible-outputs.json",
            batch_size=args.eval_batch_size,
        )
        round_record = {"round": round_number, "training": training, "visible": visible}
        rounds.append(round_record)
        write_json(output / "run-progress.json", {**run, "rounds": rounds})
        if round_number == 1 and visible["exact_matches"] >= 486:
            selected_round = 1
            break
        if round_number == 1:
            round_record["unselected_model"] = save_model_tree(
                model,
                output / "round-1-unselected-candidate",
                {
                    "round": 1,
                    "schema": "filiolae.priority6-v2-candidate-provenance.v1",
                    "selected": False,
                    "source_tree_sha256": args.source_tree_sha256,
                },
            )
        if round_number == 2 and visible["exact_matches"] >= 461:
            selected_round = 2
    run["rounds"] = rounds
    run["finished_at"] = utc_now()
    if selected_round is None:
        run["status"] = "visible-development-threshold-failed"
        write_json(output / "run-terminal.json", run)
        return 2
    candidate = save_model_tree(
        model,
        output / "frozen-candidate",
        {
            "round": selected_round,
            "schema": "filiolae.priority6-v2-candidate-provenance.v1",
            "selected": True,
            "source_tree_sha256": args.source_tree_sha256,
        },
    )
    run["candidate"] = candidate
    run["selected_round"] = selected_round
    run["status"] = "candidate-frozen-before-readiness"
    write_json(output / "candidate-freeze.json", run)
    write_json(output / "run-terminal.json", run)
    return 0


def command_evaluate(args: argparse.Namespace) -> int:
    import torch

    cases = load_cases(args.suite.resolve(), args.expected_count)
    os.environ.update({"HF_DATASETS_OFFLINE": "1", "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"})
    source_model, tokenizer = load_runtime(args.source.resolve(), args.metadata.resolve())
    source_model.to("cuda:0")
    source = evaluate_model(
        source_model,
        tokenizer,
        cases,
        args.output.resolve() / "source-outputs.json",
        batch_size=args.eval_batch_size,
    )
    del source_model
    torch.cuda.empty_cache()
    candidate_model, candidate_tokenizer = load_runtime(args.candidate.resolve(), args.metadata.resolve())
    candidate_model.to("cuda:0")
    candidate = evaluate_model(
        candidate_model,
        candidate_tokenizer,
        cases,
        args.output.resolve() / "candidate-outputs.json",
        batch_size=args.eval_batch_size,
    )
    regression = source["quality_bps"] - candidate["quality_bps"]
    summary = {
        "candidate": candidate,
        "candidate_tree_sha256": tree_digest(args.candidate.resolve())[0],
        "complete": source["complete"] and candidate["complete"],
        "regression_bps": regression,
        "schema": "filiolae.priority6-v2-paired-model-evaluation.v1",
        "source": source,
        "source_tree_sha256": tree_digest(args.source.resolve())[0],
        "suite_sha256": sha256_file(args.suite.resolve()),
    }
    write_json(args.output.resolve() / "evaluation-summary.json", summary)
    print(json.dumps(summary, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    train = sub.add_parser("train-visible")
    train.add_argument("--root", type=Path, required=True)
    train.add_argument("--manifest", type=Path, required=True)
    train.add_argument("--output", type=Path, required=True)
    train.add_argument("--source-tree-sha256", required=True)
    train.add_argument("--seed", type=int, default=684021)
    train.add_argument("--learning-rate", type=float, default=5e-5)
    train.add_argument("--batch-size", type=int, default=32)
    train.add_argument("--accumulation-steps", type=int, default=2)
    train.add_argument("--eval-batch-size", type=int, default=64)
    train.set_defaults(func=command_train)
    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("--source", type=Path, required=True)
    evaluate.add_argument("--candidate", type=Path, required=True)
    evaluate.add_argument("--metadata", type=Path, required=True)
    evaluate.add_argument("--suite", type=Path, required=True)
    evaluate.add_argument("--expected-count", type=int, required=True)
    evaluate.add_argument("--output", type=Path, required=True)
    evaluate.add_argument("--eval-batch-size", type=int, default=64)
    evaluate.set_defaults(func=command_evaluate)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except Exception as exc:
        with contextlib.suppress(Exception):
            print(f"fatal: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
