from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
OPS = ROOT / "ops" / "two-gpu-smoke"
sys.path.insert(0, str(OPS))


common = importlib.import_module("common")
tamper = importlib.import_module("tamper_after_step1")
remote = importlib.import_module("remote_preflight")
runner = importlib.import_module("run_happy")
collector = importlib.import_module("collect_evidence")
tamper_runner = importlib.import_module("run_tamper")


def test_smoke_tools_compile_and_are_documented() -> None:
    expected = {
        "build_payload.py",
        "remote_preflight.py",
        "run_happy.py",
        "run_tamper.py",
        "tamper_after_step1.py",
        "collect_evidence.py",
    }
    assert expected <= {path.name for path in OPS.glob("*.py")}
    readme = (OPS / "README.md").read_text()
    assert "does **not** provision" in readme
    assert "setsid" in readme
    assert "not candidate-quality evidence" in readme
    bootstrap = (OPS / "bootstrap_remote.sh").read_text()
    assert "export PYTHONDONTWRITEBYTECODE=1" in bootstrap
    assert "python -B" in bootstrap
    for name in expected | {"common.py"}:
        compile((OPS / name).read_text(), str(OPS / name), "exec")


def test_prime_run_output_matches_pinned_host_layout(tmp_path: Path) -> None:
    assert common.prime_run_output(tmp_path / "campaign") == tmp_path / "campaign" / "run_default"


def test_manifest_verification_rejects_tamper(tmp_path: Path) -> None:
    payload = tmp_path / "payload"
    payload.mkdir()
    item = payload / "item.txt"
    item.write_text("original")
    manifest = {
        "schema": "filiolae.two-gpu-smoke-payload.v1",
        "files": {"item.txt": common.sha256_file(item)},
    }
    common.atomic_write_json(payload / "manifest.json", manifest)
    assert common.load_manifest(payload)["files"] == manifest["files"]
    item.write_text("changed")
    with pytest.raises(common.SmokeToolError, match="digest mismatch"):
        common.load_manifest(payload)


def test_payload_preserves_an_installable_manifest_bound_wheel_name(tmp_path: Path) -> None:
    payload = tmp_path / "payload"
    payload.mkdir()
    wheel = payload / "filiolae-0.1.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    manifest: dict[str, object] = {
        "filiolae_wheel": wheel.name,
        "files": {wheel.name: common.sha256_file(wheel)},
    }
    assert remote._payload_wheel(manifest, payload) == wheel
    manifest["filiolae_wheel"] = "filiolae.whl"
    with pytest.raises(common.SmokeToolError, match="invalid Filiolae wheel filename"):
        remote._payload_wheel(manifest, payload)
    manifest["filiolae_wheel"] = "../filiolae-0.1.0-py3-none-any.whl"
    with pytest.raises(common.SmokeToolError, match="invalid Filiolae wheel filename"):
        remote._payload_wheel(manifest, payload)


def test_frozen_bootstrap_includes_only_the_required_flash_attention_extra() -> None:
    assert remote.FROZEN_SYNC_ARGS == (
        "sync",
        "--frozen",
        "--package",
        "prime-rl",
        "--package",
        "reverse-text-v1",
        "--extra",
        "flash-attn",
        "--extra",
        "disagg",
        "--no-dev",
    )
    source = (OPS / "remote_preflight.py").read_text()
    assert "import filiolae, flash_attn, prime_rl, prime_rl.trainer.model, reverse_text_v1" in source


def test_run_id_and_absolute_symlink_checks(tmp_path: Path) -> None:
    assert common.validate_run_id("run-001") == "run-001"
    for unsafe in ("", ".hidden", "-option", "../escape", "spaces bad"):
        with pytest.raises(common.SmokeToolError):
            common.validate_run_id(unsafe)
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(common.SmokeToolError, match="symlink"):
        common.absolute_no_symlinks(alias)


def _tamper_fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    artifact_root = tmp_path / "artifacts"
    candidate = artifact_root / "sha256" / "trees" / "aa" / ("a" * 64)
    candidate.mkdir(parents=True)
    weights = candidate / "model.safetensors"
    weights.write_bytes(b"weights")
    (candidate / "STABLE").write_text("ready")
    ledger = tmp_path / "ledger.jsonl"
    records = [
        {"seq": 0, "event": "run.genesis", "data": {}, "artifacts": []},
        {
            "seq": 1,
            "event": "weights.published",
            "data": {"step": 1, "attempt_id": "a"},
            "artifacts": [
                {
                    "name": "candidate_weights",
                    "kind": "tree",
                    "path": candidate.relative_to(artifact_root).as_posix(),
                }
            ],
        },
        {"seq": 2, "event": "gate.approved", "data": {"step": 1}, "artifacts": []},
        {"seq": 3, "event": "policy.promoted", "data": {"step": 1}, "artifacts": []},
    ]
    ledger.write_text("".join(json.dumps(record) + "\n" for record in records))
    operator_log = tmp_path / "operator" / "tamper.json"
    operator_log.parent.mkdir()
    return ledger, artifact_root, weights, operator_log


def test_tamper_helper_targets_bound_step_one_candidate_and_refuses_replay(tmp_path: Path) -> None:
    ledger, artifact_root, weights, operator_log = _tamper_fixture(tmp_path)
    before = weights.read_bytes()
    args = argparse.Namespace(
        ledger=str(ledger),
        artifact_root=str(artifact_root),
        operator_log=str(operator_log),
        timeout_seconds=0.1,
        poll_seconds=0.01,
    )
    report = tamper.tamper(args)
    assert weights.read_bytes() != before
    assert report["ledger_modified"] is False
    assert report["target_relative_to_artifact_root"].endswith("model.safetensors")
    assert json.loads(operator_log.read_text())["sha256_before"] == report["sha256_before"]
    assert tamper_runner._validate_operator_log(operator_log, artifact_root) == report
    weights.write_bytes(b"changed-again")
    with pytest.raises(common.SmokeToolError, match="no longer matches"):
        tamper_runner._validate_operator_log(operator_log, artifact_root)
    with pytest.raises(common.SmokeToolError, match="replay"):
        tamper.tamper(args)


def test_tamper_helper_times_out_without_promotion(tmp_path: Path) -> None:
    ledger, artifact_root, _, operator_log = _tamper_fixture(tmp_path)
    records = [json.loads(line) for line in ledger.read_text().splitlines()]
    ledger.write_text("".join(json.dumps(record) + "\n" for record in records[:-1]))
    args = argparse.Namespace(
        ledger=str(ledger),
        artifact_root=str(artifact_root),
        operator_log=str(operator_log),
        timeout_seconds=0.01,
        poll_seconds=0.005,
    )
    with pytest.raises(common.SmokeToolError, match="timed out"):
        tamper.tamper(args)
    assert not operator_log.exists()


def test_source_manifest_allows_only_exact_pinned_build_hook_output(tmp_path: Path) -> None:
    prime_rl = tmp_path / "prime-rl"
    tracked = prime_rl / "tracked.txt"
    tracked.parent.mkdir()
    tracked.write_text("tracked")
    manifest = tmp_path / "source-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "filiolae.prime-rl-patched-source.v1",
                "prime_rl_commit": common.PRIME_RL_SHA,
                "verifiers_commit": common.VERIFIERS_SHA,
                "submodules": common.PRIME_SUBMODULES,
                "archive_policy": "tracked-regular-files-only; no symlinks or special nodes",
                "patched_files": sorted(common.PATCHED_PRIME_FILES),
                "files": {"tracked.txt": common.sha256_file(tracked)},
            }
        )
    )
    generated = prime_rl / "deps" / "renderers" / "renderers" / "_version.py"
    generated.parent.mkdir(parents=True)
    generated.write_text(
        """# file generated by vcs-versioning
# don't change, don't track in version control
from __future__ import annotations

__all__ = [
    "__version__",
    "__version_tuple__",
    "version",
    "version_tuple",
    "__commit_id__",
    "commit_id",
]

version: str
__version__: str
__version_tuple__: tuple[int | str, ...]
version_tuple: tuple[int | str, ...]
commit_id: str | None
__commit_id__: str | None

__version__ = version = '0.0.0'
__version_tuple__ = version_tuple = (0, 0, 0)

__commit_id__ = commit_id = None
"""
    )
    assert (
        common.sha256_file(generated)
        == common.BUILD_GENERATED_SOURCE_FILES["deps/renderers/renderers/_version.py"]
    )
    remote._validate_source_manifest(prime_rl, manifest)
    generated.write_text("unreviewed build output")
    with pytest.raises(common.SmokeToolError, match="build-generated source digest mismatch"):
        remote._validate_source_manifest(prime_rl, manifest)
    generated.unlink()
    unexpected = prime_rl / "unexpected.py"
    unexpected.write_text("unreviewed")
    with pytest.raises(common.SmokeToolError, match="unexpected files in patched source"):
        remote._validate_source_manifest(prime_rl, manifest)


def test_runtime_lineage_must_resolve_beneath_verified_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    prime_rl = tmp_path / "prime-rl"
    prime_origin = prime_rl / "src" / "prime_rl" / "orchestrator" / "orchestrator.py"
    reverse_origin = (
        prime_rl
        / "deps"
        / "verifiers"
        / "environments"
        / "reverse_text_v1"
        / "reverse_text_v1"
        / "__init__.py"
    )
    for path in (prime_origin, reverse_origin):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# pinned source\n")
    origins = {
        "prime_rl.orchestrator.orchestrator": str(prime_origin),
        "reverse_text_v1": str(reverse_origin),
    }
    monkeypatch.setattr(
        remote, "run_checked", lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(origins))
    )
    assert remote._validate_runtime_lineage(Path("/venv/python"), prime_rl) == origins
    outside = tmp_path / "outside.py"
    outside.write_text("# stale package\n")
    origins["prime_rl.orchestrator.orchestrator"] = str(outside)
    with pytest.raises(common.SmokeToolError, match="does not resolve"):
        remote._validate_runtime_lineage(Path("/venv/python"), prime_rl)


def test_remote_config_profile_validation(tmp_path: Path) -> None:
    config = tmp_path / "smoke.toml"
    config.write_text((ROOT / "examples" / "prime-rl" / "reverse-text-filesystem-smoke.toml").read_text())
    assert remote._validate_config(config)["max_steps"] == 2
    config.write_text(config.read_text().replace('type = "filesystem"', 'type = "nccl"'))
    with pytest.raises(common.SmokeToolError, match="filesystem"):
        remote._validate_config(config)


def test_remote_dry_run_reads_prime_rl_resolved_orchestrator_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    output_parent = tmp_path / "runs"
    output_parent.mkdir()
    config = tmp_path / "smoke.toml"
    config.write_text("test = true\n")
    charter = tmp_path / "charter.yaml"
    charter.write_text("test: true\n")
    hf_home = tmp_path / "hf"
    hf_home.mkdir()

    def fake_run(argv, **kwargs):
        del kwargs
        dry_output = Path(argv[argv.index("--output-dir") + 1])
        configs = dry_output / "configs"
        configs.mkdir(parents=True)
        (configs / "orchestrator.toml").write_text('[weight_broadcast]\ntype = "filesystem"\n')
        return SimpleNamespace(stdout="dry run complete")

    monkeypatch.setattr(remote, "run_checked", fake_run)
    report = remote._dry_run_config(
        "/venv/bin/filiolae-rl",
        config,
        output_parent,
        charter,
        Path("/venv/bin"),
        hf_home,
        30,
    )
    assert report["weight_broadcast_type"] == "filesystem"
    assert len(report["resolved_config_sha256"]) == 64


def test_runner_sanitizes_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SECRET_TOKEN", "do-not-forward")
    monkeypatch.setenv("PATH", "/bin")
    args = argparse.Namespace(
        payload_dir=str(tmp_path),
        anchor_private_key=str(tmp_path / "private.pem"),
        anchor_dir=str(tmp_path / "anchors"),
        hf_home=str(tmp_path / "hf"),
        torch_home=None,
        venv_dir=str(tmp_path / "venv"),
        prime_rl=str(tmp_path / "prime-rl"),
    )
    env = runner._child_env(args)
    assert "SECRET_TOKEN" not in env
    assert env["CUDA_VISIBLE_DEVICES"] == "0,1"
    assert env["HF_HUB_OFFLINE"] == "1"
    assert env["HF_DATASETS_OFFLINE"] == "1"
    assert env["UV_OFFLINE"] == "1"
    assert env["UV_CACHE_DIR"] == str(tmp_path / "hf" / "filiolae-uv-cache")
    assert env["XDG_CONFIG_HOME"] == str(tmp_path / "hf" / "filiolae-xdg-config")
    assert env["HOME"] == str(tmp_path / "hf" / "filiolae-harness-home")
    assert env["PATH"].split(":")[:2] == [str(tmp_path / "bin"), str(tmp_path / "venv" / "bin")]


def test_terminal_ledger_semantics(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    records = [
        {"event": "gate.approved", "data": {"attempt_id": "a", "step": 1}},
        {"event": "policy.promoted", "data": {"attempt_id": "a", "step": 1}},
        {"event": "gate.approved", "data": {"attempt_id": "b", "step": 2}},
        {"event": "policy.promoted", "data": {"attempt_id": "b", "step": 2}},
        {"event": "run.exited", "data": {"status": "success"}},
    ]
    ledger.write_text("".join(json.dumps(item) + "\n" for item in records))
    runner._validate_ledger(ledger)
    ledger.write_text("".join(json.dumps(item) + "\n" for item in records[:2] + records[-1:]))
    with pytest.raises(common.SmokeToolError, match="exactly steps"):
        runner._validate_ledger(ledger)
    records[3]["event"] = "weights.load_failed"
    ledger.write_text("".join(json.dumps(item) + "\n" for item in records))
    with pytest.raises(common.SmokeToolError, match="fail-closed events"):
        runner._validate_ledger(ledger)


def test_collector_binds_preflight_manifest_run_and_config(tmp_path: Path) -> None:
    output = (tmp_path / "run").absolute()
    anchors = (tmp_path / "anchors").absolute()
    config = (tmp_path / "smoke.toml").absolute()
    manifest_path = (tmp_path / "manifest.json").absolute()
    preflight_path = (tmp_path / "remote-preflight.json").absolute()
    config.write_text("max_steps = 2\n")
    state = {
        "run_id": "run-happy",
        "resolved_run_output": str(common.prime_run_output(output)),
    }
    manifest = {
        "schema": "filiolae.two-gpu-smoke-payload.v1",
        "runs": {"happy": "run-happy", "tamper": "run-tamper"},
        "files": {"smoke.toml": common.sha256_file(config)},
    }
    manifest_path.write_text(json.dumps(manifest))
    preflight = {
        "schema": "filiolae.two-gpu-remote-preflight.v1",
        "ok": True,
        "run_id": "run-happy",
        "profile": "happy",
        "output": str(output),
        "anchor_dir": str(anchors),
        "config": str(config),
        "payload_manifest_sha256": common.sha256_file(manifest_path),
    }
    preflight_path.write_text(json.dumps(preflight))
    assert (
        collector._validate_run_inputs(state, "happy", output, anchors, config, manifest_path, preflight_path)
        == preflight
    )
    wrong_layout = dict(state, resolved_run_output=str(output))
    with pytest.raises(common.SmokeToolError, match="does not bind the collected run inputs"):
        collector._validate_run_inputs(
            wrong_layout, "happy", output, anchors, config, manifest_path, preflight_path
        )
    manifest["runs"]["happy"] = "other-run"
    manifest_path.write_text(json.dumps(manifest))
    preflight["payload_manifest_sha256"] = common.sha256_file(manifest_path)
    preflight_path.write_text(json.dumps(preflight))
    with pytest.raises(common.SmokeToolError, match="does not bind the run ID"):
        collector._validate_run_inputs(state, "happy", output, anchors, config, manifest_path, preflight_path)


def test_collector_requires_actual_nonzero_tamper_returncode() -> None:
    state = {
        "status": "success",
        "signal_received": None,
        "governed_returncode": 75,
        "injector_returncode": 0,
        "expected_audit_returncode": 1,
        "validation_error": None,
    }
    collector._assert_success_state(state, "tamper")
    for invalid in (0, None, "75"):
        rejected = dict(state, governed_returncode=invalid)
        with pytest.raises(collector.SmokeToolError, match="unsuccessful freeze/audit semantics"):
            collector._assert_success_state(rejected, "tamper")


def test_full_collector_omits_redundant_trainer_and_export_bulk(tmp_path: Path) -> None:
    output = tmp_path / "run"
    expected = [
        output / "configs" / "orchestrator.toml",
        output / "logs" / "orchestrator.log",
        output / "run_default" / "broadcasts" / "step_1" / "model.safetensors",
        output / "run_default" / "control" / "filiolae" / "ledger.jsonl",
        output / "run_default" / "control" / "filiolae" / "artifacts" / "candidate",
        output / "run_default" / "rollouts" / "step_1" / "traces.jsonl",
    ]
    omitted = [
        output / "checkpoints" / "step_2" / "trainer" / "optimizer.bin",
        output / "weights" / "step_2" / "model.safetensors",
    ]
    for path in [*expected, *omitted]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"evidence")
    files = collector._full_run_files(output)
    sources = {source for source, _ in files}
    assert set(expected) <= sources
    assert not (set(omitted) & sources)
    assert {name for _, name in files} == {f"run/{path.relative_to(output).as_posix()}" for path in expected}


def test_collector_refuses_live_runner_before_snapshot(tmp_path: Path) -> None:
    output = tmp_path / "run"
    output.mkdir()
    state = {
        "terminal": False,
        "runner_pid": os.getpid(),
        "runner_start_token": common.process_start_token(os.getpid()),
    }
    with pytest.raises(common.SmokeToolError, match="not terminal"):
        collector._assert_quiescent(state, output)


def test_tamper_runner_accepts_only_step_one_then_denial(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    records = [
        {"seq": 1, "event": "policy.promoted", "data": {"step": 1}},
        {"seq": 2, "event": "tripwire.fired", "data": {"step": 2}},
        {"seq": 3, "event": "gate.denied", "data": {"step": 2}},
    ]
    ledger.write_text("".join(json.dumps(item) + "\n" for item in records))
    tamper_runner._validate_tamper_ledger(ledger)
    records.insert(1, {"seq": 2, "event": "policy.promoted", "data": {"step": 2}})
    ledger.write_text("".join(json.dumps(item) + "\n" for item in records))
    with pytest.raises(common.SmokeToolError, match="promote only step 1"):
        tamper_runner._validate_tamper_ledger(ledger)


def test_all_prime_submodules_are_pinned() -> None:
    assert common.PRIME_SUBMODULES == {
        "deps/pydantic-config": "4f5ae373582ceffdbf7e6bd1998c9ad568fcc1ad",
        "deps/renderers": "d4707862ac83aa3773c21f4096aec72bd17b91e4",
        "deps/research-environments": "f9c43a74fe6179381f108575c8a8426a9923eecc",
        "deps/verifiers": "d30a3f48e5f14b06b3081b2102ec32cc3149b849",
    }


def test_gpu_policy_requires_two_matching_a6000s(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    monkeypatch.setattr(remote.shutil, "which", lambda name: "/usr/bin/nvidia-smi")
    query = "0, GPU-a, NVIDIA RTX A6000, 49140, 535.0\n1, GPU-b, NVIDIA RTX A6000, 49140, 535.0\n"

    def fake_run(argv, **kwargs):
        del kwargs
        if "--query-gpu=index,mig.mode.current" in argv:
            return SimpleNamespace(stdout="0, N/A\n1, N/A\n")
        return SimpleNamespace(stdout=query)

    monkeypatch.setattr(remote, "run_checked", fake_run)
    policy = {"name_contains": "NVIDIA RTX A6000", "min_memory_mib": 47000, "count": 2}
    assert len(remote._gpu_report(policy)) == 2
    policy["name_contains"] = "H100"
    with pytest.raises(common.SmokeToolError, match="name violates"):
        remote._gpu_report(policy)


def test_gpu_policy_rejects_enabled_or_unknown_mig_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace

    monkeypatch.setattr(remote.shutil, "which", lambda name: "/usr/bin/nvidia-smi")
    gpu_query = "0, GPU-a, NVIDIA RTX A6000, 49140, 535.0\n1, GPU-b, NVIDIA RTX A6000, 49140, 535.0\n"
    mig_mode = "Enabled"

    def fake_run(argv, **kwargs):
        del kwargs
        if "--query-gpu=index,mig.mode.current" in argv:
            return SimpleNamespace(stdout=f"0, {mig_mode}\n1, Disabled\n")
        return SimpleNamespace(stdout=gpu_query)

    monkeypatch.setattr(remote, "run_checked", fake_run)
    policy = {"name_contains": "NVIDIA RTX A6000", "min_memory_mib": 47000, "count": 2}
    with pytest.raises(common.SmokeToolError, match="MIG-enabled"):
        remote._gpu_report(policy)
    mig_mode = "mystery"
    with pytest.raises(common.SmokeToolError, match="unrecognized MIG mode"):
        remote._gpu_report(policy)


def test_exact_model_snapshot_directory_is_required(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    revision = "c97a910849ec6aa962add3dc253a0817d61c0210"
    home = tmp_path / "hf"
    snapshot = home / "hub" / "models--PrimeIntellect--Qwen3-0.6B-Reverse-Text-SFT" / "snapshots" / revision
    snapshot.mkdir(parents=True)
    for name in ("config.json", "tokenizer_config.json"):
        (snapshot / name).write_text("test")
    lfs_files: dict[str, dict[str, object]] = {}
    for name, content in (("model.safetensors", b"weights"), ("tokenizer.json", b"tokens")):
        (snapshot / name).write_bytes(content)
        lfs_files[name] = {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
    monkeypatch.setattr(remote, "MODEL_LFS_FILES", lfs_files)
    manifest = {
        "model": {
            "repo_id": "PrimeIntellect/Qwen3-0.6B-Reverse-Text-SFT",
            "snapshot_commit": revision,
            "lfs_files": lfs_files,
        }
    }
    assert (
        remote._assert_model_snapshot(manifest, home, Path("/unused/python"), prefetch=False, timeout=1)
        == snapshot
    )
    main_ref = snapshot.parents[1] / "refs" / "main"
    assert main_ref.read_text() == revision
    assert main_ref.stat().st_mode & 0o777 == 0o600
    (snapshot / "config.json").unlink()
    with pytest.raises(common.SmokeToolError, match="does not exist"):
        remote._assert_model_snapshot(manifest, home, Path("/unused/python"), prefetch=False, timeout=1)


def test_exact_dataset_snapshot_is_pinned_and_loads_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    home = tmp_path / "hf"
    dataset_cache = home / "hub" / "datasets--PrimeIntellect--Reverse-Text-RL"
    snapshot = dataset_cache / "snapshots" / common.DATASET_REVISION
    (snapshot / "data").mkdir(parents=True)
    (snapshot / "README.md").write_text("dataset card")
    parquet = snapshot / "data" / "train-00000-of-00001.parquet"
    parquet.write_bytes(b"reviewed parquet")
    lfs_files = {
        "data/train-00000-of-00001.parquet": {
            "size": parquet.stat().st_size,
            "sha256": hashlib.sha256(parquet.read_bytes()).hexdigest(),
        }
    }
    monkeypatch.setattr(remote, "DATASET_LFS_FILES", lfs_files)
    observed: dict[str, object] = {}

    def fake_run(argv, *, env, **kwargs):
        del kwargs
        observed["argv"] = argv
        observed["env"] = env
        return SimpleNamespace(stdout='{"columns": ["prompt"], "rows": 1000}\n')

    monkeypatch.setattr(remote, "run_checked", fake_run)
    manifest = {
        "dataset": {
            "repo_id": common.DATASET_REPO_ID,
            "snapshot_commit": common.DATASET_REVISION,
            "lfs_files": lfs_files,
        }
    }
    evidence = remote._assert_dataset_snapshot(
        manifest, home, Path("/venv/python"), prefetch=False, timeout=30
    )
    assert evidence["snapshot"] == str(snapshot)
    assert evidence["offline_load"] == {"columns": ["prompt"], "rows": 1000}
    assert observed["env"]["HF_HUB_OFFLINE"] == "1"
    assert observed["env"]["HF_DATASETS_OFFLINE"] == "1"
    assert "revision=" not in " ".join(observed["argv"])
    main_ref = dataset_cache / "refs" / "main"
    assert main_ref.read_text() == common.DATASET_REVISION
    assert main_ref.stat().st_mode & 0o777 == 0o600
    parquet.write_bytes(b"tampered")
    with pytest.raises(common.SmokeToolError, match="wrong size"):
        remote._assert_dataset_snapshot(manifest, home, Path("/venv/python"), prefetch=False, timeout=30)


def test_null_harness_is_prewarmed_then_proven_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    payload = tmp_path / "payload"
    payload_bin = payload / "bin"
    payload_bin.mkdir(parents=True)
    for name in ("uv", "pip"):
        executable = payload_bin / name
        executable.write_text("tool")
        executable.chmod(0o700)
    lock = payload / "null-harness-program.py.lock"
    lock.write_text("reviewed lock")
    prime_rl = tmp_path / "prime-rl"
    program = prime_rl / "deps" / "verifiers" / "verifiers" / "v1" / "harnesses" / "null" / "program.py"
    program.parent.mkdir(parents=True)
    program.write_text("print('harness')\n")
    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    hf_home = tmp_path / "hf"
    hf_home.mkdir()
    interpreter = hf_home / "filiolae-uv-cache" / "environments-v2" / "test" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text("python")
    interpreter.chmod(0o700)
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs.get("env")))
        if argv[:2] == ["sh", "-c"]:
            local_bin = hf_home / "filiolae-harness-home" / ".local" / "bin"
            return SimpleNamespace(
                stdout=f"{local_bin / 'pip'}\n{local_bin / 'uv'}\nuv 0.11.8 (x86_64-unknown-linux-gnu)\n"
            )
        if argv[1:4] == ["python", "find", "--script"]:
            return SimpleNamespace(stdout=f"{interpreter}\n")
        if argv[1:] == ["--version"]:
            return SimpleNamespace(stdout="uv 0.11.8 (x86_64-unknown-linux-gnu)\n")
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(remote, "run_checked", fake_run)
    evidence = remote._prepare_null_harness(
        payload,
        prime_rl,
        venv_bin,
        hf_home,
        prefetch=True,
        timeout=30,
        script_dir=tmp_path / "scripts",
    )
    assert evidence["lock_sha256"] == hashlib.sha256(b"reviewed lock").hexdigest()
    assert Path(evidence["script"]).read_bytes() == program.read_bytes()
    sync_calls = [(argv, env) for argv, env in calls if "sync" in argv]
    assert len(sync_calls) == 3
    assert "UV_OFFLINE" not in sync_calls[0][1]
    assert sync_calls[1][1]["UV_OFFLINE"] == "1"
    assert "--frozen" in sync_calls[1][0]
    assert sync_calls[2][1]["UV_OFFLINE"] == "1"
    assert "--frozen" not in sync_calls[2][0]
    ensure_calls = [(argv, env) for argv, env in calls if argv[:2] == ["sh", "-c"]]
    assert len(ensure_calls) == 1
    assert "pip install -q -U --user uv" in ensure_calls[0][0][2]
    assert ensure_calls[0][1]["HOME"] == str(hf_home / "filiolae-harness-home")
    assert evidence["harness_home"] == str(hf_home / "filiolae-harness-home")


def test_model_main_ref_rejects_a_conflicting_revision(tmp_path: Path) -> None:
    model_cache = tmp_path / "models--example"
    refs = model_cache / "refs"
    refs.mkdir(parents=True)
    (refs / "main").write_text("other-revision")
    with pytest.raises(common.SmokeToolError, match="conflicts"):
        remote._bind_model_main_ref(model_cache, common.MODEL_REVISION)


def test_model_snapshot_rejects_cache_link_escape(tmp_path: Path) -> None:
    home = tmp_path / "hf"
    model_cache = home / "hub" / "models--PrimeIntellect--Qwen3-0.6B-Reverse-Text-SFT"
    snapshot = model_cache / "snapshots" / common.MODEL_REVISION
    snapshot.mkdir(parents=True)
    (model_cache / "blobs").mkdir()
    outside = tmp_path / "outside-config.json"
    outside.write_text("{}")
    (snapshot / "config.json").symlink_to(outside)
    manifest = {
        "model": {
            "repo_id": common.MODEL_REPO_ID,
            "snapshot_commit": common.MODEL_REVISION,
            "lfs_files": common.MODEL_LFS_FILES,
        }
    }
    with pytest.raises(common.SmokeToolError, match="escapes"):
        remote._assert_model_snapshot(manifest, home, Path("/unused/python"), prefetch=False, timeout=1)


def test_tamper_profile_requires_four_steps(tmp_path: Path) -> None:
    config = tmp_path / "tamper.toml"
    text = (ROOT / "examples" / "prime-rl" / "reverse-text-filesystem-smoke.toml").read_text()
    config.write_text(text.replace("max_steps = 2", "max_steps = 4", 1))
    assert remote._validate_config(config, expected_steps=4)["max_steps"] == 4
    with pytest.raises(common.SmokeToolError, match="max_steps = 2"):
        remote._validate_config(config, expected_steps=2)
