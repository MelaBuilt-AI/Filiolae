from __future__ import annotations

import tomllib
from pathlib import Path


def test_pinned_two_gpu_smoke_profile_is_fail_closed() -> None:
    config = tomllib.loads(
        (
            Path(__file__).parents[1] / "examples" / "prime-rl" / "reverse-text-filesystem-smoke.toml"
        ).read_text()
    )
    assert config["max_steps"] == 2
    assert config["weight_broadcast"]["type"] == "filesystem"
    assert config["model"]["name"] == "PrimeIntellect/Qwen3-0.6B-Reverse-Text-SFT"
    assert "resume_step" not in config["ckpt"]
    assert len(config["orchestrator"]["train"]["source"]) == 1
