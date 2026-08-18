from pathlib import Path


def test_reference_patch_contains_required_fatal_control_flow() -> None:
    patch = (Path(__file__).parents[1] / "adapters" / "prime-rl-v0.8.0-fail-closed.patch").read_text()
    for required in (
        "PRIME_RL_ORCHESTRATOR_ENTRYPOINT",
        "promotion_barrier.freeze_fatal",
        "asyncio.wait_for",
        "asyncio.FIRST_COMPLETED",
        "os._exit(1)",
        "approved_weights_path",
        "wait_for_final_filesystem_policy",
        "FINAL_POLICY_WAIT_TIMEOUT_S",
        "Governed policy promotions reached step",
    ):
        assert required in patch
