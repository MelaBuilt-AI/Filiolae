# prime-rl v0.8.0 integration

**Pinned host:** `PrimeIntellect-ai/prime-rl@60bc2954` (tag `v0.8.0`) with its gitlink
`verifiers@d30a3f48e5f14b06b3081b2102ec32cc3149b849`.

## Stock seam audit

The stock `WeightWatcher.apply_policy_update` is fail-open for governance: it advances policy state
before observer callbacks and swallows observer errors. `VersionObserver` is telemetry, not an
enforcement point. Stock component tasks can also fail without the main orchestrator task propagating
the error.

## Reference host patch

`../adapters/prime-rl-v0.8.0-fail-closed.patch` applies cleanly to the pinned tag. It adds:

- a mandatory `PromotionBarrier`, distinct from `VersionObserver`;
- bounded authorization before observers, state mutation, or weight loading;
- loading only the exact gate-owned staged path returned by the barrier;
- one durable success/load-failure outcome before policy/version state advances;
- fatal freeze propagation on denial, timeout, cancellation, load failure, or ambiguous outcome;
- critical-component/main-loop racing so watcher failure makes the orchestrator fail nonzero;
- nonzero forced-teardown exit rather than `os._exit(0)`;
- `PRIME_RL_ORCHESTRATOR_ENTRYPOINT` so the local role launcher can select Filiolae's governed
  orchestrator while retaining prime-rl's cleanup of all local roles.

Apply for review:

```bash
git clone --branch v0.8.0 https://github.com/PrimeIntellect-ai/prime-rl.git
cd prime-rl
git apply --check /path/to/filiolae/adapters/prime-rl-v0.8.0-fail-closed.patch
git apply /path/to/filiolae/adapters/prime-rl-v0.8.0-fail-closed.patch
```

## Governed launcher

Filiolae installs two integration entrypoints:

- `filiolae-rl`: delegates to prime-rl's local launcher while selecting the governed orchestrator;
- `filiolae-prime-rl-orchestrator`: constructs the Charter, Ledger, ArtifactStore, Gate, freeze
  controller, evidence builder, and `PrimeRLPromotionBarrier` before starting patched `Orchestrator`.

The MVP rejects resume and every transport except an explicit `weight_broadcast.type = "filesystem"`.
For step `N`, it requires exactly `<output>/broadcasts/step_N` with a regular `STABLE` marker and the
effective training traces at `<output>/rollouts/step_N/train/effective/traces.jsonl`. Symlink path
components are rejected. It stages the candidate and returns only the gate-owned copy.

A CPU/single-node invocation after installing Filiolae into the patched prime-rl environment is:

```bash
export FILIOLAE_CHARTER=/absolute/path/to/filiolae/examples/charter.demo.yaml
filiolae supervise \
  --freeze-marker /absolute/output/control/filiolae/freeze.json \
  --cwd /path/to/patched/prime-rl -- \
  filiolae-rl @ /absolute/path/to/rl.toml --output-dir /absolute/output
```

A pinned two-GPU profile and execution checklist are provided in
[`../examples/prime-rl/reverse-text-filesystem-smoke.toml`](../examples/prime-rl/reverse-text-filesystem-smoke.toml)
and [`two-gpu-smoke-runbook.md`](two-gpu-smoke-runbook.md). The config must explicitly select
filesystem broadcasting. Do not run the reverse-text example
unchanged: with an inference block, v0.8.0 otherwise selects NCCL. The CPU supervisor uses a held
READY/GO bootstrap to prevent governed target exec between pre- and post-spawn freeze checks. It
terminates non-escaping members of the dedicated process group with TERM then KILL. It is not a
hostile sandbox; production must add separate credentials and a cgroup/service-manager boundary.

The launcher can additionally require local Ed25519 head checkpoints by setting both
`FILIOLAE_LOCAL_ANCHOR_PRIVATE_KEY` and `FILIOLAE_LOCAL_ANCHOR_DIR` to protected paths outside the
run output. Genesis records the signer key ID; the Gate requires a durable receipt for the exact
evidence predecessor; terminal outcomes and `run.exited` are checkpointed. See
[`signed-head-checkpoints.md`](signed-head-checkpoints.md). This is same-control-domain signing.

Experimental witness mode instead configures
`FILIOLAE_ANCHOR_WITNESS_SOCKET`, `FILIOLAE_ANCHOR_WITNESS_PUBLIC_KEY`,
`FILIOLAE_ANCHOR_WITNESS_MIRROR_DIR`, `FILIOLAE_LEDGER_LOCK_PATH`, and
`FILIOLAE_LEDGER_SHARED_GID`. The modes are mutually exclusive. In witness mode the orchestrator
loads only the public key; a separate UID may own the signer and authoritative receipt chain while a
pre-provisioned group lock stabilizes the Ledger snapshot. See [`unix-witness.md`](unix-witness.md)
for the cross-credential contract and trusted-first-use/same-host non-claims.

## Evidence semantics

For the first smoke run:

- `config.resolved`: prime-rl's resolved `control/orch.toml`;
- `batch.committed`: effective training traces that led to candidate step `N`;
- `source_eval.result`: deterministic source-policy/run lineage evidence with
  `candidate_quality_evaluated: false`;
- `weights.published`: exact trainer filesystem broadcast staged into the Gate store;
- signed head receipt (when required): durable acknowledgement of the exact evidence head;
- `gate.approved`: single-use authorization intent binding that receipt;
- `policy.promoted` or `weights.load_failed`: exactly one outcome, followed by a receipt;
- `run.exited`: terminal status, followed by the final receipt.

Candidate-quality gating requires shadow inference/evaluation of candidate weights and is deferred.
The current evidence must never be described as proving candidate quality.

## Validation status

CPU tests cover the real evidence builder plus Gate, exact-path success, denial/fault/timeout with zero
weight loads, signed-receipt vectors/chaining/tamper detection/key safety/Gate binding/timeout/CAS
race, load/outcome ambiguity, a freeze-killed process tree, TERM-to-KILL escalation, and the
deterministic pre-exec race. Patch application against the exact pinned commit, lint, builds, and the
offline suite pass. The pinned two-A6000 reverse-text happy/tamper campaign passed at Filiolae
commit `9bbad47bf40a17d24273025bf85f09e867f82305`; see
[`live-two-gpu-acceptance.md`](live-two-gpu-acceptance.md). This proves only the bounded integration
and fail-closed tamper behavior described there, not production containment or candidate quality.
