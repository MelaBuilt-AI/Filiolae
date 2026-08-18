# Pinned two-GPU reverse-text smoke runbook

This procedure was exercised in the bounded r18 two-A6000 campaign documented in
[`live-two-gpu-acceptance.md`](live-two-gpu-acceptance.md). Re-running it is still required after
changes to the governed runtime, adapter, payload, or safety controls.

For a billed Prime Intellect acceptance, the canonical executable procedure is
`ops/two-gpu-smoke/README.md`. Its automation binds the exact source/model/dataset/config inputs, runs this
happy/tamper protocol, retains evidence, and keeps provider-side exact-pod-ID termination independent
from the governed process. The commands below remain the underlying manual protocol.

## Preconditions

1. Linux host with two authorized visible GPUs and enough storage for the model plus staged copies.
2. Fresh clone at prime-rl `60bc29547a8824ad1de7b9af8d265e2b27b2a72d`; verify the `verifiers`
   gitlink is `d30a3f48e5f14b06b3081b2102ec32cc3149b849`.
3. Apply `adapters/prime-rl-v0.8.0-fail-closed.patch` and install Filiolae into that prime-rl
   environment. Do not use an unpatched host.
4. Use a fresh absolute output directory. The governed MVP rejects resume and an existing
   `<output>/control/filiolae` directory.
5. Set `FILIOLAE_CHARTER` to an absolute reviewed Charter. For this smoke, the demo Charter tests
   evidence/integrity mechanics only; it is not a production policy.
6. Prefetch and integrity-check model commit `c97a910849ec6aa962add3dc253a0817d61c0210` and
   `PrimeIntellect/Reverse-Text-RL` dataset commit `eacc9a0d76d9fd22e40008ab9d546008bdd7e432`;
   bind both Hugging Face `refs/main` files to those commits and run with hub, datasets, and
   Transformers offline modes enabled. Prewarm the manifest-bound null-harness script lock with the
   reviewed uv binary, then enforce uv offline mode during governed execution. Bind all
   supervision, audit, injection, and collection paths to prime-rl's resolved `OUTPUT/run_default`
   directory, and require every expected filesystem checkpoint to cross the promotion barrier
   before clean orchestrator exit. The canonical automation performs these checks.

## Happy path

From the patched prime-rl checkout:

```bash
export CUDA_VISIBLE_DEVICES=0,1
export FILIOLAE_CHARTER=/absolute/path/to/filiolae/examples/charter.demo.yaml
export FILIOLAE_OUTPUT=/absolute/fresh/path/filiolae-reverse-text-happy
export FILIOLAE_LOCAL_ANCHOR_PRIVATE_KEY=/absolute/protected/path/private.pem
export FILIOLAE_LOCAL_ANCHOR_DIR=/absolute/protected/path/fresh-happy-receipts

# Run once beforehand; retain the public key out of band.
filiolae anchor-keygen \
  --private-key "$FILIOLAE_LOCAL_ANCHOR_PRIVATE_KEY" \
  --public-key /absolute/protected/path/public.pem

# Alternative: use the mutually exclusive Unix-witness environment and separately started service
# from docs/unix-witness.md. Do not set FILIOLAE_LOCAL_ANCHOR_* in that mode. A same-UID test does not
# validate the documented cross-credential boundary.

filiolae supervise \
  --freeze-marker "$FILIOLAE_OUTPUT/control/filiolae/freeze.json" \
  --cwd "$PWD" -- \
  filiolae-rl \
    @ /absolute/path/to/filiolae/examples/prime-rl/reverse-text-filesystem-smoke.toml \
    --output-dir "$FILIOLAE_OUTPUT"
```

Pass criteria:

- process exits 0 and no freeze marker exists;
- the Ledger audits with artifacts and Charter;
- exactly steps 1 and 2 are approved and each has exactly one `policy.promoted` outcome;
- every approval binds a valid signed receipt for its immediate predecessor and the final outcome head
  is checkpointed with zero unanchored tail records;
- inference loaded a verified disposable copy under `control/filiolae/approved-loads`, not the trainer path or the immutable artifact-store master;
- resolved config says `weight_broadcast.type = "filesystem"`;
- no claim is made that candidate quality was evaluated.

Audit command:

```bash
filiolae audit \
  "$FILIOLAE_OUTPUT/control/filiolae/ledger.jsonl" \
  --artifact-root "$FILIOLAE_OUTPUT/control/filiolae/artifacts" \
  --charter "$FILIOLAE_OUTPUT/control/filiolae/charter.yaml" \
  --anchor-dir "$FILIOLAE_LOCAL_ANCHOR_DIR" \
  --anchor-public-key /absolute/protected/path/public.pem
```

## Tamper game day

Use a separate fresh output and raise `max_steps` to at least 4 in a copied config. After
`policy.promoted` for step 1 appears, an authorized game-day operator (outside the governed role)
corrupts one step-1 staged evidence artifact. Do not modify the Ledger. The next Gate must detect the
artifact digest mismatch, make zero further weight-load calls, write/latch freeze state, and cause the
supervisor to terminate all non-escaping local roles. The governed process must exit nonzero (the CLI
uses 75 for freeze). Preserve the run directory for audit.

This drill intentionally assumes operator write access that a production deployment must remove. A
POSIX process group is only the CPU/single-node backstop; production acceptance requires the same
scenario under cgroup/service-manager containment.

## Evidence to retain

- exact host and submodule SHAs, applied-patch digest, Filiolae commit, GPU model/driver/CUDA versions;
- command/config and environment allowlist (redact credentials);
- governed control/artifacts, broadcasts, rollouts, configs/logs, Ledger audit JSON, freeze marker if any, and process exit status (trainer optimizer checkpoints and convenience exports are not promotion evidence);
- wall-clock authorization/staging time to tune the current 600-second host timeout.
