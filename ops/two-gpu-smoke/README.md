# Two-GPU smoke acceptance automation

This directory prepares and operates the pinned Filiolae/prime-rl two-GPU smoke. It does **not** provision compute. The first live campaign result is recorded in [`../../docs/live-two-gpu-acceptance.md`](../../docs/live-two-gpu-acceptance.md). Its accepted boundary is deliberately narrow:

- local Ed25519 head anchors (same host/control domain);
- Filiolae's POSIX process-group supervisor;
- exactly two visible, non-MIG GPUs;
- pinned prime-rl v0.8.0 plus the reviewed fail-closed patch;
- filesystem weight broadcast and fresh outputs only;
- source-lineage/integrity evidence, **not candidate-quality evidence**.

A process can escape a POSIX process group with `setsid`. These scripts do not make the separate-UID, systemd/cgroup, remote-witness, trusted-time, or production-security claims described elsewhere. The local pod controller only terminates cloud resources by the exact recorded pod ID; it never provisions or selects a pod.

## Files

- `build_payload.py` — runs local quality/build/patch checks and writes a secret-free payload outside the repository.
- `remote_preflight.py` — verifies every payload hash, the already-patched host, exact GPUs, offline assets, key permissions, disk, and fresh paths; then creates only the fresh output/receipt directories.
- `run_happy.py` — invokes remote preflight, sanitizes the child environment, applies a hard wall timeout to `filiolae supervise`, and verifies audit/anchors/terminal semantics.
- `tamper_after_step1.py` — bounded authorized game-day corruption of the exact Gate-staged step-1 candidate. It never edits the Ledger.
- `collect_evidence.py` — refuses a live snapshot, re-runs audit/anchor checks, and creates an allowlisted uncompressed archive plus SHA-256 on durable storage.
- `pod_controller.py` — local exact-ID guard/deadline/termination helper. It is intentionally not a provisioner.

All tools use only the Python standard library. Generated payloads, state, archives, keys, and receipts must remain outside this source tree.

## 1. Before any GPU is billed

Create the local-anchor key outside both repositories and keep the public key locally:

```bash
umask 077
uv run filiolae anchor-keygen \
  --private-key /secure/smoke/run-001-private.pem \
  --public-key /secure/smoke/run-001-public.pem
chmod 0600 /secure/smoke/run-001-private.pem
```

Prepare a clean prime-rl checkout at `60bc29547a8824ad1de7b9af8d265e2b27b2a72d` with gitlink `deps/verifiers@d30a3f48e5f14b06b3081b2102ec32cc3149b849`. The builder requires that checkout to be **unpatched** so it can independently apply-check the repository patch:

```bash
uv run --no-sync python ops/two-gpu-smoke/build_payload.py \
  --prime-rl /work/prime-rl-clean \
  --campaign-id campaign-001 \
  --happy-run-id run-001-happy \
  --tamper-run-id run-001-tamper \
  --anchor-public-key /secure/smoke/run-001-public.pem \
  --output /secure/smoke/run-001-payload.tar.gz \
  --min-free-gib 40
```

The command requires a clean Filiolae checkout; runs lock/lint/full tests/technical preflight; builds a wheel; applies and compiles the patch in a temporary worktree; and emits a payload plus `.sha256`. It archives a gitless pre-patched prime-rl source tree containing all four pinned submodules (`pydantic-config`, `renderers`, `research-environments`, and `verifiers`), a per-file source manifest, and the pinned `pyproject.toml`/`uv.lock` hashes. It also bundles the reviewed Linux x86_64 uv 0.11.8 binary (SHA-256 `646adf5cf12ba17d1a41fa77c8dd6496f73651dcfeeed6b5f4ec019b36bc7153`), so bootstrap never clones or fetches a submodule. The payload contains the public key, never the private key. Build the tested wheel, patched prime-rl tree, model, reverse-text assets, and caches into an immutable image or persistent disk before provisioning. Do not put credentials or the private key in that image.

## 2. Remote transfer and run

Transfer the payload and private key separately. Verify the payload checksum before extracting it into a new mode-0700 directory. Never disable SSH host-key checking; use a per-run known-hosts file and retain its fingerprint. Ubuntu 22 may have only Python 3.10, so invoke every remote tool through `payload/bin/bootstrap_remote.sh {preflight|happy|tamper|inject|collect}`. That POSIX shell verifies bundled uv, installs/selects managed Python 3.12, then invokes the chosen stdlib Python tool.

Prefer an image with the environment plus the exact model and dataset snapshots already present. Otherwise the first happy invocation may use `--bootstrap-source --bootstrap-frozen --prefetch-model --prefetch-dataset --prefetch-harness`: source bootstrap safely extracts and verifies the bundled gitless pre-patched tree (all source hashes and submodule SHAs, plus reverse patch check); the **only** allowed sync is `uv sync --frozen --package prime-rl --package reverse-text-v1 --extra flash-attn --extra disagg --no-dev`, followed by a no-dependency payload-wheel install. **Never use `uv sync --locked` here**: on this pin, freshness resolution can spend more than ten billed minutes fetching optional flash-attn-4 ROCm/aiter sources. All later commands use direct `.venv/bin` executables and never implicit uv sync. Every profile re-installs Filiolae and its console wrappers from the manifest-bound wheel without dependencies; the payload preserves and binds the wheel's valid distribution/version/tag filename required by installers. It then proves `prime_rl` and `reverse_text_v1` resolve beneath the verified bundled source tree. Bootstrap/prefetch asserts model snapshot `c97a910849ec6aa962add3dc253a0817d61c0210` and dataset snapshot `eacc9a0d76d9fd22e40008ab9d546008bdd7e432`, verifies the reviewed Git-LFS sizes and SHA-256 digests, binds both offline caches' `refs/main` files to those reviewed commits, and proves the dataset loads offline as exactly 1,000 `prompt` rows. It also publishes the pinned null-harness PEP 723 script lock at the content-addressed path, warms that exact environment with bundled uv 0.11.8, then re-syncs and launches `--help` under `UV_OFFLINE=1`. A manifest-bound `pip` shim accepts only verifiers' exact `pip install -q -U --user uv` probe and redirects it to the already-verified bundled uv; every other invocation fails closed. Preflight then requires exactly two policy-matching A6000 GPUs with at least 47000 MiB by default, allocates a Torch tensor on both GPUs, and performs a bounded `filiolae-rl --dry-run` config resolution before creating run paths. Pinned prime-rl resolves the actual governed run beneath `OUTPUT/run_default`; supervision, audit, tamper injection, and collection must use that resolved directory. The patched orchestrator also keeps its critical watcher alive after rollout drain until every expected filesystem checkpoint is promoted, or fails boundedly instead of reporting success before late trainer broadcasts.

Run the complete remote run/collection/retrieval command inside the local exact-ID guard so its `finally` path terminates billing. Start an independent deadline process from a separate control session first (state and known-hosts paths must be outside this repository):

```bash
DEADLINE=$(date -u -d '+4 hours' +%Y-%m-%dT%H:%M:%SZ)
nohup uv run --no-sync python ops/two-gpu-smoke/pod_controller.py \
  --identity ~/.ssh/id_ed25519_filiolae_compute \
  --known-hosts /secure/smoke/run-001.known_hosts \
  --state-dir /secure/smoke/controller-state \
  deadline --pod-id "$POD_ID" --deadline "$DEADLINE" --yes \
  > /secure/smoke/run-001-deadline.log 2>&1 &

uv run --no-sync python ops/two-gpu-smoke/pod_controller.py \
  --identity ~/.ssh/id_ed25519_filiolae_compute \
  --known-hosts /secure/smoke/run-001.known_hosts \
  --state-dir /secure/smoke/controller-state \
  guard --pod-id "$POD_ID" --max-seconds 2400 --yes -- \
  /secure/smoke/local-orchestrate-and-retrieve.sh "$POD_ID"
```

`guard` terminates the exact pod after the command succeeds, fails, times out, or receives a handled signal. `deadline` is the crash-independent TTL backstop. Both require explicit `--yes`, atomically retain controller state, and confirm disappearance from the provider's active list. `status`, `ssh`, `upload`, and `download` use the same exact ID. For a newly provisioned pod, SSH/SCP waits up to the bounded `--ssh-ready-timeout` while the Prime status field is exactly `N/A`; any other malformed connection remains a fail-closed error. The transport uses a controller-owned accept-new-once then strict `known_hosts` file; do not share or delete it mid-run. See `pod_controller.py --help` for bounded polling options.

On the pod, with no API tokens in the environment:

```bash
/secure/payload/bin/bootstrap_remote.sh happy \
  --payload-dir /secure/payload \
  --prime-rl /opt/prime-rl \
  --run-id run-001-happy \
  --output /runs/run-001 \
  --anchor-private-key /secure/keys/run-001-private.pem \
  --anchor-dir /secure/receipts/run-001 \
  --state-dir /secure/operator/run-001 \
  --venv-dir /opt/prime-rl/.venv \
  --bootstrap-source --bootstrap-frozen --prefetch-model --prefetch-dataset --prefetch-harness \
  --hf-home /models/huggingface \
  --require-path /models/huggingface \
  --wall-seconds 1800
```

`remote_preflight.py` rejects pre-existing output or receipt paths. A failed attempt is retained and a retry uses a new run ID; there is no resume. The runner sets `CUDA_VISIBLE_DEVICES=0,1`, offline Hugging Face/Datasets/Transformers and null-harness uv modes, and WANDB offline, and passes only an explicit environment allowlist. It writes no private material to logs or state.

For the separate disposable tamper drill, use the derived `tamper.toml` (`max_steps = 4`) and a fresh run ID/output. Start this helper as the authorized external operator:

```bash
/secure/payload/bin/bootstrap_remote.sh inject \
  --ledger /runs/run-002/control/filiolae/ledger.jsonl \
  --artifact-root /runs/run-002/control/filiolae/artifacts \
  --operator-log /secure/operator/run-002/tamper-operation.json \
  --timeout-seconds 300
```

It waits for exactly one `policy.promoted` at step 1, resolves the bound `candidate_weights` artifact beneath the Gate root, rejects symlinks/special files, flips one byte in place with `O_NOFOLLOW` and `fsync`, and records before/after hashes. Run it only after the happy smoke passes and never against production.
The normal tamper acceptance uses the controller, not the injector alone:

```bash
/secure/payload/bin/bootstrap_remote.sh tamper \
  --payload-dir /secure/payload \
  --prime-rl /opt/prime-rl \
  --run-id run-001-tamper \
  --output /runs/run-001-tamper \
  --anchor-private-key /secure/keys/run-001-private.pem \
  --anchor-dir /secure/receipts/run-001-tamper \
  --state-dir /secure/operator/run-001-tamper \
  --venv-dir /opt/prime-rl/.venv \
  --hf-home /models/huggingface \
  --require-path /models/huggingface
```

It uses the manifest-bound distinct tamper run ID, fresh paths, shared already-bootstrapped `.venv`, and `tamper.toml` (`max_steps = 4`). `run_tamper.py` starts the bounded injector, expects governed nonzero plus a freeze marker, retains the expected failing artifact audit, verifies anchors, and rejects any `policy.promoted` after step 1. Never pass the happy run ID or reuse its paths.

## 3. Quiesce, collect, retrieve, terminate

The runner must reach terminal state before collection. The collector also requires zero visible GPU compute processes and rejects likely remaining governed processes. It does not kill by pattern. Full mode is the acceptance bundle; `--control-only` is an emergency bounded fallback when bulk evidence is already retained on persistent storage.

```bash
/secure/payload/bin/bootstrap_remote.sh collect \
  --profile happy \
  --filiolae /opt/prime-rl/.venv/bin/filiolae \
  --output /runs/run-001 \
  --anchor-dir /secure/receipts/run-001 \
  --state-dir /secure/operator/run-001 \
  --public-key /secure/payload/anchor-public.pem \
  --submitted-config /secure/payload/smoke.toml \
  --payload-manifest /secure/payload/manifest.json \
  --destination /durable-evidence/run-001.tar
```

The archive is uncompressed to minimize billed GPU time and excludes the private key. Before collection, the tool binds the terminal runner state to the exact remote-preflight report, run/profile, output and receipt paths, payload-manifest digest, and submitted config digest. Full mode retains governed control/artifacts, trainer broadcasts, rollouts, configs/logs, authoritative receipts, public inputs, operator state, fresh audit/anchor results, and bounded host/GPU metadata. It deliberately omits redundant top-level trainer optimizer checkpoints and convenience weight exports (`checkpoints/` and `weights/`), which are not promotion evidence and otherwise add about 9 GB to this smoke. Retrieve the archive, verify the adjacent `.sha256`, and repeat `filiolae audit` locally. If bulk retrieval exceeds its budget, retrieve a `--control-only` bundle, retain the omitted/full run on persistent storage, and let the exact-ID controller terminate the pod. Evidence-copy failure must never suppress provider-side termination.

Stopping `filiolae supervise`, finishing collection, or deleting local files does **not** stop billing. Only confirmed provider-side exact-ID termination does.
