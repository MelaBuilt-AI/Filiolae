# Priority 6 v2 Gate D execution packet

Status: **One additional Gate D attempt is Owner-authorized; execution is deferred to a new session**

This packet executes the Gate D portion of the canonical
[Priority 6 v2 design](priority-6-v2-positive-path-design.md). It does not reopen the permanently
failed r18 candidate, weaken either threshold, authorize deployment/publication, or make Gate F
unconditional.

## Frozen objective and envelope

- Produce one new model-only character-reversal candidate from pinned r18 step-1 **source** tree
  `c047cbef4cca5dc09de95acd9f4a2ea884e8abd4f1e47dd34c2608165307c0c7`; the failed r18 step-2
  candidate is excluded.
- Use one fresh GPU with at least 48 GB VRAM, at most two precommitted SFT rounds, at most three
  total GPU-hours, and at most $3 provider spend after a fresh quote.
- Freeze the candidate before the 256-case readiness suite is released. Readiness passes only with
  256/256 complete source and candidate outputs, candidate >=244 exact (>=9,500 bps), and regression
  <=39 bps.
- A miss burns the holdback and stops this authorized path. It does not authorize another holdback,
  candidate repair, seed change, filter, threshold change, or Gate F.

The machine-readable execution manifest is
`examples/priority-6-v2/gate-d-v1/execution-manifest-v1.json`. Its SHA-256 is
`3543032f25d0bab716730e18e33bd8296c6a50c3bf2cfc1ecc0e0ee7ddda3d1a`.

## Data and candidate-selection contract

`ops/priority-6-v2/data_contract.py` deterministically generates prompts containing 6–20 symbols
from `abcdefghijkmnpqrstuvwxyz23456789`, separated by one ASCII space. The label is the exact Unicode
code-point reversal of the prompt. This deliberately bounded disclosed domain makes the result a
credible task-specific systems acceptance, not general reasoning evidence.

- Training: 50,000 unique cases; JSONL SHA-256
  `d25d18419a0684d1d5ef44544f81b52bb0b341c1a7cbc7200d11058f43b5c53b`.
- Visible development: 512 unique cases, disjoint from training; JSONL SHA-256
  `e8af52d34a6153ea6f1b977d27e6266d4df4eebbe1ce937d4e1dae615688aca5`.
- The old observed v1 suite overlaps neither set.
- Pinned tokenizer contract over all training rows: 54–107 tokens, mean 74.28022; no truncation.
- Round 1 is one full training epoch. Freeze it only at >=486/512 visible exact. Otherwise run the
  precommitted second and final epoch; freeze round 2 only at >=461/512 visible exact. If that misses,
  stop before readiness.

The readiness and final seeds are 256-bit repository Actions secrets that are generated through a
pipe and never displayed or retained in the candidate-development workspace. The private custodian
workflow first emits only commitments. It releases readiness plaintext only after the repository
contains an immutable candidate freeze record matching the requested tree digest. It releases final
plaintext only after a matching passing readiness record. All four prompt inventories are checked
for disjointness.

## Runtime and provenance

`ops/priority-6-v2/gate_d_runtime.py` pins the source/model metadata, strict-loads the source weights,
uses full-parameter AdamW SFT (`5e-5`, global batch 64, seed 684021), masks all system/user tokens from
the loss, and lets only model output tokens compute the answer. It uses no reversing wrapper,
postprocessor, retrieval, or case router. Greedy batched evaluation retains every raw completion and
strictly parses the first `<reversed_text>...</reversed_text>` span.

The fresh host installs top-level pins `torch==2.7.0`, `transformers==4.55.0`,
`safetensors==0.6.2`, and `huggingface_hub==0.34.4`; downloads only metadata from public revision
`c97a910849ec6aa962add3dc253a0817d61c0210`; verifies every staged digest; then runs training and
inference in a systemd `PrivateNetwork=yes` service with no external route. Host, package, GPU,
network, training, completion, model-tree, and cleanup evidence is retained.

## Paid-resource safety

The independent controller is a persistent WSL user-systemd template
`deploy/systemd-user/filiolae-prime-watchdog@.service`. Linger is enabled, so it survives Aster,
terminal, SSH, and login-session loss. Before model work begins, its instance is bound to the full
immutable Prime pod ID and absolute UTC deadline. The narrow controller has no creation operation,
resolves only an exact ID, retries deletion after transient failures, and requires history/absence
confirmation. The workload itself is detached under remote systemd; no foreground SSH call controls
its lifetime.

The installed template and repository bytes both hash to
`f00dc046f076d7681563677d83161615aac5103a9a2de5362674f8fe179f5ee8`. A sandboxed template test
resolved historical terminated pod `2cbed9a0b2b24d7a93fd86ce7645f87d` exactly and returned
`already-terminated`; the live instance must remain active with a nonzero PID and exact current ID
before any model command starts.

The provider supports permission-scoped API keys, but key creation is dashboard-only. The watchdog
therefore uses the existing controller credential through code that exposes only exact status/history/delete
operations; no provider credential is copied to the GPU. If the live credential, quote, identity,
watchdog instance, or termination route is ambiguous, the pod is terminated before model work.

## Live quote and stop rules

Preparation found one non-spot Massed Compute A6000 48 GB listing (`ea69b8`, cloud
`gpu_1x_a6000`) at $0.54/hour: $1.62 for the three-hour maximum, below the $3 ceiling. The immediate
creation-time refresh selected the replacement listing `b1fae8` with the same cloud, hardware, and
price. The retained response and calculation passed every authorized resource/cost bound.

Stop and terminate on any digest, dataset, suite custody, source, package, GPU, price, identity,
network namespace, watchdog, detached-lifecycle, output-completeness, time, billing, evidence, or
cleanup ambiguity. Evidence-copy failure never extends the deadline.

## Recorded pre-workload stop

The authorized fresh development pod `24b80331e5234775a3ce789f66465087` was created on 2026-08-13,
but its detached creator rejected Prime CLI's `YYYY-MM-DD HH:MM:SS UTC` timestamp. A subsequent
in-place edit changed the script path while the systemd service was still executing it. The exact-ID
watchdog was independently armed before any remote/model command, and the creator's EXIT cleanup
terminated the still-provisioning pod after one minute. Provider history reports total cost `0.0`,
the exact route now returns `already-terminated`, and the account has zero active pods.

No SSH endpoint, upload, preparation, model download, SFT, visible evaluation, candidate freeze, or
sealed-suite release occurred. This is not a Gate D quality result, and the readiness holdback was not
burned. It did consume the one fresh development GPU specified by the authorization, so a second pod
requires renewed Owner authorization. Gate F remains unused and cannot begin. The retained record is
[`evidence/attempts/priority-6-v2-gate-d-preworkload-stop-20260813/`](../evidence/attempts/priority-6-v2-gate-d-preworkload-stop-20260813/).

The exact-ID controller now accepts Prime CLI's emitted UTC form. Any future authorized orchestrator
must run from a content-addressed immutable path that cannot be edited while executing, and must
repeat every live preflight.

## Replacement authorization

After the pre-workload stop, the Owner authorized exactly one replacement Gate D development pod
under the unchanged original envelope: one fresh GPU with at least 48 GB VRAM, at most three
additional GPU-hours, hard $3 additional provider spend after a new live quote, and at most two SFT
rounds. This is not open-ended retry authorization. The frozen source, data, runtime, candidate
selection, holdback, and thresholds do not change.

`ops/priority-6-v2/create_and_arm_pod.py` is the tested narrow replacement creator. Before launch,
its exact bytes and the exact-ID controller are copied to content-addressed paths and verified by
digest. It requires zero active pods, captures the full create ID, parses Prime's actual UTC form,
arms and verifies the persistent exact-ID deadline service, and terminates every exact ID
attributable to the unique requested name if any step is incomplete. No workload command exists in
this creator.

The first immutable remote driver invocation on the replacement pod stopped before host/model
preparation because its system unit ran as root while the preparation contract requires a non-root
user; its Python 3.10 terminal-record fallback also used the Python 3.11-only `datetime.UTC` alias.
No dependency install, model download, SFT, evaluation, candidate, or suite release occurred. The
Owner's explicit follow-up authorization permits one corrected same-pod driver invocation inside the
same three-hour/$3 envelope. It uses the existing exact pod/watchdog rather than another resource,
runs as the provider's non-root `ubuntu` user, and supplies a pinned supported Python 3.12.3 runtime.

The corrected invocation completed pinned Python/dependency installation, metadata retrieval, host
checks, and network-isolation preflight. It then stopped before loading a model because the driver
had created `run-output` for its own log while the runtime correctly refuses to overwrite any existing
output root. No source inference, SFT batch/round, visible evaluation, candidate freeze, or sealed
suite release occurred. Exact-ID cleanup terminated the pod after 20 minutes; Prime history raw cost
`1603` normalizes to $0.1603 and zero pods remain.

This lifecycle failure stopped the replacement/follow-up path. Gate F remains unused and ineligible.

## Additional attempt authorized and deferred

After reviewing the retained stop, the Owner authorized exactly one additional Gate D development
attempt under the unchanged envelope and directed that it begin only in a new session. No resource or
workload was started during that save/authorization session.

The new session may provision one fresh GPU with at least 48 GB VRAM for at most three GPU-hours,
hard $3 provider spend after a fresh quote, and at most two precommitted SFT rounds. It must use the
repaired driver (`23f907090e220035e51f821236e3bce8ea3fbdc51f61e790ed62bb6e0bcc50bb`), which keeps
lifecycle logs outside the non-overwriting runtime output root. Every content-address, exact-ID
watchdog, account, quote, payload, GPU, Python, detached-user, network-isolation, cleanup, and billing
preflight must be repeated from zero resources.

This authorization is for one additional Gate D attempt, not open-ended retries. A lifecycle or
readiness failure stops again. A conforming readiness pass activates the existing conditional Gate F
authorization without another prompt; it does not authorize deployment or publication.

## Gate F boundary

A conforming readiness pass activates the already authorized Gate F preparation, not deployment
or publication. Gate F still needs a fresh >=48 GB evaluator host, <=90 minutes, hard $1 quote,
sealed 128-case suite, separate evaluator UID/key/write authority, standard complete signed terminal
evidence, fresh Ledger/Gate, exactly one disposable shadow promotion, recovery/audit, retained
inventory, key/process/resource cleanup, and zero-resource/billing proof. A final miss permanently
closes this candidate without rerun or repair.
