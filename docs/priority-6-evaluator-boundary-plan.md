# Priority 6 evaluator-boundary audit and staged plan

Status: **Stage 1 separate-UID CPU acceptance passed; the authorized one-shot Stage 2 GPU
experiment failed its quality threshold; a post-hoc standard receipt/Ledger/Gate denial replay passed;
full live evaluator acceptance remains failed**

This plan turns the CPU-only control plane in
[`candidate-shadow-evaluation.md`](candidate-shadow-evaluation.md) into the smallest honest paired
source-versus-candidate experiment. It does not authorize an evaluator service, credential, model
or suite download, external write, paid compute, a quality claim, or promotion-authority change.

## P6.0 — implemented guarantee versus real-boundary gap

This table is the frozen **pre-implementation audit** that motivated Stage 1/Stage 2; its “remaining”
column is historical rather than the current project claim register. Current evidence and gaps are in
[`capability-and-gap-matrix.md`](capability-and-gap-matrix.md) and the execution sections below.

| Surface | Implemented guarantee | Code and direct tests | Remaining real evaluator/data-plane gap |
|---|---|---|---|
| Charter | A hard `candidate_shadow_evaluation` clause pins lowercase SHA-256 identities for evaluator bundle, suite, config, and source manifest; an Ed25519 key ID; quality/regression thresholds; and receipt age. Unknown/extra fields, booleans as integers, malformed ranges, soft policy, and duplicate policies fail loading. | `src/filiolae/charter.py:43-152`, `src/filiolae/shadow_eval.py:96-136`; `test_charter_rejects_soft_or_malformed_shadow_policy` | A digest names reviewed bytes; it does not prove those bytes executed. The final evaluator bundle and signer key do not yet exist and therefore are not yet Charter-pinned. |
| Configured assets | `PrimeRLEvidenceBuilder` content-addresses exactly four assets and refuses any digest map that differs from the Charter. Gate and audit repeat the exact artifact-name/digest check. | `prime_rl_entrypoint.py:47-140`, `gate.py:267-306`, `audit.py:313-342`; `test_cpu_mock_shadow_eval_allows_exact_digest_bound_candidate` | The governed process currently supplies these files. There is no independent evaluator startup measurement, read-only mount proof, or proof that the service used them. |
| Source identity | Policy and receipt bind an exact `source_policy_sha256` and source policy version. | `shadow_eval.py:25-53, 303-318`; happy-path and audit tests | `ShadowEvaluator.evaluate()` receives no source path. The mock never loads or hashes source weights. A real service must resolve and verify the source manifest and source bytes itself. |
| Candidate identity | The request binds the Gate-staged candidate tree digest and Ledger weights head. The mock recomputes the candidate path digest; Gate later compares pending bytes with the attested checkpoint. | `prime_rl_entrypoint.py:193-217`, `shadow_eval.py:255-261`, `gate.py:352-405`; `test_cpu_mock_refuses_candidate_bytes_that_contradict_request_digest` | Only the in-process mock performs the evaluator-side byte check. No remote request/package protocol exists. |
| Signed receipt | Canonical bounded JSON, exact fields/types, domain-separated Ed25519 signature, pinned signer/public key, run/attempt/step/source/candidate/config/head bindings, UTC completion time, and completed/error status are verified. | `shadow_eval.py:20-43, 151-230, 287-336`; parser, wrong-signer, stale, happy-path tests | The receipt carries aggregate scores only. It does not bind per-case outputs, case completion count, evaluator logs, host identity, or an execution attestation. Those must be retained and independently checked outside receipt v1. |
| Gate ordering | Candidate receipt must be the sole artifact on `candidate_eval.result`, immediately after `weights.published`, bound to its previous hash, and the current Ledger tail. Missing key/result, bad ordering, malformed receipt, failed status, low quality, excess regression, or stale/future time denies and freezes. | `gate.py:307-393`; missing, quality/regression/error, wrong-key, and stale tests | The production `_build_barrier()` explicitly rejects a Charter containing this policy. No real evaluator, public-key wiring, transport, timeout, or live prime-rl integration exists. |
| Offline audit | Audit requires the evaluator public key, rechecks control assets, ordering, signature, bindings, thresholds at approval time, and exact approval summary. | `audit.py:309-434`; `test_offline_audit_requires_and_reverifies_candidate_key` | No independently retained evaluator package exists yet. Audit verifies the signed aggregate, not the truth of inference or scoring. |
| Failure durability | Once Gate receives a deficient promotion request, it appends a tripwire and denial where possible, anchors, and freezes. | `gate.py:125-153`; fail-closed shadow tests | A synchronous evaluator exception/hang occurs inside `request_for_step()` before a `PromotionRequest` is returned. There is no bounded timeout, idempotent status lookup, lost-response reconciliation, or guaranteed Gate denial for that path. |
| Replay resistance | Receipt binds run, random attempt, step, candidate, evaluated Ledger seq/head, and freshness; Gate rejects reused step/attempt approvals. | `shadow_eval.py:303-322`, `gate.py:217-229`; mutation paths in shadow tests | A remote service has no request digest, one-shot allowlist, terminal-result store, or exactly-once retrieval semantics yet. |
| Real quality | None. The CPU mock supplies predetermined integers and verifies protocol flow. | `CPUMockShadowEvaluator`, `tests/test_shadow_eval.py` | No real source/candidate inference, deterministic held-out scoring, evaluator isolation, or quality/regression result has passed. |

### Engineering blockers before real inference

1. Replace the test-only synchronous seam with a bounded request/result adapter while preserving
   receipt v1 and Gate authority.
2. Make the evaluator independently verify source **and** candidate trees, suite, config, evaluator
   bundle, and one allowlisted request digest before inference.
3. Add timeout, crash, missing-result, and lost-response paths that always reach a durable Gate denial
   or recover the byte-identical terminal receipt—never silently retry or promote.
4. Wire only the Charter-pinned evaluator public key into Gate/audit; keep the private key outside the
   governed learner credential and host.
5. Retain complete per-case outputs and deterministic score recomputation because receipt v1 contains
   only aggregates.
6. Exercise a real model runtime under a separate evaluator credential/host. Until then, quality is
   unproven.

Actor strings in the Ledger are labels, not authentication. Likewise, `evaluator_sha256` is a
reviewed identity claim signed by the evaluator, not remote attestation. The bounded claim below
therefore depends on the tested separation, startup/preflight evidence, and independently reproduced
scores, not on those strings alone.

## P6.1 — smallest frozen paired experiment

The selected pair already exists in the preserved r18 happy archive, so no new training is needed.
It was chosen before running any paired evaluator:

- archive: `prime-a6000-20260811-r18-happy.tar`, size `6,021,683,200`, SHA-256
  `99dfa460d2ff1266ffb27183eae7988f866178b842c804a7862e983d047e3bde`;
- source: r18 step-1 promoted tree, policy version 1, Ledger seq 4, tree SHA-256
  `c047cbef4cca5dc09de95acd9f4a2ea884e8abd4f1e47dd34c2608165307c0c7`, size
  `1,503,300,328`;
- candidate: r18 step-2 tree, target step 2, Ledger seq 9, tree SHA-256
  `4bd8ca5cba086ff538f00f56fbd4ad9f241e05bc60e5307f976c63a81579473d`, same size;
- lineage: r18 run `22c750e2bb3742619cdfcd65f762dc6f`, Filiolae
  `9bbad47bf40a17d24273025bf85f09e867f82305`, prime-rl
  `60bc29547a8824ad1de7b9af8d265e2b27b2a72d`, and model snapshot
  `PrimeIntellect/Qwen3-0.6B-Reverse-Text-SFT@c97a910849ec6aa962add3dc253a0817d61c0210`.

Frozen in-tree inputs:

| Input | SHA-256 | Contract |
|---|---|---|
| `examples/candidate-eval/r18-step2-pair-selection-v1.json` | `f6be24ccd30c78e53ef75e4d0479521c90097b4c8ce129c2f584c8caaef26a88` | Exact preserved pair and provenance; explicitly retrospective shadow-only |
| `examples/candidate-eval/r18-step1-source-manifest-v1.json` | `3d70ada0ce838365e0f53692ec61349d844ede5cb7ac44fe1e802f26f6bb822e` | Exact source tree, model/tokenizer identity, and original Ledger provenance |
| `examples/candidate-eval/reverse-text-held-out-v1.jsonl` | `7d2a3c9edd04d6e75f5784ae7b686788ae515d524056a0d2895df354e3afc03d` | 128 deterministic synthetic cases, IDs 000–127, exact code-point reversals |
| `examples/candidate-eval/reverse-text-paired-config-v1.json` | `e911bb6d9f767b8baf67bba6410e77a1998f4cc18acd4cb41480b27facbae712` | Identical source/candidate prompting, inference, parsing, scoring, order, and thresholds |

The suite has 128 unique prompts, lengths 51–76, and zero exact overlap with the 1,000 prompts in
pinned training dataset commit `eacc9a0d76d9fd22e40008ab9d546008bdd7e432`. The sorted set of
SHA-256 training-prompt digests hashes to
`39976e1245ae5aefc3a123a2c207383d0db39f19e77956bb682fd7d9ae0c7a0a`. The candidate predates this
suite, but the suite is synthetic and disclosed—not a secret or general anti-leakage benchmark.

Each model runs in a fresh process, source first and candidate second, over cases in ascending ID
order. Inference is one greedy completion per case (`temperature=0`, `top_p=1`, seed 0,
`max_completion_tokens=128`, float16), no case retry, using the pinned `prime-qwen3` renderer and the
exact reverse-text system prompt. The first tagged response is stripped and compared exactly with
the frozen answer. Primary quality is `floor(10000 * exact_matches / 128)`; mean SequenceMatcher
ratio is diagnostic only. Any missing/duplicate case or runtime error produces status `error` with no
scores.

Precommitted Gate thresholds are:

- candidate quality at least **8,000 bps** (80% exact);
- source-to-candidate regression at most **79 bps** (at most one 128-case exact-match quantum); and
- receipt age at Gate no more than **1,800 seconds**.

The evaluator bundle digest and evaluator signing-key ID are intentionally blank until the
network-free implementation/rehearsal is reviewed. They must be frozen into a new hard Charter
before any real inference. Results must not be inspected and then used to change this pair, suite,
config, or thresholds.

## P6.2 — separation of authority

### Recommended bounded topology

1. **Owner/controller domain:** verifies and extracts the preserved r18 archive, builds the one-shot
   request, provisions/terminates the exact evaluator resource, retains the evaluator public key,
   retrieves evidence, and runs independent Gate/audit checks. Provider/API credentials remain here.
2. **Evaluator domain:** one fresh GPU host, different from the original learner host, with a dedicated
   non-root `filiolae-eval` credential. It receives only verified read-only model inputs, the frozen
   suite/config/source manifest, the reviewed evaluator bundle, and one allowlisted request. It has
   no learner, Gate, Ledger, cloud-provider, repository-write, or publication credential.
3. **Shadow Gate domain:** a fresh retrospective shadow Ledger on the Owner/controller side stages the
   exact candidate, records the signed receipt, and exercises Gate and offline audit. It grants no
   authority over the already-completed r18 run or any deployed model.

The evaluator signing key is generated after provisioning under the evaluator credential, mode
0600, never copied to the learner/controller, and removed during cleanup. Only its public key/key ID
is returned, reviewed, and pinned in the Charter. Inputs are staged by the controller, made read-only,
then the evaluator runs with `trust_remote_code=false`, no shell/repository token, no outbound
network, no writable input mount, a fresh output directory, bounded systemd/cgroup resources, and
only required GPU devices. Model source and candidate run sequentially in fresh processes.

For this one-shot acceptance, SSH with a controller-owned strict `known_hosts` file is the peer-auth
and transfer channel; the evaluator does not expose a learner-facing API. After staging, network is
disabled for inference. A future live service needs mutually authenticated transport, but that is
outside this retrospective bounded experiment.

### Request and terminal-result rules

- Canonical request binds run/attempt/step, source and candidate digests, all policy digests, evaluator
  key ID, evaluated Ledger seq/head, and a request digest.
- Evaluator preflight recomputes every byte identity and accepts exactly one allowlisted request.
- A terminal store is keyed by request digest. Repeated retrieval returns byte-identical evidence;
  the evaluator never re-evaluates a terminal request.
- A completed run signs one receipt only after 128/128 source and 128/128 candidate cases and score
  recomputation succeed. Partial output signs `status=error` with no scores when possible.
- On timeout/crash with no signed result, the adapter passes a missing result to Gate, which must
  durably deny/freeze. Unknown outcome is reconciled by request-digest lookup; it is never treated as
  success and never retried after result inspection.
- Learner/model bytes cannot select cases, alter code/config, read the key, edit results, suppress a
  terminal failure, or append to the shadow Ledger.

## P6.3 — threat and failure matrix

| Threat/failure | Required prevention/detection and result | Rehearsal/acceptance proof |
|---|---|---|
| Attest evaluator A, execute B | Read-only evaluator bundle is hashed before startup; process command/environment/package inventory are retained. Signer refuses a request whose evaluator digest differs. This is measured startup evidence, not hardware remote attestation. | Mutated bundle preflight fails; accepted run records bundle digest, argv, environment allowlist, package manifest, UID/cgroup. |
| Source/candidate swap or substitution | Evaluator recomputes both tree digests; request/receipt binds candidate and source manifest; Gate binds candidate to weights Ledger head. | Swap paths and one-byte/tree mutations fail before scoring; existing candidate-byte contradiction mutation remains green. |
| Suite/config mutation | Charter, configured Ledger event, evaluator preflight, request, and receipt bind exact digests. | One-byte suite and config mutations fail; no receipt or approval. |
| Selective examples / partial results | Frozen ascending 128-case enumeration; unique IDs; exactly one terminal output per source/candidate case; no retry; aggregate recomputed from retained cases. | Omit, duplicate, reorder, or truncate case output -> status error/no scores and denial. |
| Score or threshold manipulation | Deterministic scorer is in the evaluator bundle; full outputs retained; controller independently recomputes both aggregates; Gate applies Charter thresholds. | Alter aggregate/per-case output/Charter threshold -> signature, package, config, or Charter mismatch and denial/audit failure. |
| Wrong, leaked, or replaced key | Key ID and public key are Charter-pinned; private key is evaluator-UID-only, absent from environment/logs/evidence, and destroyed at cleanup. | Wrong-key receipt test; mode/ownership checks; evidence scan; a leak cannot be disproved, so no stronger claim is made. |
| Stale, future, or replayed receipt | Run/attempt/step/candidate/head/time bindings plus current-tail ordering and request terminal store. | Existing stale/wrong-attempt/head mutations; repeat retrieval must be byte-identical; replay into another run denies. |
| Evaluator crash/hang | Hard service and adapter deadlines; no promotion on missing terminal result; missing-result request reaches Gate denial/freeze. | Kill before source, between models, and before signing in CPU rehearsal; real GPU acceptance needs one bounded pre-sign kill/recovery drill without repeating inference. |
| Lost response / unknown outcome | Query terminal store by request digest. Existing receipt is recovered byte-for-byte; absent terminal result is failure. | Drop controller response after durable receipt, retrieve again, compare exact bytes, then Gate once. |
| Malformed output/receipt | Strict case schema, bounded canonical receipt parser, exact fields/types/signature. | Existing malformed receipt tests plus malformed case/result mutations deny. |
| Learner/model process escape | Evaluator is a separate host/credential with no learner secrets, no outbound network, read-only inputs, and bounded service/cgroup. `trust_remote_code=false`; weights are safetensors. | UID, mount, network, cgroup, process, device, and post-run cleanup evidence; this is bounded host isolation, not proof against kernel/GPU-driver compromise. |
| Post-result tampering or suppression | Signed receipt, content-addressed evidence package, Ledger artifact audit, independent copy/recompute, and controller retrieval before termination. | One-byte receipt/output mutation fails; terminal result presence is reconciled before any missing-result decision. |

Every uncertainty denies and freezes the shadow run; none grants promotion authority.

## P6.4 — staged acceptance and evidence contract

### Stage 0 — frozen local assets (completed in planning)

Pass requires generator/snapshot agreement, 128 unique self-consistent cases, canonical config and
manifests, exact recorded digests, and targeted existing shadow-control tests. This stage makes no
quality or isolation claim.

### Stage 1 — network-free implementation and two-credential CPU rehearsal

Implementation is complete for the bounded adapter, canonical request/terminal-store protocol,
source/candidate verification, exact code-bundle measurement, complete-output signed evidence and
independent scoring, timeout/crash/lost-response handling, and failure-to-Gate path. The exact r18
pair passed a process-separated same-UID CPU fixture rehearsal, including intentional lost-response
recovery. Targeted mutation/recovery tests pass. No model inference or quality claim occurred. See
[`priority-6-stage1-cpu-rehearsal.md`](priority-6-stage1-cpu-rehearsal.md).

**Stage 1 is not yet fully accepted.** The daily WSL host cannot create/use a disjoint UID without
privileged authorization: passwordless sudo is unavailable and unprivileged `setpriv` failed. A
different PID under UID 1000 is not a separate credential domain. Final pass still requires the same
rehearsal under distinct controller/evaluator UIDs on a privileged native host or private CI, with
private-key/write-authority and cleanup proofs. A push/run of this new implementation requires a
fresh Owner decision; the prior push authorization covered planning commit `35ab713` only.

### Stage 2 — real paired inference (fresh authorization required)

Provision one fresh 48 GB A6000-class GPU evaluator, stage and verify the pair and fully resolved
model snapshot, freeze the evaluator key ID/bundle/suite/config/source digests into the Charter, then
run source and candidate once each. Retain 128/128 outputs for each model and independently recompute
scores. Do not alter inputs/thresholds or retry cases after seeing results.

Pass requires candidate quality >= 8000 bps, regression <= 79 bps, exactly complete case sets,
byte-verified inputs, signed canonical receipt, and no runtime/preflight uncertainty. A threshold miss
is an honest failed experiment, not permission to tune and rerun.

### Stage 3 — Gate, recovery, retention, and cleanup

Append the receipt to the fresh shadow Ledger, require Gate decision, run independent audit with the
pinned public key, execute CPU mutation checks and the bounded lost-response/pre-sign crash recovery
case, package evidence, retrieve and verify it, terminate the exact provider resource independently,
and prove cleanup.

Retain at least:

- Owner authorization, exact cost/TTL, resource ID, controller/deadline/termination state;
- repository, Charter, evaluator bundle, dependency, model snapshot, source, candidate, suite, config,
  request, public-key, and command/environment digests;
- preflight; host/GPU/UID/cgroup/mount/network/process evidence;
- all source/candidate raw completions and per-case parsed/exact/LCS results;
- recomputed aggregate report, signed receipt, terminal-store metadata, Ledger, Gate decision, offline
  audit, and failure-drill reports;
- cleanup/termination proof, `PACKAGE.json`, `SHA256SUMS`, inventory, and an Owner-readable acceptance
  report with bounded claim/non-claims.

Evidence excludes the private signing key and provider/SSH credentials. Publication and transparency
submission remain unauthorized.

### Intended bounded claim

A pass would establish only that the exact preserved r18 step-1 source and step-2 candidate were each
evaluated once over the same frozen 128-case suite by the reviewed evaluator under the tested
separate host/credential boundary; that retained outputs reproduce the signed aggregate scores; and
that a fresh shadow Gate correctly consumed the exact signed receipt.

It would **not** retroactively make r18's original promotion quality-gated, prove live prime-rl
integration, general model quality or safety, benchmark secrecy/leakage resistance, evaluator
validity beyond this suite, trusted time, kernel/GPU-driver security, production isolation, deploy
or publication authorization, or authority to rerun after observing results.

## P6.5 — Owner execute/defer packet

### Recommendation

**Authorize pushing the local Stage 1 implementation to private `main` and run its bounded private-CI
separate-UID job; continue to defer Stage 2 paid inference.** The implementation and same-UID process
rehearsal closed the exception/timeout/source-verification/transport/complete-output gaps and froze
CPU evaluator bundle `a9bd47e2...fd3fb`. Only the distinct-credential acceptance remains open.

The prepared private CI job creates fresh controller/evaluator UIDs and a shared read-only result
boundary, keeps the evaluator private key unreadable to the controller, runs happy/lost-response and
crash-before-terminal cases, checks terminal results are unwritable by the controller, proves process
cleanup/key deletion, and uploads only a small summary. It uses no external evaluator service, model
download, paid/GPU compute, real inference, quality claim, Gate-authority change, or publication. The
push and hosted CI write require Owner's next explicit authorization.

After full Stage 1 passes, the proposed separate Stage 2 authorization packet is:

- **Resource:** one fresh 48 GB A6000-class evaluator GPU, >=20 GiB free disk, hard 90-minute TTL;
- **Budget:** expected 20–45 minutes and roughly $0.25–$0.60 using the prior campaign as a rough
  reference; hard provider-spend ceiling **$1.00** (price must be rechecked before approval);
- **External actions:** provision/terminate exact GPU resource, strict SSH upload/download, and—only
  if the preserved local inputs are insufficient—download the exact pinned model snapshot;
- **Credentials:** provider credential and SSH private key stay controller-side; one ephemeral
  evaluator Ed25519 private key stays evaluator-side; no learner/repository/publication credential;
- **Stop conditions:** any digest/key/host mismatch, extra GPU/process/network, timeout, partial case,
  missing/ambiguous result, threshold miss, evidence-copy failure, or cleanup uncertainty fails
  closed and still triggers exact-resource termination;
- **Residual risk:** no hardware attestation; Owner/cloud-root can control evaluator; GPU/kernel
  compromise not excluded; suite is small/synthetic/disclosed; result is retrospective shadow-only.

## Executed closure (2026-08-13)

Owner subsequently authorized the Stage 1 push/private-CI run and the precommitted Stage 2 paid GPU
experiment after CI green. Stage 1 passed at commit `48579ba` in private run `31719690665`, with
controller UID 999, evaluator UID 997, key/terminal authority separation, lost-response recovery, and
cleanup.

The frozen GPU attempt completed 128/128 source and candidate cases but failed: both exact-match
scores were 0 bps, so candidate quality missed the >=8,000-bps threshold. Diagnostic candidate mean
LCS was 6,325 bps versus source 2,819, but LCS was not the acceptance metric. The exact experiment is
closed and no rerun or retuning is authorized. The pod was recovered and terminated; zero Prime pods
remain. The operational TTL/cost incident and original runner protocol deviations are documented in
the retained recovery report.

Owner then approved a network-free negative-path replay. The new explicitly post-hoc replay importer
verified the original signed receipt and all retained completions, emitted Filiolae's standard receipt
and complete terminal evidence, and fed a fresh shadow Ledger/Gate. Gate denied for low quality,
appended `tripwire.fired` plus `gate.denied`, froze, and recorded no approval/promotion. Offline audit
passed with 9 records and 0 promotions. See
[`priority-6-stage2-posthoc-replay.md`](priority-6-stage2-posthoc-replay.md) and evidence package
`evidence/acceptance/candidate-eval-stage2-posthoc-replay-20260813/`.

This replay closes the standard fail-closed **negative path only**. It is not live inference or a
single separately credentialed end-to-end evaluator acceptance and does not retroactively repair the
GPU run. Full Priority 6 remains failed. No Prime pod is active; any new experiment requires a new
Owner decision and precommitment.
