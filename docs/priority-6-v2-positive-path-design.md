# Priority 6 v2 positive-path design and decision packet

Status: **Gate D development/readiness and conditional Gate F final execution are Owner-authorized
inside the exact bounded envelopes below; deployment and publication remain unauthorized**

This packet defines a wholly new experiment intended to earn a credible positive-path Priority 6
result. It does not reopen or repair the r18 Stage 2 experiment. That exact source/candidate run
remains permanently threshold-failed at 0/128 exact, while its later hosted replay proves only the
standard fail-closed negative path.

Machine-readable invariants are frozen in
[`examples/priority-6-v2/acceptance-contract-v1.json`](../examples/priority-6-v2/acceptance-contract-v1.json)
(SHA-256 `4bbb86cd2e0d3312a0f1794a57b53970a1dd67e2bd6e4a0604b28cb2af2d3c6c`). The contract deliberately
contains no final-suite plaintext, seed, answer, candidate digest, evaluator key, or execute authority.

## 1. Bounded objective and non-claims

The objective is to show that one genuinely new candidate, derived from one pinned source, passes one
sealed 128-case exact-reversal evaluation under a separate evaluator credential; that Filiolae
consumes the evaluator's standard signed receipt and signed complete evidence through a fresh
Ledger/Gate; and that exactly one disposable shadow load is approved, recorded, audited, recovered,
and cleaned up.

A pass would not prove general model quality or safety, production isolation, hardware attestation,
benchmark-leakage absence, trusted time, public deployment readiness, or permission to publish. The
shadow promotion cannot affect a production or historical policy. The model must perform reversal;
a wrapper, renderer, parser, postprocessor, retrieval component, or case-specific router may not
compute or substitute the answer.

## 2. Architecture and authority boundaries

### 2.1 Candidate-development domain

This domain may hold the source checkpoint, training data, development data, trainer, development
inference runtime, and a development-only experiment key. It may not receive the final suite seed,
plaintext, answers, evaluator private key, final terminal-store write authority, Gate authority, or
publication credentials. It emits one immutable candidate tree plus provenance and dependency
manifests. Candidate selection ends when that tree digest is frozen.

### 2.2 Final-suite custodian/evaluator domain

A separate credential—and for final acceptance a fresh separate host—is the sole custodian of the
sealed suite and ephemeral Ed25519 private key. It owns a reviewed, digest-pinned evaluator bundle,
request allowlist, read-only source/candidate/config inputs, and terminal-result store. It has no
trainer, repository-write, provider-control, learner, deployment, or publication credential.

The evaluator accepts exactly one canonical request digest. It independently hashes source,
candidate, bundle, suite, config, and source manifest; runs source and candidate sequentially in
fresh inference processes; retains every ordered raw completion and parsed score; recomputes
aggregates; then atomically commits the standard receipt and signed complete terminal evidence.
A terminal request is never evaluated twice. Repeated lookup returns byte-identical files.

### 2.3 Acceptance controller and fresh shadow Gate

The controller knows provider/resource identity and may stage immutable model artifacts, but it does
not know the evaluator private key or final-suite plaintext before candidate freeze. After the
candidate is frozen and final execution is separately authorized, it receives the suite/evidence for
independent recomputation, verifies the pinned public key and terminal package, and appends the
standard receipt and complete evidence to a fresh content-addressed shadow Ledger.

The fresh Gate applies the precommitted thresholds. If allowed, it exposes only the staged candidate
to one disposable shadow loader. One `policy.promoted` outcome must follow the single approval, after
which the loaded process and staging area are destroyed. A denial, malformed/missing result, load
failure, ambiguous outcome, timeout, or audit uncertainty freezes the run and creates no authority.

### 2.4 Concrete process, key, write, network, and recovery controls

| Boundary | Required control and retained proof |
|---|---|
| OS/process | Distinct controller/evaluator UIDs; evaluator service in its own cgroup; exact argv, PID/UID/GID, cgroup, descendants, limits, and exit retained. Candidate and source run in fresh sequential child processes. |
| Key | Evaluator generates mode-0600 Ed25519 key under its UID. Controller receives only public key/key ID. Private key is absent from argv/environment/logs/package and deleted after verified retrieval. |
| Inputs | Source, candidate, evaluator bundle, suite, config, and source manifest are regular, no-symlink, read-only artifacts whose digests match the one request and Charter. No mutable model cache is shared between source/candidate runs. |
| Writes | Evaluator alone writes terminal output. Controller/learner cannot alter or suppress it. Gate alone writes Ledger, artifact store, freeze state, approval, and load outcome. Candidate process has a fresh scratch directory only. |
| Network | Provisioning/staging uses a strict allowlisted controller channel. Inference has outbound network disabled and no repository/provider credentials. Network state before, during, and after is retained. |
| Lifecycle | Exact resource ID, independent watchdog proof, hard TTL, process deadline, detached controller, and exact-resource termination are established before any paid workload. Foreground SSH is never the lifecycle authority. |
| Recovery | Lost response triggers lookup by request digest, never inference retry. A durable terminal result is recovered byte-identically; no terminal result by deadline is a permanent failed attempt. |
| Audit | Independent signature, artifact, per-case, aggregate, Ledger, Gate, load-outcome, inventory, and cleanup checks run from retained bytes. |

Actor strings and filesystem ownership are evidence, not remote attestation. Cloud root, kernel, and
GPU-driver compromise remain outside the bounded claim.

## 3. Three disjoint data classes

The old observed v1 suite and its outputs are excluded from all v2 training, development evaluation,
model selection, and prompt tuning.

### 3.1 Training data

Generate at least 50,000 unique labeled examples from a versioned generator specification spanning
the accepted character/length domain. Freeze generator code, root commitment, exact count, prompt
hash inventory, answer rule, renderer, tokenizer, and split manifest before training. Training may
use labels and repeated epochs. Every prompt digest must be absent from both development and final
inventories.

### 3.2 Development suite

Use 512 visible iterative cases plus a 256-case readiness holdback. The visible suite supports error
analysis and bounded model iteration. The readiness holdback is revealed only after a candidate is
frozen. A readiness miss converts that holdback into ordinary development data; further work requires
a fresh, disjoint, precommitted holdback and a newly frozen candidate. This prevents repeatedly
selecting against one nominal holdback.

Request final-acceptance authorization only if the frozen candidate has complete ordered outputs,
at least **244/256 exact (>=9,500 bps)** on the current readiness holdback, and regression versus the
pinned source of at most **39 bps** (one 256-case quantum). The visible suite should also remain at
least 90% exact. Readiness is evidence of margin, not final acceptance.

### 3.3 Sealed final suite

A custodian outside candidate development generates exactly 128 cases from the frozen domain
specification using fresh secret entropy. Before candidate development completes, only a signed
commitment, case count, generator digest, domain digest, and custody record may leave that domain;
no seed, prompt, answer, length sequence, or plaintext inventory may be disclosed.

After training and readiness pass, the candidate digest is frozen and the final Charter/request are
constructed. Only then may a separately authorized final evaluator unseal the suite. It checks all
three prompt-hash inventories are pairwise disjoint before inference. Any overlap, early access, suite
regeneration, selective case removal, or candidate change invalidates the attempt. The terminal suite
is never reused for another candidate.

## 4. Candidate-development plan

1. **Offline contract checks:** prove renderer/parser agreement, label construction, token budgets,
   Unicode/code-point policy, no truncation, deterministic dataset generation, split disjointness,
   and that only model tokens—not host code—produce the tagged answer.
2. **New SFT candidate:** start from one pinned source checkpoint and train on the new training class.
   Preserve optimizer/scheduler, seed, package, hardware, command, dataset, and checkpoint manifests.
   Do not use the r18 candidate as the v2 candidate.
3. **Visible development:** run the pinned source and each candidate with the same inference config.
   Diagnose only visible development failures. Precommit a small maximum number of training rounds
   before development compute begins.
4. **Readiness freeze:** choose one candidate without viewing the current holdback, hash its exact
   tree, then evaluate source/candidate once on the holdback. A miss returns to development and burns
   that holdback; a pass freezes candidate, source, tokenizer, renderer, runtime, and config.
5. **Owner final packet:** present candidate/readiness evidence, exact resource/watchdog plan, final
   commitments, costs, and residual risks. Final-suite unsealing and inference require a new decision.

Recommended first development hypothesis is supervised fine-tuning rather than more RL: exact
character reversal and tag discipline have direct labels, while the failed candidate's diagnostic
partial similarity did not satisfy exact match. RL may be proposed only after SFT development evidence
and as a separately precommitted bounded round; it is not the default way to rescue a miss.

## 5. Production external evaluator adapter

The production seam is a one-shot request-inbox/terminal-store adapter, not an in-process scorer. The
controller publishes only canonical `filiolae.paired-eval-request.v1` bytes and verifies its local
candidate digest. A separately operated evaluator resolves pre-staged content by digest and commits
`filiolae.candidate-eval-receipt.v1` plus
`filiolae.paired-eval-evidence.v1` under the request digest. The controller has no evaluator key,
fixture, source path, config path, or runner command.

`ExternalTerminalShadowEvaluator` implements this controller seam. It verifies complete signed
terminal evidence and independently recomputes scores before returning the standard receipt to the
fresh Ledger/Gate builder. Missing or invalid terminal state raises an evaluator-unavailable error;
the builder still supplies Gate a durable error marker so denial/freeze occurs. Existing CPU fixture
workers remain explicitly rehearsal-only and are not the production inference implementation.

The fresh evidence builder now content-addresses the exact one-request terminal package beside the
standard receipt. Gate and offline audit independently verify its signature, request binding, complete
ordered outputs, recomputed scores, and receipt identity. A local same-UID fixture reached exactly one
disposable promotion and valid audit; this is control-plane evidence only, not credential separation
or quality evidence.

## 6. Phased validation ladder

### V2.0 — design and invariant assets (current, network-free)

Pass: Owner-readable packet and canonical contract agree; no sealed plaintext/seed or execute
authority exists; old failure boundaries and thresholds remain unchanged.

### V2.1 — external adapter and mutation tests (locally passed, network-free)

Local tests pass canonical request publication; no private evaluator inputs in the controller adapter;
signed complete-terminal recovery; independent score recomputation; candidate/request substitution,
receipt/output/signature mutation, missing result, timeout, duplicate retrieval, extra-file rejection,
and lost response fail closed or recover byte-identically.

### V2.2 — fresh Ledger/Gate acceptance runner (bounded distinct-UID fixture passed)

Private GitHub Actions run `31742000291` passed the v2 job at exact source commit
`7ae0e0708d2fd12e49797133fd7cc866874fdbfa`. Controller UID 999 and evaluator UID 997 were distinct;
the evaluator owned a mode-0400 request allowlist and private key, the controller could not read the
key or write terminal evidence, and cleanup retained no key or evaluator process. The exact signed
terminal package was content-addressed beside the standard receipt; Gate independently verified it,
approved exactly once, loaded one disposable shadow candidate, recorded exactly one promotion, and
offline audit passed with 9 records/1 promotion.

The downloaded 35-file package passed its complete inventory. Its `SHA256SUMS` digest is
`3c86d2b6239d0e9969db6a074b17e91fc1da9aa7c4afd02729a104327d853d11`; it is retained under
`evidence/acceptance/priority-6-v2-distinct-uid-fixture-20260813/`. CPU completions remain fixtures,
not inference or quality evidence. Existing network-free mutation/recovery tests cover missing
complete evidence, crash/timeout, lost response, substitution, tampering, and extra files.

### V2.3 — candidate development (new Owner execute/defer decision)

Pass: provenance-complete new candidate and the 244/256 readiness gate. No final-suite access. Stop
at the precommitted round, time, and cost ceilings.

### V2.4 — one-shot final acceptance (new Owner execute/defer decision)

Pass requires all of the following without retry or redefinition:

- candidate >= **8,000 bps**, therefore at least **103/128 exact**;
- source-to-candidate regression <= **79 bps**;
- 128/128 ordered outputs for both source and candidate;
- exact pinned source/candidate/bundle/suite/config/runtime/provenance;
- valid standard receipt and signed complete evidence, independently recomputed;
- tested distinct evaluator credential, key and terminal write separation;
- exactly one fresh shadow Gate approval, exactly one disposable promotion/load outcome;
- lost-response recovery, offline audit, evidence inventory, key/process/resource cleanup; and
- independent watchdog and exact-resource termination proof.

A threshold miss or ambiguous terminal state closes that candidate's final attempt. It does not
permit a rerun, new seed, threshold change, suite filtering, or candidate repair.

## 7. Compute, cost, and risk envelopes

These are planning envelopes, not current authorization or provider quotes.

| Phase | Proposed envelope | Cost planning bound | Principal stop conditions |
|---|---|---|---|
| Offline/data contract | Daily WSL CPU, sequential targeted tests | no paid resource | memory floor, nondeterminism, split overlap, renderer/tokenizer mismatch |
| Development SFT + dev inference | One fresh >=48 GB GPU, at most two precommitted training rounds, <=3 GPU-hours total | expected roughly $1–$2; propose hard **$3** ceiling after live quote | watchdog absent, digest/dependency mismatch, OOM, time/cost ceiling, incomplete provenance |
| Readiness holdback | Same bounded development authorization if explicitly included; one frozen candidate | included only if Owner packet says so | early holdback access, candidate mutation, incomplete cases, <244/256 |
| Final acceptance | One fresh >=48 GB evaluator GPU, <=90 minutes, one candidate and one suite | expected roughly $0.25–$0.75; propose hard **$1** ceiling after live quote | any preflight/isolation/watchdog mismatch, partial output, ambiguity, threshold miss, evidence or cleanup failure |

The old Stage 2 resource exceeded its authorized TTL because no independent watchdog existed. Any
future paid resource must first have a detached, independently verified exact-resource termination
watchdog that survives this agent session, SSH, and controller failure. No workload starts until its
kill target, deadline, credentials, and test termination are proven.

Residual risks include disclosed task/domain overfitting, a small synthetic final suite, evaluator or
cloud-root control, no hardware attestation, kernel/GPU compromise, stochastic runtime drift despite
greedy configuration, and a readiness-to-final distribution gap. The 95% readiness margin reduces
but does not eliminate the last risk.

## 8. Separate Owner decision gates

### Gate D — authorized bounded execution

Owner explicitly authorized the exact development envelope on 2026-08-13. The executable packet is
[`priority-6-v2-gate-d-execution.md`](priority-6-v2-gate-d-execution.md). It freezes source, runtime,
50,000 training cases, 512 visible cases, a separately custodied one-use 256-case holdback, at most
two SFT rounds, one >=48 GB GPU, <=3 GPU-hours, and a hard $3 provider-spend ceiling. A live quote,
exact-ID watchdog, host/network preflight, detached workload, evidence, and cleanup remain fail-closed
prerequisites rather than waivable paperwork.

### Gate F — conditionally authorized one-shot execution

Owner also authorized Gate F in advance without another prompt, but it becomes executable only after
a conforming Gate D result of >=244/256 exact, >=9,500 bps, <=39-bps regression, and complete
outputs. Every final suite, evaluator, separate credential/key/write domain, fresh host, current price,
watchdog, evidence, and one-shot preflight must still match exactly. Its envelope remains one fresh
>=48 GB evaluator GPU, <=90 minutes, and hard $1. Any miss or ambiguity closes the candidate.

## Current execution state

V2.1 and bounded distinct-UID V2.2 pass. Gate D preparation is active under the Owner-approved packet;
the old r18 failure remains closed. Gate F must not start unless the frozen new candidate first passes
the one-use readiness holdback and every final preflight. Deployment, production promotion,
publication, public release, threshold changes, observed-v1-suite tuning, and r18 reopening remain
unauthorized.
