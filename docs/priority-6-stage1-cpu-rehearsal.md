# Priority 6 Stage 1 CPU protocol rehearsal

Status: **bounded separate-OS-credential CPU acceptance passed in private CI; no model-quality
claim**

This milestone is network-free and makes no model-quality claim. It implements and exercises the
transport and evidence boundary required before any real paired inference.

## Implemented boundary

`filiolae.paired_eval` now provides:

- a canonical, bounded one-shot request binding the existing receipt request and Charter policy;
- independent source-tree verification against the pinned source manifest and candidate-tree
  verification against the request;
- an evaluator-owned, non-writable one-request digest allowlist before any terminal lookup or signing;
- exact evaluator-bundle self-measurement covering the worker and its security-critical Filiolae
  modules, plus suite/config/source-manifest digest verification;
- strict frozen-suite/config/scorer reconciliation, complete ordered case-output enforcement, bounded
  completions, deterministic exact-match and diagnostic LCS recomputation;
- domain-separated Ed25519 signatures over both receipt v1 and the complete-output evidence package;
- an atomic content-addressed terminal store keyed by request digest;
- byte-identical idempotent retrieval after a lost response, without reevaluation;
- hard controller timeout and explicit crash/no-terminal failure;
- independent controller verification of terminal signatures, request bindings, every completion,
  parsed result, exact flag, LCS diagnostic, and aggregate score; and
- an evaluator-unavailable marker in `PrimeRLEvidenceBuilder`, ensuring evaluator exceptions still
  produce a complete promotion request that reaches durable Gate denial/freeze.

The worker is available as `filiolae-candidate-evaluator`; the reproducible no-quality rehearsal is
`scripts/run_candidate_eval_cpu_rehearsal.py`. `cpu-evaluator-bundle-v1.json` must exactly match the
executing modules or preflight fails. The private evaluator key is never included in retained evidence.

## Mutation and recovery coverage

Targeted tests cover:

- happy complete-output scoring and receipt verification;
- lost response after durable terminal commit followed by byte-identical recovery;
- worker crash and timeout before terminal commit;
- source-tree substitution;
- incomplete case output producing a signed `status=error` receipt with no scores;
- post-result complete-output tampering rejected by its separate evidence signature; and
- evaluator exception → builder unavailable marker → Gate tripwire/denial → irreversible freeze.

Existing shadow-control tests continue to cover malformed receipts, wrong signer, stale/future
receipt, missing evidence, low quality, excessive regression, failed status, Gate summary binding, and
no-key offline audit failure.

At the local preparation checkpoint, 251 tests passed at 83.62% aggregate coverage along with Ruff,
format, lock, technical preflight, evaluator-bundle/suite regeneration checks, evidence
checksum/signature re-verification, byte-reproducible wheel/sdist builds, Twine, and a fresh Python
3.11 wheel/CLI smoke. The separate-UID private-CI job was still unexecuted at that historical
checkpoint; the final acceptance section below records its later successful run.

## Executed r18 process rehearsal

The accepted small package is
`evidence/acceptance/candidate-eval-stage1-20260813/`; its `SHA256SUMS` digest is
`85372cb022989f513c4fc9d3de5990c88e70bcd001ef3c8d2849fc4af4e40dd9`.

The worker rehashed the exact preserved pair:

- source: `c047cbef4cca5dc09de95acd9f4a2ea884e8abd4f1e47dd34c2608165307c0c7`;
- candidate: `4bd8ca5cba086ff538f00f56fbd4ad9f241e05bc60e5307f976c63a81579473d`;
- evaluator bundle: `a9bd47e20e3a16c26063280254ed4db03d3e4d3d0afc47e3000dc7c9b3bfd3fb`;
- request: `19b3d07f9fdb1d79db9fcc9164810d3c513f4238dc35ad34b3fb480f0fa06eef`;
- signed receipt: `b7489cdff235fa3f3df23e1bcc8b028671a1a3046b6cf6ab86be6c06da4c91b8`.

All 128 source and candidate fixture outputs were complete and recomputed to 10,000 bps with zero
regression. The worker intentionally exited nonzero after terminal commit; the controller recovered
and verified the result. These numbers come from generated exact-answer CPU fixtures and are **not
model outputs, inference, or quality evidence**.

## Honest credential boundary

The controller was PID 55812/UID 1000 and the worker PID 55813/UID 1000. This proves process and
transport behavior only. It does not prove separate OS authority. The daily WSL host has no
passwordless sudo; unprivileged `setpriv` could not transition to UID 65534. We did not weaken the host
or call a same-user namespace a separate credential.

The terminal protocol supports an evaluator-owned setgid/shared-read result directory and a
controller that knows the evaluator private-key **path** without needing read/stat authority over the
key. At the pre-execution checkpoint, final Stage 1 acceptance required one privileged/native or
private-CI rehearsal in which:

1. controller and evaluator have distinct UIDs;
2. only the evaluator can read the mode-0600 private key and write the terminal store;
3. the controller can write the request but cannot alter terminal results;
4. both can read only the frozen inputs required for the run;
5. the signed evidence records distinct evaluator/controller UIDs;
6. happy, lost-response, crash/timeout, mutation, Gate denial, and cleanup checks pass; and
7. no key, process, writable work directory, or listener remains.

## Final separate-credential acceptance

Owner authorized the push and private-CI run. After isolated-runtime portability fixes, private
Actions run `31719690665` passed all jobs at commit
`48579ba1987a9d8966c75437036e711a74483d18`. The evaluator job recorded controller UID 999 and
evaluator UID 997, controller-unreadable private key, evaluator-owned mode-0400 exact-request
allowlist, controller-unwritable terminal output, successful lost-response recovery, and cleanup.
The small CI summary artifact was retained during Stage 2 recovery.

This closes only Stage 1's bounded CPU protocol/separate-credential claim. It does not turn the local
same-UID fixture scores into model evidence or establish a live GPU evaluator boundary. The later
Stage 2 result and post-hoc fail-closed replay are documented in
[`priority-6-stage2-posthoc-replay.md`](priority-6-stage2-posthoc-replay.md).
