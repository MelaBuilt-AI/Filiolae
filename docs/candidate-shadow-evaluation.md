# Candidate shadow-evaluation control plane (CPU mock milestone)

Filiolae now has an opt-in hard Charter rule, `candidate_shadow_evaluation`, for signed candidate
quality/regression evidence. This is deliberately separate from `source_eval.result`, which remains
source-policy/run lineage evidence and must not be reinterpreted as candidate-quality proof.

The rule pins exact SHA-256 identities for the evaluator bundle, suite, and evaluation config; an
Ed25519 evaluator key ID; minimum candidate quality in basis points; maximum source-to-candidate
regression in basis points; and maximum receipt age. Unknown fields, booleans used as integers,
out-of-range thresholds, soft policies, and multiple candidate policies fail Charter loading.

For a configured run, `PrimeRLEvidenceBuilder` stages candidate weights first, creates the promotion
attempt ID, and asks a `ShadowEvaluator` for a signed canonical
`filiolae.candidate-eval-receipt.v1`. The receipt binds:

- run ID, attempt ID, source version, and target step;
- the exact candidate artifact digest and `weights.published` sequence/head;
- evaluator, suite, config, and exact source-policy manifest digests;
- completion time, status, candidate quality, and paired source quality.

The receipt is content-addressed as `candidate_eval_receipt` on an immediately following
`candidate_eval.result`. Test-only/mock evaluators may retain only that artifact. An evidence-bearing
external adapter additionally stages one exact `candidate_eval_terminal` directory containing the
request-keyed standard receipt and signed complete-output envelope. Gate and offline audit verify the
terminal signature, exact request binding, ordered case inventory, independently recomputed scores,
and byte identity with the Ledger receipt before accepting it; the approval records both artifact
digests. Missing, malformed, stale, wrong-key, failed, below-threshold, regressing, incomplete, or
mutated evidence permanently denies/freezes and grants no load authority. Omission of the public key
is an audit failure for a Charter that requires the receipt.

`CPUMockShadowEvaluator` exercises the aggregate-receipt path with deterministic integer scores.
`ExternalTerminalShadowEvaluator` is the controller-only production seam: it publishes one canonical
request, has no evaluator private key/source/config/fixture/worker command, polls an evaluator-owned
terminal store, and verifies complete evidence before returning the standard receipt. Network-free
fixtures prove this adapter-to-fresh-Ledger/Gate/audit path and exactly one disposable promotion;
private run `31742000291` additionally proves the bounded fixture path across distinct controller and
evaluator UIDs with retained cleanup evidence. They **do not** perform inference or prove model
quality. The first frozen GPU attempt failed quality and did not satisfy the full reviewed protocol.
Priority 6 v2 therefore remains pre-inference.

The closed original experiment and negative replay are documented in
[`priority-6-evaluator-boundary-plan.md`](priority-6-evaluator-boundary-plan.md) and
[`priority-6-stage2-posthoc-replay.md`](priority-6-stage2-posthoc-replay.md). The wholly new data,
candidate-development, evaluator, acceptance, cost, and separate-authorization contract is in
[`priority-6-v2-positive-path-design.md`](priority-6-v2-positive-path-design.md).
