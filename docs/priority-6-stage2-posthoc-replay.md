# Priority 6 Stage 2 post-hoc fail-closed replay

Status: **bounded negative-path replay passed; full Priority 6 live evaluator acceptance remains failed**

## Why this exists

The authorized one-shot Stage 2 GPU experiment retained complete source/candidate outputs and a valid
custom signed receipt, but the candidate missed its frozen exact-match threshold and the GPU runner
did not use Filiolae's reviewed receipt/Ledger/Gate/audit path. Owner approved a network-free repair:
import the already observed outputs without new inference, score or threshold changes, and prove that
the standard governance path denies and freezes.

## Replay importer

`filiolae.paired_eval_replay` and `filiolae-candidate-replay-evaluator` add an explicitly post-hoc
lane. The Charter-pinned replay config binds the canonical replay package, original custom receipt,
original signer, original config and status. The worker independently verifies:

- original Ed25519 signature and custom signing domain;
- original source/candidate/suite/config/source-manifest bindings;
- complete ordered retained rows and their exact output-file hashes;
- every completion's parsing, exact flag, and diagnostic LCS value;
- both aggregate scores, regression, and threshold status; and
- exact executing replay bundle, standard one-shot request allowlist, candidate/source trees, and
  standard replay signing key.

It emits the existing standard `filiolae.candidate-eval-receipt.v1` and signed complete
`filiolae.paired-eval-evidence.v1` terminal package. It performs no inference.

## Executed result

`scripts/run_candidate_eval_posthoc_replay.py` created a fresh shadow run over the exact retained pair.
The standard receipt reported source/candidate quality 0/0 bps. Gate authorization returned false
with `candidate quality is below the Charter threshold`, then durably appended `tripwire.fired` and
`gate.denied`, froze the run, and recorded zero approvals/promotions. Independent offline audit passed:

`Governance audit valid: 9 records, 0 promotion(s)`

Retained package:
`evidence/acceptance/candidate-eval-stage2-posthoc-replay-20260813/`.
Its `SHA256SUMS` digest is
`a38551fb45ccaf04d2a8f4d496b0ed4d8da6ba770fc7e89ea3034c45a305077f`.
The original and replay evaluator private keys are absent.

## Bounded claim

This proves the retained real failure can be imported into Filiolae's standard signed terminal
protocol and that a fresh Ledger/Gate/audit path correctly fails closed. It is not new/live inference,
not a same-run combination with Stage 1's separate-UID proof, and does not retroactively repair the
original GPU runner. It grants no promotion, deployment, publication, retuning, or rerun authority.
