# Priority 6 Stage 2 post-hoc Gate replay

Status: **bounded negative-path replay passed; Priority 6 remains failed**

Owner approved the network-free Option 2 on 2026-08-13: import the already retained real GPU
completions into Filiolae's reviewed receipt/Ledger/Gate/audit path without performing new inference
or changing the observed experiment.

## Result

The replay evaluator independently verified the original custom Ed25519 receipt, original signer,
source/candidate output hashes, complete ordered 128-case sets, exact source/candidate/suite/config
bindings, recomputed per-case parsing/exact/LCS values, aggregate scores, and the original
`threshold-failed` status. It then signed a standard `filiolae.candidate-eval-receipt.v1` plus complete
`filiolae.paired-eval-evidence.v1` terminal result under a fresh replay-only key.

A fresh shadow run consumed that standard receipt. The Gate denied authorization because candidate
quality was 0 bps, durably appended `tripwire.fired` and `gate.denied`, created an irreversible freeze,
and recorded no approval or promotion. Offline governance audit passed:

`Governance audit valid: 9 records, 0 promotion(s)`

Key bindings:

- original receipt SHA-256: `b010d27b4ae3f1bd6645a7052d0d390a0ad2aacf5f192907bd6f2ad62c8ad179`
- completion replay package SHA-256: `39db7e17941f71e0cf513873aac983129e8ef1d1e5c4c1c937b686dcee03cb08`
- standard receipt SHA-256: `9a22b968b66ac31d55f9d44a9f8738331d55ac1d1c5c7244a32992be14a7768a`
- replay evaluator signer: `sha256:63a55cf017ae800dbf01260e543e9ca717cb62f9b7c45b82c69cf96272b6b1fe`
- source tree: `c047cbef4cca5dc09de95acd9f4a2ea884e8abd4f1e47dd34c2608165307c0c7`
- candidate tree: `4bd8ca5cba086ff538f00f56fbd4ad9f241e05bc60e5307f976c63a81579473d`
- source/candidate quality: 0/0 bps; decision allowed: false

## Retention and verification

This small package retains the frozen suite/source manifest, canonical replay package and config,
exact replay evaluator bundle, original-completion provenance inside the replay package, standard
request/terminal receipt/complete evidence, fresh Charter, Ledger, freeze marker, replay public key,
summary, and audit result. `PACKAGE.json` inventories every retained file and `SHA256SUMS` provides
the package root. The full local run, including the Gate-owned candidate artifact copy, remains
in the private replay workspace outside this repository; its machine-specific path is intentionally
omitted.

The original GPU signing key was already deleted and is not present. The replay evaluator private key
was deleted after audit and is not present. No external service, network write, paid compute, GPU,
model inference, model training, threshold change, or rerun was used.

## Bounded claim and non-claims

This establishes that Filiolae can import the retained real failed completions into its standard
signed terminal protocol and that a fresh Ledger/Gate/audit path correctly denies and freezes on the
precommitted quality miss. It is explicitly post-hoc replay evidence.

It is **not** a new/live evaluation, does not retroactively repair the original GPU runner, does not
combine Stage 1's separate-UID proof with this same-UID replay into a single live-isolation claim, and
does not authorize promotion, deployment, publication, retuning, or another GPU run. Priority 6 as a
full live evaluator claim remains failed.
