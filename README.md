# Filiolae

**A fail-closed governance kernel for automated AI R&D.**

Filiolae binds a machine-readable Charter to a tamper-evident Ledger, content-addressed evidence,
and a policy-promotion Gate. The Phase 1 target is `prime-rl` v0.8.0 with its pinned `verifiers`
submodule. The governed learner never gets write authority over the Charter, Ledger, staged
checkpoint, or freeze control.

> Status: Phase 1 pre-alpha. The CPU governance game day, pinned `prime-rl` v0.8.0 two-A6000
> happy/tamper campaign, bounded native-systemd/cgroup-v2 separate-UID game day, and Priority 6
> Stage 1 separate-credential CPU acceptance passed. The first frozen real GPU evaluation honestly
> failed and remains closed. Priority 6 v2 subsequently passed its bounded one-use readiness and
> final real-model path: 256/256 readiness and 127/128 final exact, with one Gate approval and one
> disposable shadow promotion. See the [bounded acceptance report](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/priority-6-v2-acceptance.md).
> These are controlled experimental results, not a deployment, production, publication, general
> quality, or independent-reproduction claim.

## Why this exists

Automated AI R&D is becoming a real model-improvement loop: rollouts and evaluations feed training,
training publishes new weights, and those weights become the next policy. Filiolae enforces one
invariant:

> **The system being improved never controls the evaluator, the record, or its own shutdown path.**

The canonical current claim register is the
[`capability-and-gap matrix`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/capability-and-gap-matrix.md). The initial evidence taxonomy is in
[`docs/threat-taxonomy.md`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/threat-taxonomy.md); the full architecture is in
[`docs/design.md`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/design.md), the bounded live result is in
[`docs/live-two-gpu-acceptance.md`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/live-two-gpu-acceptance.md), and its bounded preservation and
fresh-restore result is in
[`docs/r18-preservation-acceptance.md`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/r18-preservation-acceptance.md).

## The gap Filiolae targets

Enterprise AI-security products increasingly discover AI assets, scan model files and data paths,
mediate prompts and tool calls, and red-team applications. Those controls are necessary, but they
usually answer a different question from Filiolae:

> **Before these exact candidate bytes become the next active policy, what exact evidence authorizes
> that transition—and can the system being improved forge or bypass it?**

Filiolae is an evidence-gated **promotion-integrity kernel** for that boundary. On its implemented
candidate-evaluator path, it binds candidate identity, evaluator material, precommitted policy,
signed results, and prior Ledger state; then it fails closed before the weight loader when that
evidence is missing, stale, replayed, malformed, or denied. Surrounding posture and runtime products
can supply useful signals, but they do not replace this model-transition control. Filiolae does not
replace their discovery, DLP, prompt filtering, model scanning, or fleet-wide agent security either.

This addresses a **publicly visible gap**. It is not a claim that frontier labs lack undisclosed
internal controls. Success can therefore take any of three forms: direct adoption of Filiolae,
evidence-backed disclosure of an equivalent control, or publication of a stronger independently
verifiable alternative. The public-interest objective is the control, not exclusive ownership of
its implementation.

See the evidence-bounded
[`AI-security landscape and Filiolae-equivalence profile`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/ai-security-landscape-and-equivalence.md)
for the layer comparison, source limits, and concrete questions an equivalent system should answer.

## Implemented kernel

- strict YAML Charter loading with duplicate-key and unknown-rule rejection;
- deterministic, domain-separated hash-chained JSONL Ledger with locked, fsynced appends;
- gate-owned content-addressed artifact staging for exact-byte promotion;
- structural and semantic offline audit plus bounded Owner-readable `filiolae explain` reports;
- fail-closed promotion checks binding run evidence, source version, target version, pending weights,
  Charter digest, and Ledger head;
- irreversible-in-process freeze semantics backed by both a marker and prior Ledger tripwires;
- a `PrimeRLPromotionBarrier` that returns a verified disposable copy of the staged weights and records load outcomes;
- a governed `filiolae-rl` launcher/evidence builder for patched prime-rl filesystem broadcasts;
- a held-exec POSIX process-group supervisor that reacts to freeze and escalates TERM to KILL;
- optional required Ed25519-signed Ledger-head checkpoints with strict offline verification;
- an explicitly enrolled experimental Linux Unix-socket witness that keeps the private
  key/authoritative receipts out of the governed orchestrator and mirrors verified receipts back;
- a deterministic static receipt-retention export/restore verifier plus Priority 5 transparency
  laboratory: full signed receipt leaves, RFC 6962 proofs, C2SP checkpoints, frozen Python/Go vectors,
  and a bounded Tessera loopback personality/two-monitor acceptance harness;
- an opt-in digest/key-bound candidate shadow-evaluation Gate plus a one-shot external evaluator
  filesystem protocol with exact source/candidate/code/suite/config verification, signed complete-output
  evidence, idempotent terminal recovery, timeout/crash handling, deterministic CPU fixtures, and a
  controller-only external-terminal adapter that content-addresses complete evidence for Gate/audit;
- CPU-only happy-path, tamper-path, timeout, load-fault, anchor-fault, shadow-eval, and process-tree
  game days.

## Quick start from a source checkout

The pre-alpha runtime is supported on Linux/POSIX with Python 3.11 or 3.12. No licensed package has
been publicly published yet.

```bash
uv sync --locked --group dev
uv run pytest

uv run filiolae demo .demo/happy --charter examples/charter.demo.yaml
uv run filiolae demo .demo/tamper --charter examples/charter.demo.yaml --tamper

uv run filiolae audit .demo/happy/control/ledger.jsonl \
  --artifact-root .demo/happy/control/artifacts \
  --charter .demo/happy/control/charter.yaml
uv run filiolae explain .demo/happy
```

The demo refuses to touch an existing path.

## prime-rl integration warning

`prime-rl` v0.8.0's `VersionObserver` **cannot block a policy update**: the stock watcher advances
version state before the hook and swallows hook exceptions. It is telemetry-only. Filiolae therefore
uses a separate mandatory authorization barrier in the same control flow as `update_weights`.
See [`docs/prime-rl-integration.md`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/prime-rl-integration.md), the
[`two-GPU smoke runbook`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/two-gpu-smoke-runbook.md), and the pinned reference patch in
[`adapters/`](https://github.com/MelaBuilt-AI/Filiolae/tree/main/adapters/).

## Security boundaries and current limitations

A local hash chain detects edits but cannot prevent full-chain rewrite or rollback. Filiolae now
supports required Ed25519-signed local checkpoints, but they become independent anchors only when the
key and retained receipts live in a separately protected witness domain. The external
supervisor must own the freeze marker and termination authority; deleting a local marker is not a
security boundary. The included POSIX supervisor is suitable for the CPU game day, but a process can
escape a process group with `setsid`; production requires a separate credential domain plus a cgroup
or service-manager kill boundary. Candidate-quality gating is enforceable only for Charters that opt into the signed shadow-eval
policy; `source_eval.result` alone still describes only source-policy/run lineage. Stage 1's
separate-credential CPU protocol rehearsal passed. The first frozen real paired attempt failed its
precommitted exact-match threshold and remains closed. Priority 6 v2 later produced one frozen trained
candidate and passed its bounded one-use readiness/final real-inference path, but that candidate and
both suites are consumed and closed. This is one narrow positive result—not independent reproduction,
general model quality, production evaluator security, or deployment evidence.

See [`SECURITY.md`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/SECURITY.md) for the threat boundary and non-claims, and
[`docs/signed-head-checkpoints.md`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/signed-head-checkpoints.md) for the signed-receipt protocol,
[`docs/unix-witness.md`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/unix-witness.md) for the cross-credential witness,
[`docs/receipt-retention.md`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/receipt-retention.md) for the Priority 5 static delivery contract,
[`docs/receipt-transparency.md`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/receipt-transparency.md) for the protocol audit, architecture decision,
privacy boundary, recovery model, and shadow-acceptance ladder,
[`docs/receipt-transparency-interop.md`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/receipt-transparency-interop.md) for the passed offline S1 evidence,
[`docs/tessera-loopback-shadow-plan.md`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/tessera-loopback-shadow-plan.md) and
[`docs/tessera-loopback-shadow-acceptance.md`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/tessera-loopback-shadow-acceptance.md) for the passed bounded S2 result,
[`docs/owner-explain.md`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/owner-explain.md),
[`docs/candidate-shadow-evaluation.md`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/candidate-shadow-evaluation.md), the
[`Priority 6 evaluator-boundary plan`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/priority-6-evaluator-boundary-plan.md), the
[`Stage 1 CPU rehearsal record`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/priority-6-stage1-cpu-rehearsal.md), and the
[`Stage 2 post-hoc fail-closed replay`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/priority-6-stage2-posthoc-replay.md), and the
[`Priority 6 v2 positive-path design`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/priority-6-v2-positive-path-design.md).
The clean-room [`independent-reproduction protocol`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/independent-reproduction-protocol.md),
[`operational-hardening plan`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/operational-hardening-plan.md), and
[`public-preview readiness plan`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/public-preview-readiness-plan.md) define the next gates.
Publication evidence and release mechanics are tracked in
[`RELEASE_CHECKLIST.md`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/RELEASE_CHECKLIST.md); the
prepared [`v0.1.0 source-preview notes`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/public-preview-release-notes.md)
list exact carried-forward evidence and non-claims.

## Licensing, contributions, and adoption

Filiolae software is available under **AGPL-3.0-only**. MelaBuilt AI may offer a separate commercial
license to organizations needing rights incompatible with AGPL. Every executed commercial license
must carry a narrow public adoption-registry entry; there is no confidential-licensee exception.
Commercial rights are granted only by a separate signed agreement.

Repository-authored documentation, policy, adoption-registry content, and evidence are generally
licensed under **CC BY 4.0**. Software contributors retain copyright and accept a narrow CLA granting
the Project Steward the rights needed to maintain the public AGPL edition and offer commercial terms.
The CLA is not a copyright assignment.

AGPL users are explicitly invited to disclose evaluation, research, pilots, deployment, or
discontinuation through the public registry. Registration is voluntary for the AGPL route and
mandatory for commercial licensees. Neither registration nor commercial licensing means
certification, endorsement, production readiness, or an expanded security claim. No certification
program is active for v0.1.0.

See [`LICENSES.md`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/LICENSES.md),
[`COMMERCIAL-LICENSING.md`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/COMMERCIAL-LICENSING.md),
[`ADOPTION.md`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/ADOPTION.md),
[`CLA.md`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/CLA.md), the
[`licensing decision`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/licensing-decision.md),
[`licensing FAQ`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/docs/licensing-faq.md), and the
[`trademark policy`](https://github.com/MelaBuilt-AI/Filiolae/blob/main/TRADEMARKS.md) for exact terms
and boundaries.
