# Changelog

All notable changes are documented here. Filiolae has not yet made a licensed public release.

## Unreleased

### Added

- Evidence-bounded AI-security landscape, promotion-integrity positioning, and a draft
  Filiolae-equivalence question set that explicitly preserves public-evidence and non-certification
  limits.
- AGPL-3.0-only public software route with separate commercial licensing, mandatory public listing for
  commercial licensees, voluntary AGPL adoption registry, narrow non-assignment contributor CLA,
  trademark policy, and an explicitly inactive v0.1.0 certification boundary.
- Fail-closed Charter, Ledger, artifact store, Promotion Gate, semantic audit, and freeze controller.
- Governed prime-rl v0.8.0 launcher/evidence builder and pinned fail-closed host patch.
- Held-exec POSIX process-group supervisor with TERM-to-KILL escalation.
- CPU happy, tamper, timeout, load-fault, and role-cleanup game days.
- Prepared two-GPU reverse-text filesystem profile and runbook.
- Fail-closed two-GPU acceptance automation for pinned payload construction, Ubuntu 22 bootstrap,
  happy/tamper campaigns, evidence collection, and exact-ID Prime pod termination backstops.
- Required Ed25519-signed local Ledger-head checkpoints, chained receipt verification, and Gate CAS binding.
- Experimental Linux Unix-socket witness/client with peer-UID restriction, fixed cross-credential
  Ledger lock, actual-head signing, and durable public-key-verified Gate mirror catch-up.
- Reproducible multi-Python CI quality, coverage, build, fresh-wheel, and exact-SHA patch checks.
- Bounded Owner-readable `filiolae explain` text/JSON reports with fail-closed history suppression.
- One-time explicit Unix-witness enrollment manifests, digest-bound genesis, and witness protocol v2.
- Opt-in signed candidate shadow-evaluation receipts with digest binding, quality/regression thresholds,
  offline reverification, and deterministic CPU mock tests.
- Provider-neutral static receipt-retention exports with deterministic namespaces/manifests, exact
  restore verification, and out-of-band key pinning; Priority 5 will use public transparency logs and
  independent monitors rather than a private Object Lock receipt sink.
- Network-free receipt-transparency primitives: disclosure-gated full receipt leaves, RFC 6962 Merkle
  roots/inclusion/consistency proofs, C2SP signed-note checkpoints, complete-mirror verification, and
  rollback/same-size-fork/inconsistent-growth detection, with a bounded interoperability architecture.
- Passed S1 offline dual-implementation interoperability with frozen synthetic Python/Go vectors,
  independently generated and verified proofs, independent signed-note verification, mutation tests,
  and bounded fuzz targets.
- Passed bounded S2 Tessera POSIX loopback acceptance with a strict synthetic-leaf personality,
  disjoint Filiolae/Python and independent Go complete monitors, restart/rebuild, truncated-resource,
  lost-response, immutable-conflict, SIGKILL recovery, checksummed evidence, and complete cleanup.
- Accepted bounded r18 preservation/recoverability evidence: successful 1,095-day AWS and B2 backup
  plans, fresh restores with identical logical inventories, and exact package verification. AWS Object
  Lock is enabled; B2 is explicitly retained but not immutable, and dual-cloud WORM is not claimed.
- Priority 6 one-shot candidate-evaluator filesystem protocol with independently verified source and
  candidate trees, exact executing-code bundle measurement, signed receipt and complete-output package,
  idempotent terminal recovery, timeout/crash failure handling, and durable evaluator-failure denial.
  Stage 1 separate-UID private-CI acceptance passed; the first frozen GPU attempt then failed its
  quality threshold, and a standard post-hoc negative-path Gate replay passed without new inference.
- Priority 6 v2 network-free positive-path design and canonical acceptance contract: disjoint training,
  development/readiness, and sealed-final controls; 95% readiness margin; unchanged final thresholds;
  separate development/final Owner gates; bounded cost/risk envelopes; and a controller-only external
  terminal adapter whose complete signed evidence is content-addressed and reverified by Gate/audit.
- Bounded Priority 6 v2 distinct-UID CPU fixture acceptance in private CI: controller UID 999 and
  evaluator UID 997; evaluator-owned key/request allowlist/terminal authority; exactly one Gate approval
  and disposable shadow promotion; valid 9-record audit; complete retained package and cleanup. This is
  protocol evidence only. The later one-use v2 readiness/final path supplied the separately bounded
  real-model result.

### Fixed

- Preserve the built wheel's valid distribution/version/tag filename in two-GPU payloads and bind that
  filename in the manifest, so remote `uv pip install` cannot reject a renamed `filiolae.whl`.
- Query MIG state through stable `nvidia-smi --query-gpu` fields, accepting explicit unsupported/N/A
  reports for non-MIG A6000s while still rejecting enabled or unrecognized modes.
- Validate prime-rl dry-run output at its actual `configs/orchestrator.toml` path before creating governed paths.
- Install the lock-pinned `flash-attn` extra required by prime-rl trainer imports, and prove the trainer
  import during remote preflight before any governed output paths are created.
- Bind Hugging Face's offline `refs/main` metadata to the fully verified model commit so prime-rl cannot
  miss the exact snapshot or resolve a different revision during its mandatory pre-download step.
- Install prime-rl's lock-pinned `disagg` extra and require its `vllm-router` executable during preflight;
  local inference cannot start without that router even though the smoke does not use disaggregated nodes.
- Pin, integrity-check, and offline-load the exact reverse-text dataset snapshot; bind its `refs/main`,
  prebuild the Datasets cache, and enforce `HF_DATASETS_OFFLINE=1` during dry-run and governed execution.
- Wait boundedly for a newly provisioned pod's exact `N/A` SSH status to become a validated endpoint;
  malformed endpoint strings still fail closed and the exact-ID guard still terminates on timeout.
- Prewarm the null-harness PEP 723 environment from a reviewed lock with bundled uv 0.11.8, verify an
  offline re-sync and launch, and reject runtime uv downloads through a manifest-bound exact-command shim.
- Bind supervision, audit, tamper injection, and evidence paths to prime-rl v0.8.0's resolved
  `OUTPUT/run_default` directory rather than the unresolved output root.
- Keep the critical weight watcher alive after the rollout loop drains until every expected filesystem
  checkpoint crosses the mandatory promotion barrier, or fail boundedly instead of reporting early success.
- Materialize each approved checkpoint as a verified disposable load copy, so weight consumers cannot
  mutate the Gate-owned content-addressed evidence master; remove the copy after the load outcome commits.
- Keep evidence preflight binding on the submitted output root while deriving audit/control paths from
  pinned prime-rl v0.8.0's resolved `OUTPUT/run_default` directory.
- Permit only the exact digest-pinned hatch-vcs fallback `_version.py` generated by frozen uv bootstrap,
  so the second offline profile can revalidate a reused VCS-less prime-rl source tree.
- Commit and anchor an integrity denial before exposing its freeze marker, preventing the external
  supervisor from terminating the Gate before `tripwire.fired` and `gate.denied` become durable.
- Omit redundant trainer optimizer checkpoints and convenience exports from full acceptance archives
  while retaining all governed artifacts, broadcasts, rollouts, configs, logs, receipts, and operator evidence.
- Record the tamper subprocess's actual nonzero return code under an explicit
  `governed_returncode` state field.
- Complete the bounded pinned prime-rl v0.8.0 two-A6000 happy/tamper acceptance campaign.

### Security boundaries

- No production containment, independently administered remote/WORM/transparency anchoring,
  independent reproduction, general model-quality result, or production evaluator deployment is
  claimed. Stage 1 CPU credential separation is bounded protocol evidence. Priority 6 v2 produced one
  narrow positive trained-candidate result whose candidate and suites are consumed and closed. See
  `SECURITY.md`, `docs/capability-and-gap-matrix.md`, and `RELEASE_CHECKLIST.md`.
