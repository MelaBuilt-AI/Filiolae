# Public release checklist

Filiolae is pre-alpha. The canonical claim boundary is the
[`capability-and-gap matrix`](docs/capability-and-gap-matrix.md). A public source preview is ready only
when every preview-required item below has evidence; unchecked post-preview hardening items remain
explicit non-claims rather than silent blockers.

## Automated and repository-local

- [x] Locked Python environment (`uv.lock`).
- [x] Unit/integration suite, ≥80% aggregate coverage floor, Ruff lint/format, and package build.
- [x] Exact-SHA prime-rl patch apply-check and syntax compilation.
- [x] README, security boundaries, threat taxonomy, design, host integration guide, and GPU runbook.
- [x] sdist contains documentation, examples, tests, and the pinned patch; wheel contains all runtime modules.
- [x] CI workflow reproduces the checks above on Python 3.11/3.12 with full-SHA-pinned actions.
- [x] Build backend pinned; sdist allowlist/exclusions defined; repeated builds compared byte-for-byte.
- [x] Twine metadata check and fresh-environment wheel import/CLI smoke test.
- [x] Machine-readable technical surface audit (`scripts/release_preflight.py --scope technical`) checks
  links, Obsidian/private-machine leakage, obvious credential patterns, action pins, metadata bounds,
  and release documents; CI runs it.
- [x] Make `scripts/release_preflight.py --scope publication` pass with exact software/content license
  split, dual-licensing policy, adoption registry, CLA/trademark/certification documents, metadata,
  URLs, citation, reporting route, GitHub origin, claim-register, and public-surface checks.
- [x] After the separately approved visibility change, verify GitHub Private Vulnerability Reporting,
  run CI as a public observer, and retain the public workflow URL before announcement.

## Preview identity and policy

- [x] Use `MelaBuilt-AI/Filiolae` as the source-preview destination; private origin access is verified.
- [x] License software under AGPL-3.0-only and repository-authored documentation/evidence under CC BY
  4.0; offer commercial rights only through a separate executed agreement.
- [x] Document the non-waivable public registry condition for every commercial license and explicitly
  invite voluntary AGPL evaluation/adoption disclosures without claiming AGPL forces them.
- [x] Add the empty machine-readable adoption registry/schema, narrow contributor CLA, contribution
  acceptance statement, commercial inquiry/disclosure forms, trademark policy, and inactive
  certification boundary.
- [ ] Before accepting an external software Contribution, obtain qualified review of the CLA and
  verify the exact recorded-acceptance mechanism. Before issuing a commercial license, obtain qualified
  review of its agreement, rights chain, fee terms, and mandatory public-listing condition.
- [x] Add exact license/notice files, package metadata, Source/Documentation/Issues/Security URLs, and
  absolute README links that render from package indexes as well as GitHub.
- [x] Select GitHub Private Vulnerability Reporting as the exact security route and encode its URL.
- [x] Enable and verify that GitHub route immediately after visibility changes and before announcement;
  close/revert the gate if GitHub does not expose it.

## Phase 1 evidence gates

- [x] CPU happy/tamper/timeout/load-fault/process-supervision tests.
- [x] Governed launcher and exact Gate-owned path loading in CPU integration tests.
- [x] Execute and archive the pinned two-GPU reverse-text happy run; see
  [`docs/live-two-gpu-acceptance.md`](docs/live-two-gpu-acceptance.md).
- [x] Execute and archive the staged-artifact tamper run with zero post-tamper weight loads; see the
  same bounded acceptance record.
- [x] Validate the reference systemd/cgroup-v2 deployment with distinct witness/orchestrator UIDs and
  retained bounded evidence; see [`docs/native-systemd-containment-game-day.md`](docs/native-systemd-containment-game-day.md).
- [ ] Validate deterministic witness lost-response S5, real reboot persistence, GPU-device controls,
  and production hardening before claiming a production containment boundary.
- [x] Add required Ed25519-signed local Ledger-head checkpoints and offline verification.
- [x] Add an experimental Unix-socket witness/client, fixed shared-lock contract, explicit reviewed
  enrollment manifest, public-key mirror, same-UID integration tests, and bounded distinct-UID hosted acceptance.
- [ ] Retain receipts under an independently administered remote witness/WORM/transparency domain.
- [x] Add the digest/key-bound candidate shadow-evaluation control plane, deterministic CPU mock,
  distinct-UID CPU acceptance, and one bounded Priority 6 v2 real-model positive path.
- [ ] Execute a clean-room independent reproduction with a new candidate, suites, operators,
  credentials, hosts, evaluator/witness administration, and evidence custody.
- [ ] Validate versioned key rotation/revocation and M-of-N exact-promotion approval.
- [ ] Pass an isolated multi-witness/monitor split-view transparency exercise.

## Release mechanics

- [x] Select package version `0.1.0` and preview tag `v0.1.0`; add validated pre-alpha `CITATION.cff` metadata.
- [x] After the final private CI pass, replace the superseded private Apache candidate tag/draft with
  annotated `v0.1.0` at the exact AGPL candidate commit and record deterministic local artifact hashes.
- [x] Compare the final AGPL candidate's private-CI result and build checks with the local release
  manifest; no superseded Apache artifact remains attached to the draft.
- [x] Prepare release notes listing tested host SHAs, non-claims, migration/resume limits, and known risks.
- [x] After visibility approval, create the GitHub source-preview release from the frozen tag; do not
  publish to a package index in the same step.
- [x] Verify installation from the public release artifact in a fresh environment before announcement.
