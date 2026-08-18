# Filiolae v0.1.0 public source preview — release notes

Status: **frozen v0.1.0 pre-alpha source-preview notes; live publication state is authoritative on GitHub**

Filiolae v0.1.0 is an inspectable pre-alpha source preview of a fail-closed governance kernel for
automated AI R&D. It is intended for review, CPU reproduction, protocol experimentation, and
adversarial feedback—not production deployment.

## Included

- strict machine-readable Charter and tamper-evident, semantically audited Ledger;
- content-addressed Gate-owned artifacts and exact-path promotion authorization;
- durable freeze/denial behavior and a held-exec process supervisor;
- Ed25519 Ledger-head receipts, explicit Unix-witness enrollment, and a separate-credential reference
  deployment;
- static receipt retention plus RFC 6962/C2SP/Tessera interoperability laboratory;
- candidate-evaluator request/terminal protocol, signed complete evidence, recovery, and Gate binding;
- threat taxonomy and threat-to-test matrix;
- bounded acceptance reports, claim register, clean-room reproduction protocol, and consequence-ranked
  operational-hardening plan;
- an evidence-bounded AI-security landscape and draft Filiolae-equivalence profile, with explicit
  limits on market, independence, and certification claims.

## Exact bounded evidence carried forward

- Pinned `prime-rl` v0.8.0 source: `60bc29547a8824ad1de7b9af8d265e2b27b2a72d`.
- Two-A6000 happy/tamper acceptance tested Filiolae `9bbad47bf40a17d24273025bf85f09e867f82305`.
- Native systemd/cgroup-v2 distinct-UID acceptance tested `35529fec51727d360a77b41f56a19134cde94d80`.
- Priority 5 S1/S2 receipt-transparency evidence is documented with exact vector/package hashes.
- Priority 6 Stage 1 distinct-UID CPU acceptance passed at `48579ba1987a9d8966c75437036e711a74483d18`.
- Priority 6 v2 bounded final result passed at `3062d524020ada4ff15247730e2a53ee9ecd5339`;
  preservation/claim reconciliation continues through the preview candidate.

See the [`capability-and-gap matrix`](capability-and-gap-matrix.md) for exact evidence classes and
links. Earlier plans/attempt records are historical; they are not stronger current claims.

## Important non-claims

This preview is not production software, a security certification, deployment approval, or support
commitment. It does not establish:

- independent reproduction or general model quality;
- production evaluator, witness, cgroup, GPU-device, or root/admin containment;
- independent public transparency, trusted time, witness quorum, or global split-view resistance;
- accepted key rotation/revocation or multi-party promotion;
- reboot persistence, complete monitoring/rollback operations, or unattended reliability;
- WORM/immutability for every retained provider copy.

The accepted Priority 6 v2 candidate and its readiness/final suites are consumed and closed. They are
not included as reusable development inputs and must not be tuned, rerun, or represented as fresh
evidence. The repository suite-seed secrets were deleted and the retained custodian workflow is
unconditionally inert; provider-backup deletion is not claimed.

## Known operational risks

- JSONL outcome recording cannot be atomic with an external weight load; ambiguous states freeze and
  require reconciliation.
- Local receipts resist editing only to the extent their key/store and independent copies are protected.
- The POSIX process-group supervisor is not hostile-child containment; use the separately credentialed
  systemd/cgroup design and revalidate it on the exact host.
- Transparency S2 is a loopback laboratory under one host/UID, not independent observation.
- Every runtime, adapter, topology, credential, or policy change invalidates the matching bounded
  integration evidence until fresh-site reacceptance.

## Compatibility and migration

- Python: `>=3.11,<3.13`; Linux/POSIX.
- Package/API stability is not promised at v0.1.0.
- Existing Ledgers, receipt v1 chains, enrollment objects, and transparency leaves have strict schemas;
  do not rewrite them to migrate. Preserve original bytes and build explicit versioned import/transition
  tooling for any future schema.
- Stock `prime-rl` v0.8.0 `VersionObserver` is telemetry-only. The exact pinned fail-closed patch and
  mandatory promotion barrier are required for that integration.

## Security reports

Use GitHub Private Vulnerability Reporting at
<https://github.com/MelaBuilt-AI/Filiolae/security/advisories/new>. Do not publish sensitive exploit
details in an issue or discussion.

## Licensing and public adoption

Software: AGPL-3.0-only, with separately executed commercial licensing available from MelaBuilt AI.
Repository-authored documentation, policy, adoption-registry content, and evidence: CC BY 4.0 unless
marked otherwise.

Every commercial license will require a narrow public adoption-registry entry with no confidential-
licensee exception. AGPL users are invited to report evaluation/adoption voluntarily; AGPL itself is
not represented as forcing public notice of every internal evaluation. Contributors retain copyright
under the narrow CLA needed to maintain public AGPL and commercial editions. No v0.1.0 certification
program exists, and neither licensing nor registration expands the preview's security claims. See the
root licensing, commercial-licensing, adoption, CLA, trademark, and certification policies.
