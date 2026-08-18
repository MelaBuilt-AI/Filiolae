# Receipt transparency architecture decision

Status: **S1 offline interoperability and bounded local S2 acceptance passed; external deployment remains unauthorized**

Date: 2026-08-13

## Decision

Filiolae will use a public, interoperable, RFC 6962-style append-only Merkle log as the shared
receipt evidence plane. The protocol substrate is:

- **RFC 9162 Merkle hashing and inclusion/consistency proof semantics**;
- **C2SP `tlog-checkpoint` v1.0.0** checkpoints carried as **C2SP `signed-note` v1.0.0**;
- the static **C2SP `tlog-tiles`** read model as the intended interoperability target;
- **C2SP `tlog-witness` v1.0.0** and timestamped witness cosignatures as the intended witness seam.

The reference deployment candidate is **Tessera**, with a thin Filiolae receipt personality.
Tessera is a Go library rather than a protocol dependency; conformance is defined by public bytes,
checkpoints, proofs, monitor behavior, and test vectors. **Sigstore Rekor v2** is retained as an
operational reference for Tessera/tile-backed logs and self-contained verification bundles, not as
the primary API: its `hashedrekord` personality does not preserve Filiolae's full canonical leaf as
its natural entry type. **Sigsum** is retained as the best reference for explicit log/witness trust
policies and offline proof verification, but its deliberately narrow key-usage leaf is not the
Filiolae leaf. **SCITT (RFC 9943/RFC 9942)** is an important future message/receipt bridge; adopting
COSE now would duplicate the already signed Filiolae receipt and broaden this first slice.

This decision changes neither `filiolae.ledger-head-receipt.v1` nor the Unix witness v2 protocol.
It adds a separate transparency envelope and is not promotion authority.

## Protocol audit

| Candidate | Useful properties | Fit and decision |
|---|---|---|
| RFC 9162 / Certificate Transparency v2 | Standard domain-separated Merkle tree, minimal inclusion and append-only consistency proofs, mature monitor model | **Adopt cryptographic tree semantics.** CT leaf and HTTP APIs are certificate-specific, so do not adopt its application schema. |
| C2SP signed-note + tlog-checkpoint | Small interoperable signed checkpoint: origin, size, RFC 6962 root; unknown signatures enable log-key rotation and witness cosigning | **Adopt checkpoint wire format.** Extension lines are omitted because generic monitors cannot audit their meaning. |
| C2SP tlog-tiles | Static cacheable entries/tiles; clients compute proofs; simple mirroring and cheap independent operation | **Target for deployment.** Local slice computes equivalent proofs directly; tiled HTTP serving comes later. |
| C2SP tlog-witness / witness network | Witness remembers the last checkpoint, verifies log signature and consistency proof, returns a timestamped cosignature; interoperable public network | **Adopt as the future cosigning seam.** Local code verifies log checkpoints and growth but does not implement HTTP or claim witness time. |
| Tessera | Production-ready Go library, POSIX/AWS/GCP backends, tlog-tiles, witness support, log personalities | **Preferred reference implementation.** Do not port or vendor it into the Python governance kernel. Build a thin personality only after shadow acceptance. |
| Rekor v2 | Tessera-backed public-good signature log; tiled immutable resources, verified checkpoints, inclusion bundles, planned/available witnessing | **Operational reference, not primary personality.** Rekor validates its own entry types and has sharding/TUF policy useful to study later. |
| Sigsum | Ed25519-only, explicit log/witness policy and witness quorum, offline verification and active monitors; designed against log/key compromise | **Trust-policy reference.** Its checksum/key-hash leaf is too narrow for full Filiolae receipt bytes. |
| SCITT RFC 9943 + COSE receipts RFC 9942 | Standards-track, content-agnostic signed statement registration and portable VDS receipts | **Future bridge.** It does not itself choose the monitor/gossip/witness deployment, and a COSE migration is too broad for this compatibility slice. |
| Custom centralized database or object-lock sink | Easy implementation or deletion resistance | **Rejected.** Neither provides public append-only interoperability plus independent split-view detection; Owner also chose transparency-only for receipts. |

## Canonical public leaf

Schema: `filiolae.receipt-transparency-leaf.v1`.

The leaf is canonical JSON plus one newline and contains exactly:

```json
{
  "receipt_b64": "<exact filiolae.ledger-head-receipt.v1 bytes>",
  "schema": "filiolae.receipt-transparency-leaf.v1",
  "signer_public_key_b64": "<raw 32-byte Ed25519 key>",
  "witness_enrollment_sha256": "<lowercase digest or null>"
}
```

Properties and rationale:

1. **Full receipt bytes, not only a hash.** A complete mirror can preserve and independently inspect
   every public receipt without depending on MelaBuilt AI or an adjacent object store.
2. **Public verification material.** The exact signer public key accompanies the receipt, while the
   receipt's existing `signer_key_id` binds it. Trust policy still decides whether that signer is
   authorized; embedding a key is not self-authentication.
3. **Private enrollment stays private.** Unix-witness receipts require only the SHA-256 commitment
   already enrolled in the Ledger. Path-bearing enrollment JSON is excluded.
4. **No extra operational metadata.** The receipt already exposes `run_id`, sequence, signed time,
   Ledger head, signer, and cadence. The leaf adds no hostname, filesystem path, account, evaluator,
   model, prompt, artifact, or Charter content.
5. **Disclosure review is mandatory.** Current v1 receipts can expose human-selected run IDs and
   activity timing. The builder requires an explicit `disclosure_reviewed=True`; no existing receipt
   is safe to publish merely because it is cryptographically valid. Future public runs use random
   opaque IDs that do not encode project, person, host, customer, or experiment purpose.

Merkle leaf hashing is `SHA-256(0x00 || exact_leaf_bytes)`; interior hashing is
`SHA-256(0x01 || left || right)`. Leaf order is the log-assigned order, not receipt `anchor_seq`.
Multiple independent log operators may include the same leaf.

## Checkpoints, proofs, and bundles

A log checkpoint is a three-line C2SP checkpoint body (`origin`, decimal tree size, base64 root),
signed with Ed25519 in C2SP signed-note form. Log configuration pins origin, key name, public key,
validity/shard window, and accepted witnesses outside the checkpoint.

A portable proof bundle will eventually contain:

- the exact leaf and log index;
- a verified log checkpoint;
- the minimal inclusion proof or the tile material required to derive it;
- witness cosignatures satisfying a versioned trust policy;
- optional cross-log inclusion evidence and an external trusted timestamp.

The local implementation provides leaf validation, RFC 6962 roots, inclusion proofs, consistency
proofs, C2SP Ed25519 checkpoint signing/verification, complete-mirror verification, same-size fork
detection, rollback detection, and append-only checkpoint updates. S1 additionally verifies frozen
synthetic vectors in both directions with pinned Transparency.Dev Go Merkle and `sumdb/note`
implementations; see [the interoperability report](receipt-transparency-interop.md). It deliberately
does **not** call an HTTP endpoint, publish data, assert trusted time, or create Gate authority.

## Independent monitor, mirror, gossip, and cross-log model

No one service is "the Filiolae log." A production log set must include independently operated logs
and monitors. Each monitor:

1. pins the log origin/key/shard policy and last accepted checkpoint;
2. verifies every new log signature and append-only consistency proof;
3. downloads every entry (or immutable tiles), reconstructs the root, and validates each Filiolae
   receipt signature and enrollment commitment shape;
4. retains complete leaf bytes, checkpoint history, and proofs independently;
5. exchanges signed observations with other monitors over at least two administrative/network paths;
6. publishes an alarm if the same origin and tree size have different roots, growth lacks a valid
   consistency proof, entries are unavailable beyond policy, or a checkpoint rolls back.

Witness policy is explicit and versioned, following the useful Sigsum pattern: require a threshold
from distinct administrative failure domains, not merely several keys run by one organization.
Witnesses synchronously check consistency before cosigning. Checkpoint gossip supplies defense in
depth and exposes different checkpoint views to monitors.

For **cross-logging**, a primary checkpoint signed by the log and witness quorum becomes a leaf in a
separately operated secondary log. Monitors verify both inclusion and consistency and alarm on:

- a primary checkpoint observed directly but missing from the secondary beyond the maximum merge
  delay;
- two different primary roots at the same origin/size;
- a secondary rollback, inconsistent growth, or unavailable leaf/tile;
- a checkpoint advertised to a client but absent from complete independent mirrors.

The secondary log must not share operator, cloud account, signing authority, DNS control, or monitor
quorum with the primary. Cross-logging is evidence amplification, not a substitute for monitors.

## Fork detector and recovery

### Machine states

- `healthy`: signatures, inclusion, complete mirror, consistency, and policy quorum pass.
- `pending`: merge/witness/cross-log delay is inside a bounded policy window; never called final.
- `suspect`: unavailable proof/tile/checkpoint or exceeded maximum merge delay.
- `forked`: valid same-origin/same-size checkpoints have different roots, or growth is
  cryptographically inconsistent.
- `retired`: an explicitly frozen shard whose final checkpoint has passed retirement acceptance.

### Evidence and response

A fork alarm is a self-contained packet with both signed checkpoints, log verifier policy, failing
or absent consistency evidence, first/last observation times (clearly local unless independently
timestamped), monitor signatures, and cross-log references. Monitors retain and replicate it.

On `forked`, publication clients quarantine the log and stop treating new proofs as accepted.
Filiolae Gate behavior is **unchanged** in this phase: transparency remains shadow-only, so a public
log failure cannot silently approve or deny promotion. Operators preserve both views, rotate only
through a signed policy update, and create a replacement shard/log. Recovery requires:

1. public root-cause and affected-range statement;
2. complete reconciliation of all leaves from every mirror/view;
3. inclusion of the reconciliation statement and old terminal checkpoints in independent logs;
4. new log keys/origin or explicit shard identity, independently distributed trust policy;
5. adversarial replay proving the old fork cannot be hidden;
6. Owner approval before any future delivery-coupled Gate policy.

Key compromise is not "fixed" by deleting history. Old checkpoints and fork evidence remain public.

## Privacy and data minimization

Public transparency is intentionally irreversible and observable. It can reveal identifiers, times,
sequence/cadence, signer relationships, and the existence of governed activity. Hashing private data
alone may still enable dictionary or correlation attacks. Therefore:

- publish only the canonical leaf above after a documented disclosure review;
- require opaque random future run IDs and review every pre-existing receipt individually;
- never publish raw witness enrollment, paths, usernames, hostnames, account IDs, prompts, model
  contents, artifacts, private Charter clauses, or full Ledgers in this plane;
- keep MSP360 or an adopter-selected compliant system as the pluggable full-evidence preservation
  plane; transparency does not replace recovery storage;
- define retention and redaction expectations before public launch: append-only public leaves cannot
  promise deletion, so sensitive bytes must never enter them;
- treat publication timing and batch size as metadata; optionally batch/delay within a declared
  maximum merge delay, without claiming a trusted event time from the receipt's `signed_at`.

## Shadow-publication acceptance ladder

All stages use synthetic or explicitly disclosure-approved receipts.

### S0 — local deterministic conformance (implemented)

- independent RFC 6962 known vectors and exhaustive non-power-of-two sizes;
- inclusion/consistency proof round trips and bit-tamper rejection;
- C2SP checkpoint byte snapshot, origin/key/signature verification;
- exact receipt-byte round trip and wrong-key/signature/noncanonical rejection;
- complete-mirror, rollback, inconsistent-growth, and same-size-fork rejection.

### S1 — dual-implementation offline interop (passed)

- frozen seven-leaf vectors match pinned `transparency-dev/merkle` leaf hashes, roots, independently
  generated inclusion/consistency proofs, and verification in both languages;
- the frozen checkpoint verifies through pinned Go `sumdb/note` and Filiolae;
- deterministic Python mutations and bounded Go fuzz targets reject parser/proof tampering;
- complete evidence and reproduction commands are in
  [the S1 interoperability report](receipt-transparency-interop.md).

### S2 — private local shadow log (passed bounded acceptance)

- the [Tessera loopback shadow plan](tessera-loopback-shadow-plan.md) pinned Tessera v1.0.4 and was
  executed after Owner's separate authorization with synthetic leaves and ephemeral IPv4 loopback only;
- disjoint Filiolae/Python and independent Go complete monitors passed baseline, restart/rebuild,
  partial-resource, lost-response, immutable-conflict, SIGKILL recovery, evidence, and cleanup cases;
- the [S2 acceptance report](tessera-loopback-shadow-acceptance.md) records final size 16, exact root,
  evidence checksum, same-UID/process-isolation limit, pre-acceptance correction, and non-claims;
- every S2 process/listener stopped and the synthetic operational private key was removed. No external
  receipt disclosure, persistent service, witness, public retention, or Gate coupling occurred.

### S3 — isolated witness and split-view game day

- separate credentials/process domains for log, at least three witnesses, two-of-three quorum, two
  monitors, and an independent secondary log;
- inject equivocation, withheld entries, rollback, stale checkpoint, corrupted tile, witness outage,
  monitor partition, and cross-log omission;
- require alarms and preserved self-contained evidence within stated bounds.

### S4 — disclosure-reviewed private-network shadow

- use only synthetic or Owner-approved receipt bytes; perform privacy inventory and log-set policy
  review; exercise key/shard rotation and retirement; verify restore from independent mirrors.

### S5 — public canary (requires separate Owner authorization)

- publish a synthetic canary to reviewed public services; no historical/private receipt by default;
- validate independent external observation, witness quorum, cross-log evidence, and recovery runbook;
- document costs, operators, jurisdictions, retention, and incident contacts.

### S6 — delivery coupling (explicitly deferred)

Only after sustained canary operation, threat review, independent assessment, and a separate Owner
decision may Gate require a transparency delivery acknowledgement. The coupling must define bounded
fail-closed/fail-open emergency authority, prevent log operators from becoming unilateral promotion
authorities, and remain reversible through a signed, audited policy change.

## Current security and authorization boundary

Implemented code is a **local protocol laboratory**, not a transparency service. S1 proves offline
byte interoperability with maintained independent Go libraries, not independent operation. S2 exists
as bounded local acceptance source/evidence only; no listener remains. Filiolae makes no claim of
third-party observation, trusted time, witness quorum, public retention, global non-equivocation, or
independent operation. The repository now contains bounded S2 loopback personality/monitor source, but
no persistent service or CLI publication command. No public submission, external account, operational credential, provider write, paid compute, repository publication, or
Gate coupling is authorized by this decision or implementation.

## Sources audited

- RFC 9162, Certificate Transparency Version 2.0: <https://www.rfc-editor.org/rfc/rfc9162>
- C2SP signed-note v1.0.0: <https://c2sp.org/signed-note@v1.0.0>
- C2SP tlog-checkpoint v1.0.0: <https://c2sp.org/tlog-checkpoint@v1.0.0>
- C2SP tlog-tiles v0.1.0: <https://c2sp.org/tlog-tiles@v0.1.0>
- C2SP tlog-witness v1.0.0: <https://c2sp.org/tlog-witness@v1.0.0>
- Tessera README/status and architecture: <https://github.com/transparency-dev/tessera>
- Rekor v2 README/client notes: <https://github.com/sigstore/rekor-tiles>
- Sigsum documentation and trust-policy walkthrough: <https://www.sigsum.org/docs/>
- RFC 9943, SCITT Architecture: <https://www.rfc-editor.org/rfc/rfc9943>
