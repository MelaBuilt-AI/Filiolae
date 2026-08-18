# Receipt-retention export (Priority 5, static first slice)

> The transparency protocol decision and implemented local primitives now live in
> [`receipt-transparency.md`](receipt-transparency.md). This document remains the static full-chain export
> and fresh-restore contract; it is not the public leaf format.

Filiolae can now turn a verified current Ledger-head receipt chain into a deterministic, provider-neutral
static package. The package is the local handoff between the existing Unix witness protocol and a future
public transparency-log adapter. It does **not** change `filiolae.ledger-head-receipt.v1`, witness
request/response v2, Gate CAS behavior, or the signed bytes.

This is deliberately a local/static first slice. Exporting or restoring the package does not prove that a
transparency log included it, that independent monitors observed one consistent history, or that signer
equivocation was exposed.

## Owner architecture decision: transparency only

The Priority 5 retained-receipt backend will be a public, interoperable transparency protocol—not an AWS
S3, Backblaze B2, or other private Object Lock sink. Filiolae is intended as globally adoptable security
infrastructure; outside monitors, public consistency evidence, and fork visibility are part of its trust
model rather than optional add-ons.

MSP360's independently verified AWS/B2 backups remain the preservation path for full Ledgers, artifacts,
large model evidence, source bundles, and private enrollment material. Priority 5 has a different job: make
the small signed governance receipts publicly observable and make conflicting histories difficult to hide.
No second Filiolae-managed object-storage system is planned for receipts.

## Why this boundary

The accepted separate-UID witness keeps its private key and authoritative receipts away from the governed
orchestrator, but same-host root or witness compromise can still delete the Ledger and both receipt views.
Independent observation needs a different failure and administrative domain. A log-submission identity, if
the chosen log requires one, must not enter the orchestrator, Gate, learner, or witness signer. Submission
credentials convey no receipt authority: receipt authenticity continues to come from the enrolled Ed25519
key.

The first implementation solves the byte contract before choosing or implementing a transparency log:

1. lock and verify one current Ledger/authoritative-store snapshot;
2. preserve every canonical receipt byte and filename unchanged;
3. retain the canonical witness enrollment and public key as evidence (the bundled key is **not** the trust
   root);
4. create a canonical manifest with exact object hashes, sizes, receipt sequence, current Ledger head, and a
   stable opaque object prefix derived from run/signer/enrollment identity;
5. verify a fresh restore against the Ledger and a separately supplied, out-of-band public key.

## Export and restore verification

For the native-systemd reference deployment, use its fixed Ledger lock:

```bash
filiolae retention-export \
  /srv/filiolae/runs/RUN/control/filiolae/ledger.jsonl \
  --artifact-root /srv/filiolae/runs/RUN/control/filiolae/artifacts \
  --ledger-lock /run/filiolae/RUN/ledger.lock \
  --anchor-dir /var/lib/filiolae-witness/RUN \
  --public-key /etc/filiolae/ed25519-public.pem \
  --witness-enrollment /var/lib/filiolae-witness/RUN/enrollment.json \
  --output /secure/export/RUN-retention
```

The output directory must not already exist. The command requires a fully valid receipt chain anchored at
the current Ledger head. Unix-witness exports require the explicit enrollment, and the enrollment must
match the Ledger path/run/Charter/signer tuple committed in genesis.

The JSON result includes:

- `manifest_sha256`: domain-separated identity of the canonical manifest;
- `object_prefix`: stable provider-neutral namespace for this run/signer/enrollment tuple;
- `manifest_object_key`: append-only name for this exact exported head;
- `provider_retention_verified: false`: an intentional non-claim.

After a fresh restore, verify with an independently retained public key:

```bash
filiolae retention-verify \
  /fresh/restore/RUN-retention \
  /fresh/restore/run/control/filiolae/ledger.jsonl \
  --artifact-root /fresh/restore/run/control/filiolae/artifacts \
  --ledger-lock /fresh/restore/run/control/filiolae/ledger.lock \
  --public-key /independent/trust/ed25519-public.pem
```

Supplying the bundle's own `public-key.pem` can check internal consistency, but it cannot establish signer
identity after joint substitution. An acceptance verifier must pin the expected key ID out of band.

## Static package format

`RETENTION-MANIFEST.json` is canonical JSON with one trailing newline and schema
`filiolae.receipt-retention-manifest.v1`. It is written last as the local package commit marker. The package
contains only:

```text
RETENTION-MANIFEST.json
public-key.pem
witness-enrollment.json        # required for Unix-witness receipts
receipts/
  00000000000000000000-<receipt-digest>.anchor.json
  ...
```

The manifest covers every non-manifest object by path, byte length, ordinary SHA-256, kind, and (for
receipts) anchor sequence plus the existing domain-separated receipt digest. Verification rejects missing,
extra, symlinked, hard-linked, oversized, reordered, noncanonical, altered, wrong-key, wrong-enrollment,
stale-head, or Ledger-conflicting material.

The manifest cannot hash itself. Its domain-separated `manifest_sha256` is therefore used in the stable
`manifest_object_key`. The word `object` in the static v1 field names means a content-addressed package
member; it does not select object storage. The transparency adapter may map these identifiers to log leaf
identities without changing the v1 export format.

## Transparency-only delivery contract (local primitives implemented; network delivery deferred)

The accepted public leaf is now `filiolae.receipt-transparency-leaf.v1`, documented in
[`receipt-transparency.md`](receipt-transparency.md). It preserves the exact canonical `AnchorReceipt` bytes,
the raw Ed25519 public key needed for verification, and only the witness-enrollment commitment. A separate
manifest checkpoint leaf is not part of the minimal protocol: checkpoint extensions would be opaque to
generic monitors, while the full static package remains in the private preservation plane.

The raw witness enrollment contains an absolute Ledger path and therefore remains in MSP360 preservation;
its digest can be public. Future runs should use opaque public run IDs from genesis. Existing private run
receipts must not be published without a separate disclosure review because run IDs, signer times, and
cadence are observable.

A production transparency adapter must:

- use append-only submissions and reject a same-run/signer/anchor-sequence leaf with different receipt
  bytes as an equivocation alarm, never as an alternate harmless object;
- obtain and cryptographically verify a signed tree head/checkpoint plus an inclusion proof for each leaf;
- obtain consistency proofs from a previously trusted checkpoint rather than trusting a fresh log view;
- retry idempotently after a lost response and reconcile by receipt digest;
- publish all leaf bytes, proofs, and checkpoints through an open read API;
- keep submission/proof evidence outside the signer and orchestrator credential domains;
- allow independent software to verify receipts and proofs without contacting Filiolae infrastructure.

A mere HTTP success, log-assigned timestamp, or operator signature is insufficient.

## Compensating for the absence of Object Lock

Transparency replaces private deletion prevention with public detectability and replicated observation. To
make that credible, acceptance requires all of the following:

- **Full small payloads:** receipt bytes and public verification material are log leaves, so a surviving
  mirror can reconstruct the receipt chain. Only large/private run evidence remains in MSP360.
- **Independent mirrors:** multiple organizations continuously replicate complete leaves, proofs, and
  checkpoints. At least one accepted monitor must be outside the Filiolae operator's administrative domain;
  the production policy should set a higher multi-jurisdiction threshold.
- **Gossip or witness cosigning:** monitors exchange checkpoints, or a threshold of independent log
  witnesses cosigns them, so a log cannot quietly show different Merkle-tree histories to different users.
- **Cross-log durability:** checkpoints should be cross-logged into at least one independently operated log
  or equivalent public checkpoint channel. This is still transparency infrastructure, not a private Filiolae
  object store.
- **Public equivocation rules:** `(protocol, signer_key_id, run_id, anchor_seq)` is a uniqueness key.
  Conflicting receipt digests trigger a durable, publicly visible alarm.
- **Monitor archives:** monitors retain complete historical leaf payloads and verified checkpoint chains,
  allowing recovery if the original log operator disappears. Filiolae also preserves proof packages through
  the existing MSP360 workflow.
- **Honest time semantics:** inclusion proves existence no later than an independently observed checkpoint;
  it is not exact trusted UTC unless a separate time-attestation policy is added.

This does not make one log operator infallible. It makes deletion, rollback, and split views detectable as
long as at least one independent monitor or checkpoint channel remains honest and available.

## Gate coupling and honest claims

This static exporter is intentionally not in the Gate's promotion-critical path. Therefore a current Gate
approval proves a valid witness receipt and local mirror, **not** successful public inclusion. The safe
sequence is:

1. implement and validate shadow publication, proof verification, monitor operation, gossip/cross-logging,
   and recovery without granting authority;
2. define an explicit Charter/genesis policy for the required log set and monitor/witness threshold;
3. only after adversarial acceptance, require verified inclusion under a recent consistent checkpoint before
   the Gate grants promotion authority.

That later fail-closed coupling introduces a deliberate availability tradeoff: if the transparency quorum is
unavailable, no new promotion authority is issued. Bounded timeouts, idempotent reconciliation after a lost
reply, checkpoint freshness, log-key rotation, and emergency policy changes all require separate review.
Until then, reports must continue to say transparency-backed receipt retention is unvalidated. Object Lock
will not be used as a compensating Priority 5 backend; MSP360 remains the separate full-evidence preservation
system.
