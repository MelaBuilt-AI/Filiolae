# Signed Ledger-head checkpoints

Filiolae can require an Ed25519-signed, hash-chained receipt for the exact evidence head before a
Gate returns promotion authority. A second receipt checkpoints the promotion/load-failure outcome.

## What this proves

Each receipt binds the run ID, Charter digest (through the referenced genesis record), exact Ledger
sequence/head, monotonic receipt sequence, prior receipt digest, signer key ID, and signer-clock time.
Verification uses an out-of-band public key and rechecks every referenced record against the current
Ledger. Surviving receipts therefore reveal a rewritten/truncated Ledger, and receipt chaining reveals
middle deletion or reordering. Gate approval uses the signed evidence head as its compare-and-swap
predecessor. After signing, the Gate independently reloads the durable store and verifies the receipt
with its pinned public key; a fabricated callback result, concurrent append, or unavailable/bad signer
denies and freezes before weight loading.

## Local key and receipt setup

```bash
install -d -m 700 /protected/filiolae-anchor
filiolae anchor-keygen \
  --private-key /protected/filiolae-anchor/private.pem \
  --public-key /protected/filiolae-anchor/public.pem

filiolae anchor-head RUN/control/filiolae/ledger.jsonl \
  --artifact-root RUN/control/filiolae/artifacts \
  --anchor-dir /protected/filiolae-anchor/receipts \
  --private-key /protected/filiolae-anchor/private.pem

filiolae verify-anchors RUN/control/filiolae/ledger.jsonl \
  --anchor-dir /protected/filiolae-anchor/receipts \
  --public-key /protected/filiolae-anchor/public.pem
```

Key generation refuses overwrite and creates the unencrypted PKCS#8 private key mode 0600. Loading
rejects symlinks and any group/other-readable private key. Receipt files are canonical JSON, signed
with domain-separated Ed25519, created through a same-directory pending file, file-fsynced, committed
with an atomic no-clobber hard link, and directory-fsynced before and after pending-file removal. An incomplete pending file fails closed for reconciliation.

## Governed prime-rl mode

Set both variables before `filiolae-rl`; setting only one is an error:

```bash
export FILIOLAE_LOCAL_ANCHOR_PRIVATE_KEY=/protected/filiolae-anchor/private.pem
export FILIOLAE_LOCAL_ANCHOR_DIR=/protected/filiolae-anchor/fresh-run-receipts
```

Both paths must be outside the governed output. The launcher records the signer key ID and
`head_anchors_required: true` in genesis, checkpoints genesis, injects the signer into the Gate, and
checkpoints each terminal promotion outcome. `filiolae audit` must then receive `--anchor-dir` and
`--anchor-public-key`; otherwise it reports that required signatures were not checked.

Use a fresh receipt directory for every run. The current integration loads the private key inside the
trusted orchestrator/Gate process; prime-rl local roles commonly share an OS user, so this does not
isolate the signer from a hostile same-UID process. Key rotation, multisignature policy, resume
reconciliation, and a remote witness/signer protocol are not implemented. The provider-neutral
[`receipt-retention.md`](receipt-retention.md) static export preserves verified receipt bytes for later
independent delivery, but is not itself a remote acknowledgement or retention proof.

## Explicit non-claim

**Ed25519 receipts are locally stored cryptographic checkpoints, not independent external anchoring,
a public timestamp, transparency-log inclusion, or proof of existence to a third party.** They cannot
prevent joint rollback/deletion of both Ledger and receipt store, signer equivocation when a verifier
sees only one fork, private-key compromise, omission/DoS, or same-host root/kernel compromise.
`signed_at` is an informational signer clock, not trusted time; append-only files are not WORM.

Independence requires the private key and retained receipt store to be unavailable to the learner and
preferably to the orchestration host: separate credentials/host plus a remote WORM store,
transparency log, or retained witness. That production milestone remains open.


## Separating the signer process

The experimental [`unix-witness.md`](unix-witness.md) transport keeps the private key and
authoritative receipt store out of the governed orchestrator. The Gate still owns a public-key-verified
local mirror and the final Ledger CAS. This can create a separate credential boundary when deployed
with the documented UID/group/filesystem contract, but same-host Unix transport is not itself a remote
or independently retained anchor.
