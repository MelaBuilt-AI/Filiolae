# Priority 6 v2 Gate D pre-workload stop — 2026-08-13

This package retains the first paid Gate D pod lifecycle as a **failed-closed pre-workload
attempt**, not candidate-development or quality evidence. The authorized one-GPU envelope produced
exact pod `24b80331e5234775a3ce789f66465087`, but the detached creator could not parse Prime CLI's
`YYYY-MM-DD HH:MM:SS UTC` `created_at` value. An attempted in-place correction then changed the
script path while systemd was still executing it. Ambiguity triggered the creator's exact-ID EXIT
cleanup.

No SSH endpoint became available, no bytes were uploaded, no host/model preparation or SFT began,
no candidate was frozen, and neither sealed suite was released. Gate D readiness therefore has no
score, and Gate F remains unused and ineligible.

## Lifecycle result

- Fresh quote: one non-spot Massed Compute A6000 48 GB at $0.54/hour; the three-hour bound was
  $1.62 under the authorized $3 ceiling.
- Provider creation: `2026-08-13T21:44:46Z`.
- The external persistent exact-ID watchdog was manually bound and observed active before any
  remote/model command, with deadline `2026-08-14T00:44:46Z`.
- Exact-ID EXIT cleanup terminated the still-provisioning pod at `2026-08-13T21:46:25Z`.
- Provider history reports one minute and total cost `0.0`; a later exact route check returned
  `already-terminated`, the watchdog was disabled, and the account listed zero active pods.

`STOP-RECORD.json` is the canonical interpretation. Supporting JSON preserves the quote,
precommitment, provisioning status, exact history row, watchdog facts, idempotent exact-route
confirmation, and zero-resource response. `CREATOR-DIAGNOSTIC.txt` is a UTC-normalized, path-free
excerpt; raw local logs are deliberately not tracked because they contain private machine paths.

## Authorization boundary

The Owner-authorized Gate D envelope specified **one fresh development GPU**. That GPU was
provisioned and terminated, so this repository will not create a second development GPU without
renewed Owner authorization. The readiness holdback was not burned because its plaintext was never
released, but there is no candidate and no Gate D pass. Gate F cannot begin.

## Remediation

The exact-ID controller now accepts and tests Prime CLI's emitted UTC timestamp as well as RFC 3339
and offset ISO-8601 forms. Future paid orchestration must also execute a content-addressed immutable
script copy and must never edit its path while it may be running. A future authorized attempt must
repeat the live quote and every identity, watchdog, data, security, and zero-resource preflight.

Run `sha256sum -c SHA256SUMS` in this directory to verify all retained files except the checksum
manifest itself.
