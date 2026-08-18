# r18 preservation and fresh-restore acceptance

## Result

On 2026-08-13, Owner supplied the original MSP360 backup reports, backup-plan screenshots, fresh-restore
reports, and post-restore verification screenshots for the bounded two-A6000 r18 package. The evidence
supports a **bounded preservation and recoverability pass** for the revised topology:

- one AWS S3 backup configured for 1,095-day retention with MSP360 Object Lock immutability enabled;
- one Backblaze B2 backup configured for 1,095-day retention with Object Lock immutability disabled;
- successful fresh restores from both cloud destinations followed by exact package verification; and
- Owner's separate attestation that complete copies also exist on three PCs and one external device.

This closes Priority 4's bounded backup/restore objective. It is deliberately **not** a claim that both
cloud copies are WORM/immutable.

The retained source evidence and hashes are in
[`../evidence/acceptance/r18-preservation-20260813/`](../evidence/acceptance/r18-preservation-20260813/).
The SHA-256 of that directory's `SHA256SUMS` file is
`449b00c638178744a53d8d5442057f0e02dd84ca22faa16c1f2f58a0fdcf51e4`.

## Machine-checked report review

The four CSV reports were parsed as CSV rather than inferred only from screenshots:

| Evidence | Rows | Successful | Non-empty errors |
|---|---:|---:|---:|
| AWS backup report | 34 | 34 | 0 |
| B2 backup report | 34 | 34 | 0 |
| AWS restore report | 33 | 33 | 0 |
| B2 restore report | 33 | 33 | 0 |

Each backup report contains the same 33 source paths later present in each restore, plus MSP360's
`Detailed report` row. The AWS and B2 restore inventories have identical paths and identical logical
sizes:

- 33 restored files and 12,074,156,520 bytes including the pre-existing `Verify Pass.png` helper
  evidence file;
- 32 files and 12,074,083,151 bytes inside `Filiolae-r18-preservation`; and
- package-root checksum anchor
  `deec38be4eb295aa6594732bfb92a9a00b5e50f19d4e8ec903655e3699aca50c`.

Compression was enabled in both backup plans. Consequently, the backup CSV `Size` values and the UI's
8.79 GB uploaded value are transfer/archive sizes, while the restore reports provide logical restored
sizes; those columns are not expected to match directly.

## Screenshot review

Both plan screenshots show full backup and full consistency check success for 33 files, 11.2 GB read,
8.79 GB uploaded, AES-256 encryption, synthetic full enabled, and 1,095-day retention. They differ at
the expected boundary:

- AWS: `Object Lock (Immutability): Enabled`;
- Backblaze B2: `Object Lock (Immutability): Disabled`.

The two restore screenshots show `VERIFY-PRESERVATION.ps1` running from separate AWS and B2 restore
directories. Every manifest entry is reported `OK`, all four core artifacts are reported `CORE OK`,
and each ends with `FILIOLAE R18 PRESERVATION VERIFY PASS`.

## Exact claim boundary

This evidence establishes MSP360 job success, configured 1,095-day retention, AWS-plan Object Lock
enablement, B2-plan non-immutability, successful fresh restoration from each cloud provider, and
exact-byte verification of each restored package.

The supplied screenshots are MSP360 plan/status views, not AWS S3 API or console output for individual
object versions. They therefore do **not independently establish**:

- whether AWS used Compliance mode rather than Governance mode;
- the per-object S3 version IDs or exact retain-until timestamps;
- immutability of the B2 copy; or
- the inventory/current health of the three-PC and external-device copies, which is an Owner
  attestation here (earlier local/external checksum verification remains separate evidence).

Accordingly, the accepted claim is **one configured immutable cloud copy plus one retained redundant
cloud copy and multiple physical copies, with two independently restored and checksum-verified cloud
copies**. It is not dual-cloud WORM, provider-independent trusted time, or permanent preservation.
