# Priority 6 v2 AWS Object Lock restore evidence

Owner supplied these four proof files on 2026-08-14 after backing up the private Gate F evidence archive to an **AWS S3 Immutable** destination, restoring it, and hashing the restored archive.

## Supported result

The retained source evidence supports this bounded claim:

- the backup application displayed **Object Lock (Immutability): Enabled**;
- retention displayed **1,095 days**, plus yearly full retention for 3 years;
- full consistency checking, AES-256 encryption, compression, and synthetic full backup displayed enabled;
- the backup report recorded success;
- the restore report recorded success and a restored archive size of **2,385,167,636 bytes**; and
- the supplied post-restore PowerShell transcript reported SHA-256
  `ffe77bc5f4b6f7c65dc7c2a7ff44eeb5335789431b389ed0eedb3d5f1adb57ab`, exactly matching the canonical Gate F archive.

The backup CSV reports 854,346,086 bytes for the archive while the screenshot reports 2.22 GB read and 815 MB uploaded with 64% deduplication. This is treated as the uploaded/deduplicated backup representation, not a conflicting restored-file size. The restore CSV reports the exact canonical 2,385,167,636-byte size.

## Evidence boundary

The agent directly read, copied, and SHA-256-hashed the four proof files in `source/`. It did **not** directly access the AWS account, bucket/object/version, backup application, or restored `D:` archive. Accordingly:

- this is source-backed Owner verification of cloud Object Lock configuration and a successful exact-hash recovery;
- it is not an independent AWS API attestation of bucket ARN, object version ID, compliance/governance mode, retain-until timestamp, legal hold, or administrator capabilities; and
- it does not reopen the accepted candidate or consumed suites for extraction, tuning, rerun, filtering, repair, deployment, or promotion.

See `evidence.json` for the machine-readable observations and exact source digests. The large private archive is not stored in Git.
