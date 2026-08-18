# Priority 6 v2 closeout evidence

This directory records the local preservation closeout for the private Gate F evidence archive. It does **not** contain the 2.38 GB archive itself; `preservation-inventory.json` uses symbolic private locators, while exact local paths remain only in the private operator vault.

On 2026-08-14, the original archive and two no-overwrite copies were independently checked as 2,385,167,636 bytes with SHA-256:

`ffe77bc5f4b6f7c65dc7c2a7ff44eeb5335789431b389ed0eedb3d5f1adb57ab`

The copies were made sequentially through temporary paths, synced, hashed before publication, and left read-only. One copy is a separate inode outside the transient WSL control root; the other is on the Windows NTFS host filesystem. The WSL source and first copy share one ext4 filesystem. Owner subsequently supplied a PowerShell `Get-FileHash` transcript for an additional other-PC `D:` copy; it reports the same expected SHA-256 and is retained as `other-pc-d-drive-sha256.txt`. This is source-backed Owner verification, not a claim that the agent directly accessed the remote archive.

Owner later supplied AWS backup, Object Lock configuration, restore, and post-restore hash proof retained in [`../priority-6-v2-aws-object-lock-restore-20260814/`](../priority-6-v2-aws-object-lock-restore-20260814/). It supports source-backed cloud Object Lock configuration and successful recovery of the exact canonical bytes. The agent did not directly access the AWS object or restored archive, and no provider-independent disaster-recovery claim is made.

See [`../../../docs/priority-6-v2-acceptance.md`](../../../docs/priority-6-v2-acceptance.md) for the human-readable result and claim boundary. The large archive remains private and must not be committed, published, extracted for tuning, or used to reopen either consumed suite.
