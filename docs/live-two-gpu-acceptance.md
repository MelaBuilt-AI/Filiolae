# Live two-A6000 acceptance record

## Bounded result

On 2026-08-12 UTC, campaign `prime-a6000-20260811-r18` completed both governed profiles on one
Prime Intellect pod with two NVIDIA RTX A6000 48 GB GPUs. This is acceptance evidence for the pinned
single-node smoke only. It is not a production-containment, independent/WORM-witness, candidate-quality,
or hostile-workload claim.
The Git-tracked machine-readable archive index and checksums are in
[`../evidence/acceptance/r18/`](../evidence/acceptance/r18/).

Immutable inputs:

- Filiolae commit: `9bbad47bf40a17d24273025bf85f09e867f82305`
- prime-rl commit: `60bc29547a8824ad1de7b9af8d265e2b27b2a72d`
- payload SHA-256: `6170309bda3eaa3275876d9bc77fd02e2e1678f61fd4ad57b6a8ffa4106365a6`
- host: Ubuntu 22.04, NVIDIA driver 580.126.09, reported CUDA 13.0
- containment: POSIX process group only, with the documented `setsid` non-claim

## Happy profile

Run `prime-a6000-20260811-r18-happy` exited zero and its runner recorded acceptance success. The
Ledger contains 13 records, two Gate approvals and two policy promotions. Normal artifact/semantic
audit passed, all six local Ed25519 receipts verified, and the current Ledger head had no unanchored
tail.

Evidence bundle:

- filename: `prime-a6000-20260811-r18-happy.tar`
- size: 6,021,683,200 bytes
- SHA-256: `99dfa460d2ff1266ffb27183eae7988f866178b842c804a7862e983d047e3bde`
- 52 safe regular archive members, including the collection report

## Authorized tamper profile

Run `prime-a6000-20260811-r18-tamper` changed one byte in the Gate-owned step-1 candidate artifact.
The next authorization detected the digest mismatch, committed and anchored `tripwire.fired` and
`gate.denied`, wrote the irreversible freeze marker, and caused the supervisor to return 75. The
runner accepted this expected nonzero result. Only step 1 was approved/promoted; no post-tamper
approval or promotion exists.

The normal audit failed as required with `artifact_mismatch` at Ledger sequence 4. The 12-record
Ledger chain itself remained intact, all four receipts verified, and the denial head had no
unanchored tail. In this campaign's v1 runner state, the actual governed return code is stored under
the legacy field name `expected_nonzero_returncode`; later code renamed it to
`governed_returncode`.

Evidence bundle:

- filename: `prime-a6000-20260811-r18-tamper.tar`
- size: 6,023,342,080 bytes
- SHA-256: `895c2e2a3c99b1348d497d5c450d1237524b2a5bdb4da81c78da2d12ab4085ce`
- 55 safe regular archive members, including the collection report

## Independent post-retrieval checks

After checksum verification, each archive was safely extracted and checked with the repository's
Filiolae CLI. The happy audit and anchor verification returned zero. The tamper audit returned one
for the expected artifact mismatch, while its independent anchor verification returned zero. The
operator then confirmed the exact pod ID was absent from the active-pod list and stopped the backup
deadline service.

The pod ran for approximately 34 minutes and cost $0.5588. Full-mode evidence omitted redundant
trainer optimizer checkpoints and convenience weight exports, while retaining governed artifacts,
broadcasts, rollouts, configs/logs, receipts, and operator evidence.

## Preservation and recovery

On 2026-08-13, bounded preservation/recoverability acceptance passed for the complete r18 package.
AWS and Backblaze B2 backup reports contain the same package inventory; fresh restores from both
destinations reproduce identical logical path/size inventories and independently end with
`FILIOLAE R18 PRESERVATION VERIFY PASS`. AWS is configured for 1,095-day retention with MSP360
Object Lock enabled. B2 is configured for 1,095-day retention but is explicitly not immutable. See
[`r18-preservation-acceptance.md`](r18-preservation-acceptance.md) for retained evidence, exact checks,
and the non-claims around dual-cloud WORM and provider-side Object Lock metadata.
