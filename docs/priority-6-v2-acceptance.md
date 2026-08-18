# Priority 6 v2 bounded acceptance

## Plain-language result

Filiolae's Priority 6 v2 experiment passed its precommitted bounded acceptance path on 2026-08-14. A frozen fine-tuned candidate first passed a one-use readiness evaluation and then a separately released one-use final evaluation. The final evaluator recorded one Gate approval and one disposable shadow promotion, and the offline governance audit passed.

This is evidence that the tested governance path worked under the recorded controls. It is **not** a deployment, production-readiness, general model-quality, publication, or independent-reproduction claim.

## Measured result

| Stage | Candidate | Source | Outcome |
|---|---:|---:|---|
| Visible development | 508/512 exact (9,921 bps) | — | One precommitted SFT round; no second round |
| One-use readiness | 256/256 exact (10,000 bps) | 0/256 | Gate D readiness passed |
| One-use final | 127/128 exact (9,921 bps) | 0/128 | Gate F passed |

The final Ledger/Gate path issued exactly one approval and one disposable shadow promotion. Its offline audit reported:

`Governance audit valid: 9 records, 1 promotion(s)`

## Controls that bounded the result

- **Frozen candidate:** the candidate was content-addressed before either one-use suite was released. Candidate tree SHA-256 is `741fda92eada7ff04d5e10882af9c253d3a0d4cb80bb7c7d530c600004826b57`; model SHA-256 is `96af54b64fadf1ba63c5a48733f059f25aa9974d02db123582e9c4a95b99f160`.
- **Separated release and evaluation:** custodian workflows released readiness and final material only after their gates. The final pod used controller UID 998 and evaluator UID 997; the evaluator owned its signing key, allowlist, and terminal authority.
- **One bounded request:** Gate F admitted one exact candidate request and ran real source/candidate inference against the untouched 128-case final suite.
- **Fail-closed lifecycle:** five earlier immutable Gate F orchestration recoveries stopped before evaluator inference or key creation. No final model-evaluation request ran during those recoveries; the successful runner was itself content-addressed.
- **Independent shutdown:** exact-resource watchdogs covered paid pods outside their SSH sessions. Every exact pod was terminated, active pods are zero, and watchdogs were disabled only after zero-resource confirmation.
- **Cleanup:** evaluator processes, the private signing key, and unauthorized terminal write paths were absent after cleanup.

Normalized provider cost for the final-session Gate D and Gate F work was `$0.7633`.

## Evidence and custody pointers

- Final result source commit: `3062d524020ada4ff15247730e2a53ee9ecd5339`
- Final private quality run: `31766383123` (all six jobs passed)
- Frozen candidate commit: `fd35a7e7baf7e6ac8daf794a486b540da0a21e2f`
- Readiness custodian run: `31762515686`
- Readiness result commit: `5562694de63e85096a763477474e482abcaf1ed1`
- Readiness result archive SHA-256: `2aac524d392a44793d46995a224cf16b6cf67febf675b5180c35b6a73e9ea80a`
- Final custodian run: `31763035326`
- Final suite SHA-256: `f65ce4daa4ee090933af59fb56ce38315dc5d46795acf4cd785719e17cdd3336`
- Successful immutable Gate F runner commit: `7c9564f0e597adfd480e02b0f513105b154a42a7`
- Runner SHA-256: `e620dbb335e5e168e0ee7f1bc65d8b99e0ee51824dccffbcd90d86ebb23dcb60`
- Runner quality run: `31765514733`
- Private Gate F evidence archive: 2,385,167,636 bytes, SHA-256 `ffe77bc5f4b6f7c65dc7c2a7ff44eeb5335789431b389ed0eedb3d5f1adb57ab`
- Archive-internal `SHA256SUMS` digest: `c55626eec0dd76af0cd7ca8bfe3464148a7fb9d48538fad291543a58d190389c`
- Terminal tree SHA-256: `e1abe97ed64ae6ad0ec1e02c14489053b87d10603ad05f1b5941c098649130b0`
- Local preservation record: [`../evidence/acceptance/priority-6-v2-closeout-20260814/`](../evidence/acceptance/priority-6-v2-closeout-20260814/)
- AWS Object Lock restore proof: [`../evidence/acceptance/priority-6-v2-aws-object-lock-restore-20260814/`](../evidence/acceptance/priority-6-v2-aws-object-lock-restore-20260814/)

The large archive remains private and outside Git. On 2026-08-14 the original plus two no-overwrite local copies were independently hash-verified by the agent. One duplicate is outside the transient WSL control root and one is on the Windows NTFS host filesystem. Owner later supplied a retained PowerShell `Get-FileHash` transcript for an additional other-PC `D:` copy reporting the same `ffe77bc5…57ab` SHA-256. That is source-backed Owner verification, not direct agent access to the remote archive.

Owner then supplied backup-application evidence showing an AWS S3 Immutable destination with Object Lock enabled and 1,095-day retention, a successful restore report for 2,385,167,636 bytes, and a post-restore PowerShell SHA-256 exactly matching `ffe77bc5…57ab`. The agent retained and hashed those proof files but did not directly access the AWS object or restored archive. This supports source-backed cloud Object Lock configuration and exact recovery, not an independent AWS API attestation of object version, retention mode, retain-until timestamp, legal hold, or every administrator capability.

## Exact claim boundary

Gate D and Gate F authority is consumed. The readiness and final plaintexts are consumed and must never be reused for development, tuning, filtering, repair, or rerun. The accepted candidate remains immutable evidence rather than a new optimization target. Original r18 remains permanently failed and closed.

This acceptance itself grants no authority for:

- deployment or production/non-shadow promotion;
- publication or public release;
- additional training or tuning;
- readiness/final holdback access or evaluator rerun;
- threshold changes or post-hoc filtering; or
- new paid compute.

Later work may receive separate authority, but it cannot reuse this campaign's candidate, suites, or
one-use approvals as fresh evidence.

## Custody retirement (2026-08-17)

The private development repository's `P6_V2_READINESS_SEED` and `P6_V2_FINAL_SEED` Actions secrets
were deleted. A metadata readback then returned no repository Actions secrets. The retained custodian
workflow is marked `RETIRED` and its only job has an unconditional false guard, so dispatch cannot
read a seed or generate a suite without changing reviewed source first. The fresh-history public-
preview staging repository has no Actions secrets.

This closes the active repository route; it does not prove deletion from GitHub backups or any
external operator copy. The commitment hashes and historical reports remain evidence, while suite
plaintext and candidate bytes remain unavailable and non-reusable. The separately prepared
independent-reproduction and operational-hardening protocols require entirely new material and
credentials.
