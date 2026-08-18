# Operational-hardening plan

Status: **consequence-ranked design; public preview may describe these as open gates, not completed controls**

Date: 2026-08-17

## Prioritization rule

Order work by irreversible consequence and ambiguity reduction, not feature novelty. Each exercise
uses synthetic candidates/receipts unless real-model behavior is essential. A control unlocks a claim
only after its exact procedure, evidence inventory, cleanup, and non-claims are accepted.

| Priority | Failure / consequence | Required exercise | Pass evidence | Stop condition | Claim unlocked |
|---|---|---|---|---|---|
| P0 | Lost response grants duplicate or unrecorded authority | Deterministic relay drops witness/Gate response after durable receipt; restart clients; reconcile by exact request/head ID; repeat delivery without new receipt or approval | pre/post Ledger and store; relay trace; identical receipt digest; exactly one approval; zero load on unresolved state | new receipt/approval, uncertain durable point, or timeout without permanent freeze | bounded idempotent lost-response recovery |
| P0 | Reboot erases freeze, keys, receipts, cgroup policy, or denial | Native-host cold reboot at four states: pre-approval, approval committed/pre-load, load complete/pre-outcome, frozen. Verify protected mounts, service ordering, no auto-resume, cgroup cleanup, and operator-only reconciliation | boot IDs; unit dependencies; ownership/modes; Ledger/receipt audit; zero unexpected loads; retained freeze; cleanup | any automatic promotion/resume, missing evidence, writable key/store, orphan process/device | reboot persistence on the tested topology |
| P0 | Crash after weight load leaves reality ambiguous | Inject between loader return and outcome commit; quarantine candidate; require signed operator observation and multi-party reconcile-to-denial/rollback; never infer state from absent JSONL | loader probe; crash marker; Ledger tail; signed reconciliation object; rollback digest; no version advance/new work | continued training, automatic retry, unverifiable loaded version, or unilateral clearance | bounded ambiguous post-load recovery |
| P0 | Recovery data exists but cannot restore independently | Evidence custodian with no source-host access restores code, Charter, Ledger, keys/public policy, receipts, artifacts, and monitor state from a second provider/account | provider object/version policy; complete inventory; fresh-host verification/audit; recovery time/objectives | source-host dependency, mutable/missing object, unknown admin power, unverifiable key policy | provider-qualified recovery for exact package |
| P1 | Compromised signer remains trusted or rotation rewrites history | Introduce versioned signer policy with activation sequence/time, old/new key IDs, overlap rule, revocation reason, and threshold signatures; test normal rotation, emergency revoke, old-key replay, missing key, rollback, and recovery | old/new chains; signed policy objects; offline verifier and Gate results; retained revoked history | history deletion, implicit trust-on-first-use, old key accepted outside window, unilateral policy mutation | bounded key rotation/revocation |
| P1 | One operator can promote or clear ambiguity | Require M-of-N signed human/operator approvals over campaign, exact candidate, Charter, evidence head, action, expiry, and nonce; distinct key/admin domains; Gate consumes approval set once | canonical approval objects; signer policies; replay/expiry/wrong-action tests; Ledger links; two-person recovery drill | shared credential/admin, threshold bypass, reusable approval, signer also controls candidate/evaluator | bounded multi-party promotion/reconciliation |
| P1 | Log shows different histories to different observers | Isolated transparency S3: primary log, independent secondary, three witnesses (2-of-3), two monitors on disjoint credentials/paths; inject same-size fork, inconsistent growth, rollback, withheld tile, stale checkpoint, witness outage, partition, and cross-log omission | signed divergent checkpoints; consistency/inclusion material; witness observations; self-contained alarms; recovery/retirement record | alarm misses bound, shared admin invalidates isolation, evidence depends on forked log alone | split-view detection on tested topology |
| P1 | Monitoring detects failure but response is unsafe | Define health states/SLOs, page routes, quarantine/freeze mapping, bounded emergency authority, rollback target, and immutable incident packet; game-day delayed/missing/conflicting signals | signed monitor policy; alerts; decision timeline; freeze/rollback records; postmortem package | alert can approve; emergency bypass is unbounded/unsigned; rollback target unverified | bounded monitored rollback response |
| P2 | Operational state decays across upgrades | Upgrade matrix for kernel, Python, prime-rl, OS, systemd, GPU driver, evaluator, log, and storage; each change invalidates only stated evidence and triggers targeted reacceptance | compatibility manifest; diff-based required tests; fresh-site results | claiming inherited acceptance across changed boundary | version-scoped revalidation process |

## Execution packets

### Packet R — recovery and reboot persistence

**Entry:** a disposable native Linux host with systemd/cgroup v2, separate admin/witness/Gate UIDs,
no production data, synthetic candidate, and out-of-band termination route. Freeze exact source,
provisioning bytes, service graph, injections, expected states, and evidence commands. If the host is
paid, arm and independently verify an exact-resource TTL before any workload.

**Procedure:** baseline; deterministic lost-response; four crash/reboot points; ambiguous post-load
reconciliation; independent restore; key/process/device cleanup. Reboot tests must use real boot-ID
change—not process restart labeled as reboot. A failed exercise stays failed; fixes require a fresh
campaign ID and complete rerun.

### Packet K — rotation, revocation, and multi-party promotion

**Protocol object:** canonical signed policy names campaign/run, Charter digest, action, candidate,
Ledger head, key set, threshold, validity, nonce, and previous-policy digest. Rotation is append-only.
Revocation never deletes old receipts; verifiers evaluate each signature against the policy active at
that Ledger sequence and reject rollback. Emergency policy changes require the same or stricter
threshold unless the frozen Charter precommits a separately held break-glass quorum.

**Acceptance:** 2-of-3 promotion approvals from separate admin domains; 2-of-3 ambiguity clearance;
normal overlapping rotation; immediate compromised-key revocation; old-key replay, missing signer,
duplicate signer, expired approval, mixed action/head, policy rollback, and break-glass misuse all
fail closed.

### Packet T — split-view transparency

Run primary log, secondary cross-log, witnesses W1/W2/W3, and monitors M1/M2 under separate credentials
and directories; for an independence claim, use separately administered hosts/accounts and two network
paths. A fault proxy presents two valid same-origin/same-size roots to different observers. Within the
precommitted alarm bound, gossip/cross-log comparison must emit a portable packet containing both
signed checkpoints and observer signatures. Recovery retires the compromised shard, preserves both
views, reconciles all leaves, rotates policy/key through threshold approval, and proves old views
cannot be silently accepted.

## Public-preview boundary

The source preview should ship the design, existing bounded evidence, and exact non-claims now rather
than imply that every production-hardening gate is complete. P0/P1 execution results are prerequisites
for stronger integration/security-candidate labels, not for an honestly labeled inspectable pre-alpha.
No preview artifact may contain private keys, suite plaintext, private paths, credentials, mutable
runtime state, or consumed Priority 6 material.
