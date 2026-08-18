# Native systemd/cgroup-v2 separate-UID containment game day

Status: bounded acceptance passed 2026-08-12; S5 excluded
Target: Filiolae Phase 1 pre-alpha  
Scope: CPU-only, disposable native Linux host

## Bounded acceptance result

Private GitHub Actions run
`private Actions run 31561250307` passed S0–S4 and S6
on an admitted Ubuntu 24.04 Microsoft VM at source commit
`35529fec51727d360a77b41f56a19134cde94d80`. The complete checksummed archive and extracted
machine-readable summaries are preserved in
[`../evidence/acceptance/native-systemd-20260812/`](../evidence/acceptance/native-systemd-20260812/).
S5 remains explicitly excluded because no deterministic lost-response relay was implemented. The
accepted run did not exercise a reboot, GPU-device controls, remote retention, or a real candidate
evaluator.

Two predecessor runs failed before acceptance and exposed real deployment defects: tmpfiles created
the fixed Ledger lock before exact lock provisioning, and the service virtualenv resolved to a
Python binary hidden by `ProtectHome`. Commits `d6fc833` and `35529fe` fixed those defects with local
and Python 3.11/3.12 CI validation before the successful rerun.

## Purpose

Close the documented POSIX `setsid` escape and same-credential witness non-claim with live evidence
from the reference systemd deployment. The game day must prove that the orchestrator and witness run
under different numeric UIDs, that the witness private key and authoritative receipts remain outside
the orchestrator credential domain, and that systemd kills every descendant left in the governed
service cgroup after a witness or orchestrator failure.

This plan does **not** claim production security, independent remote retention, trusted time,
hardware-backed keys, evaluator isolation, candidate quality, GPU-device containment, or
public-release readiness. Actual boot persistence also remains unproven on a GitHub-hosted runner.

## Audited starting assets

| Asset | Existing contract | Live evidence still required |
| --- | --- | --- |
| `filiolae.sysusers` | Distinct witness/orchestrator users plus shared Ledger group | Numeric UIDs differ on the admitted host; memberships are exact |
| `filiolae.tmpfiles` | Protected key/receipt/mirror roots and shared runtime roots | Actual owners, modes, ACLs, mounts, and traversal behavior |
| `filiolae-witness@.service` | Witness-only key/receipts; no network; strict filesystem sandbox; cgroup kill | Successful service start, UID isolation, socket ownership, journal and cgroup state |
| `filiolae-orchestrator@.service` | `BindsTo=`/`After=` witness; cgroup-wide kill; fixed writable paths | Failure propagation, hostile `setsid` descendant kill, zero post-failure loads/promotions |
| `provision-unix-witness` | Fixed root-owned lock; one-time enrollment; metadata validation | Root execution on a real filesystem and negative permission tests |
| `filiolae-witness-ready` | Bounded socket readiness check | Missing/unready socket causes startup failure |
| Static tests | Parser/directive/provisioner source contracts | No live UID, cgroup, journald, startup, or failure-injection proof |

Audit conclusion: the reference boundary is coherent, but the repository has no native-host admission
probe, no bounded live scenario driver, no systemd-oriented governance harness, and no canonical
evidence manifest. Those are test-infrastructure gaps, not evidence that the boundary already works.
They must be added before acceptance execution.

## Resource and authorization boundary

1. First choice: one manually dispatched `ubuntu-24.04` GitHub-hosted runner job.
2. Actions working budget: 100 billed minutes total; one sequential job; no matrix; 25-minute timeout
   per full attempt; at most three full attempts without Owner review.
3. If the GitHub host fails admission, terminate that attempt and use one Prime Intellect **Compute
   CPU node**, not a Docker sandbox. Use non-spot capacity when available, maximum two hours and
   $0.10, with an on-host deadline and an external exact-provider-ID termination guard.
4. Never run destructive acceptance on the Owner's daily WSL environment. No GPU is required.
5. Use only generated game-day keys and test run IDs. No production credential or retained private
   key enters CI artifacts.

## Host admission gate

Record every command and reject the host before installation unless all checks pass:

- `/proc/1/comm` is `systemd`;
- `/sys/fs/cgroup` has filesystem type `cgroup2fs`;
- `/sys/fs/cgroup/cgroup.controllers` exists and is nonempty;
- `systemd-detect-virt --container` reports no container;
- virtualization and image identity are recorded;
- `sudo -n true` succeeds;
- systemd can create/start/stop a transient smoke service and its cgroup is observable;
- journald returns records for that service;
- sufficient free disk and memory exist;
- repository commit equals the workflow-dispatched commit.

A VM result from `systemd-detect-virt` is acceptable; a container result is not. Admission failure is
not a Filiolae failure and must never be reported as containment acceptance.

## Installation and immutable inputs

- Install the exact checked-out Filiolae wheel into a root-owned isolated virtual environment.
- Copy the audited systemd assets to their documented root-owned locations and record SHA-256 hashes.
- Generate one ephemeral Ed25519 witness keypair on-host; install the private key mode 0600 under the
  witness UID and the public key mode 0644 under root.
- Record the source commit, workflow run identity, runner image metadata, Python/systemd/kernel
  versions, unit hashes, wheel hash, and game-day driver hash before running scenarios.
- Use a test-only instance drop-in to replace only the orchestrator `ExecStart` with the repository's
  game-day governance harness. Do not weaken `User=`, groups, `BindsTo=`, slice assignment,
  `KillMode=control-group`, capabilities, filesystem protections, or the witness command.

The game-day harness must use Filiolae's real `_build_barrier`, Unix witness client, Ledger, Gate,
`PrimeRLEvidenceBuilder`, and `WeightUpdateController`. It creates a fresh enrolled run, a real
candidate evidence bundle, and a callback sentinel only when the Gate actually permits a load. It
also spawns a descendant in a new session that ignores SIGTERM so cgroup SIGKILL escalation is tested
independently of POSIX process groups.

## Scenarios and acceptance criteria

Use a fresh run ID for every scenario. Capture pre/post timestamps, unit properties, cgroup paths,
PIDs, SIDs, UIDs/GIDs, filesystem metadata, journal, Ledger, receipts, mirror, freeze marker, callback
sentinels, and audit output.

### S0 — host, installation, identity, and path contract

- Provision and enroll a fresh run.
- `filiolae-witness` and `filiolae-orchestrator` numeric UIDs must differ.
- Both have only the intended shared Ledger supplementary group.
- The orchestrator must fail to read the private key, enrollment/authoritative receipt directory, and
  witness environment file.
- The witness must fail to write the run tree and Gate mirror.
- The lock inode must be a root-owned regular file, group `filiolae-ledger`, mode 0660, below a
  root-owned non-service-writable parent.
- `provision-unix-witness validate` and `systemd-analyze security`/`verify` evidence are retained.

### S1 — baseline witnessed promotion

- Starting the orchestrator must pull in and wait for the witness.
- The harness creates and anchors genesis, then exposes its hostile `setsid` descendant.
- One valid step must produce the exact evidence events, `gate.approved`, one callback sentinel,
  `policy.promoted`, a valid authoritative receipt chain, and an identical verified Gate mirror.
- Normal audit and current-head anchor verification must pass.
- Stopping the unit must leave no process in the old orchestrator cgroup.

### S2 — witness crash and cgroup containment

- Start a fresh run and record the orchestrator main PID, hostile child PID/SID, and cgroup.
- Send SIGKILL to the witness unit.
- `BindsTo=` must deactivate the orchestrator.
- After its finite stop deadline, the main process and hostile `setsid` descendant must be gone and
  the old service cgroup must be absent or empty.
- There must be no callback sentinel, `gate.approved`, or `policy.promoted` after the failure
  timestamp.

### S3 — hung witness, denial/freeze, and reconciliation

- SIGSTOP the witness before requesting a fresh promotion.
- The witness request must time out; no load callback may execute; the run must freeze.
- The Ledger must contain the attempted evidence and a durable local tripwire/denial, while anchor
  verification truthfully reports any unanchored tail during the outage.
- SIGCONT the witness and request explicit current-head reconciliation from the still-running harness.
- The authoritative store and Gate mirror must converge on the current valid Ledger head before any
  further authority is possible. The permanent freeze remains and a second promotion remains denied.
- Stop/kill cleanup must leave both cgroups empty.

### S4 — startup failures

Use separate fresh runs and prove the orchestrator never becomes active and never records a load or
promotion when each prerequisite is missing or unusable:

1. witness private key;
2. fixed Ledger lock;
3. enrollment manifest;
4. witness socket readiness (test-only instance override starts a process that never creates it);
5. orchestrator configuration.

Restore each prerequisite only while both services are stopped. Record `Result`, `ExecMainStatus`,
condition results, dependency state, and journal messages.

### S5 — lost response

A deterministic test-only Unix-socket relay may discard the first response only after the real
witness has returned it, proving the authoritative receipt was committed while the Gate mirror did
not receive it. No authority may be granted from that lost response. After relay/witness recovery,
the normal client must import and verify the full authoritative chain before approval. Test-only
fault machinery must never be installed by the wheel or production deployment.

If deterministic lost-response injection cannot be implemented without changing production witness
behavior, report S5 separately as unexecuted rather than using a timing race or weakening the claim.

### S6 — cleanup and retained evidence

- Stop/disable test instances; remove test-only drop-ins and runtime configuration.
- Preserve run trees, authoritative receipts, mirrors, public key, journals, manifests, and audits.
- Remove the ephemeral private key from the export.
- Confirm no Filiolae test service is active and no test process/cgroup remains.
- On Prime fallback, terminate by full provider ID and independently confirm zero active pods.

## Evidence package

Create a safe relative-path archive containing:

- `MANIFEST.json` with schema, verdict per scenario, exact commands/return codes, timestamps, host and
  source identities, non-claims, and every exported file SHA-256;
- `host/`: admission output, kernel/systemd/virtualization/cgroup/mount/resource metadata;
- `install/`: unit content/hashes, package hash, sysusers/tmpfiles, identity/group/permission reports;
- `scenarios/S*/`: journals, systemctl properties, cgroup/PID/SID evidence, Ledger/audit/explain output,
  receipts/mirror, freeze and callback state;
- `cleanup/`: inactive-unit, empty-cgroup, process, and (for Prime) provider termination evidence;
- `SHA256SUMS` over every data file and a sidecar hash for the final archive.

The collector must reject symlinks, devices, sockets, absolute paths, traversal, private keys, and
unexpected large files. Upload the package even on failure using an `if: always()` step, but never let
artifact-upload success turn a failed scenario green.

## Verdict rules

- **PASS (bounded):** S0–S4 and S6 pass; S5 either passes or is explicitly excluded from the verdict;
  all evidence verifies; no unexplained tail, process, cgroup, active unit, or private key remains.
- **FAIL:** any load/promotion after a failed prerequisite, UID/key separation failure, escaped
  descendant survival, invalid Ledger/receipt chain, evidence contradiction, or cleanup failure.
- **INCONCLUSIVE:** host admission fails, the runner is interrupted, required evidence is missing, or
  behavior cannot be deterministically attributed.

A PASS removes only the documented native cgroup/separate-witness-UID non-claim for the exact tested
CPU deployment. It does not upgrade Filiolae to production-ready and does not authorize publication.

## Execution sequence

1. Add and locally validate the host probe, governance harness, scenario driver, collector, and static
   contract tests.
2. Commit/push privately and require the existing Python 3.11/3.12/build CI to pass.
3. Dispatch the probe-only workflow. Record its billed duration and admission evidence.
4. If admitted, dispatch one full sequential game day; inspect downloaded evidence independently.
5. Fix only evidence-backed gaps; repeat within the approved Actions budget; rerun full CI.
6. If GitHub is not admissible, use the bounded Prime CPU fallback and the same scripts/evidence
   schema.
7. Commit the canonical result and explicit remaining non-claims; require final green CI.
