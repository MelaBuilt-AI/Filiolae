# Unix-socket Ledger-head witness (experimental)

Filiolae can move the Ed25519 private key and authoritative receipt store out of the governed
prime-rl orchestrator process. A Linux Unix-domain-socket service observes one fixed Ledger path,
validates its complete canonical hash chain under the same advisory lock used by writers, signs only
the actual requested current head, fsyncs an authoritative receipt chain, and returns the signed
chain. The Gate-side client verifies a pinned public key, imports the chain into a local durable
mirror, and then the Gate independently verifies that mirror before its existing approval CAS.

This is a stronger process/credential seam than `FILIOLAE_LOCAL_ANCHOR_PRIVATE_KEY`; it is still an
experimental same-host witness, not a public timestamp, remote host, WORM store, transparency log,
or proof against root/kernel compromise.

## Protocol and fail-closed properties

- Linux `AF_UNIX` stream transport, one bounded canonical-JSON request/response per connection.
- The daemon obtains `SO_PEERCRED` and accepts exactly one configured numeric client UID. The pinned
  Ed25519 public key remains the client's authenticity root; socket identity mainly limits DoS.
- Requests contain no filesystem path. The daemon is constructed with one absolute Ledger path,
  fixed lock inode, private key, and authoritative store.
- The daemon compares run ID, sequence, and hash to the fully audited actual current Ledger head.
  It never signs a caller-supplied arbitrary digest.
- Receipt v1 already signs `anchor_kind`; witness receipts pin `unix_ed25519_witness`. Verification
  rejects mixed-kind chains or a kind/key inconsistent with genesis.
- The authoritative store is committed and reverified before any success response. Responses include
  the full signed chain, enabling an empty/stale mirror to catch up after a lost response. The 16 MiB
  response bound is an explicit pre-alpha scalability limit; pagination is future work.
- The client makes no RPC while holding a Ledger or mirror lock. It strictly parses and verifies every
  receipt before a no-clobber/fsynced mirror import. The Gate reloads the mirror itself using its pinned
  public key and exact expected kind/head, then uses Ledger `expected_head` CAS. A concurrent append
  after signing therefore denies/freezes rather than granting authority.
- Signer/socket/parse/timeout/mirror/fsync faults return no new authority. An authoritative receipt may
  safely exist without a corresponding approval after a lost response or CAS loss.

## Cross-credential lock and file contract

A separate witness UID must read the Ledger and participate in the same `flock` inode as the writer.
Do **not** let either service create an adjacent mode-0600 lock on demand. Provision one fixed regular
file before both services:

```bash
# Run with authority to set the shared service group.
filiolae ledger-lock-provision /run/filiolae/run-123/ledger.lock \
  --mode 0660 --gid "$FILIOLAE_SERVICE_GID"
```

Witness-mode launcher configuration requires that fixed path plus
`FILIOLAE_LEDGER_SHARED_GID`. The launcher sets its output, control, and Filiolae governance
directories to mode 0750 in that group, then changes the Ledger to mode 0640 and the configured group
before its first witness request. Administrators must still make every parent above the output root
traversable by the witness credential. The lock is mode 0660 in the same group; when the provisioning
command creates its immediate parent, it sets that directory to group ownership and mode 0750. The
witness needs group read on the Ledger and read/write on the lock, but does not need Ledger write.
The witness key and authoritative receipt store should remain mode 0600/0700 and owned only by the
witness UID.

`flock` is advisory. Filesystem permissions must prevent governed workers from replacing/writing the
Ledger or lock outside the protocol. A caller able to rename either inode can defeat the cooperative
snapshot guarantee; cgroup/service-manager boundaries and separate learner/orchestrator credentials
remain production prerequisites.

## Reference systemd deployment (separate UIDs)

`deploy/systemd/` is a concrete, fixed-layout reference for a **single Linux host**. It is not
installed by the Python wheel. The units deliberately use two service accounts and a shared group:

| Principal/path | Ownership and purpose |
| --- | --- |
| `filiolae-witness` | Reads the Ledger, writes only the shared lock/socket and authoritative receipts; owns the mode-0600 private key. |
| `filiolae-orchestrator` | Writes the governed run and its mode-0700 Gate mirror; has no access to the private key or authoritative receipts. |
| `filiolae-ledger` | Supplementary group for both UIDs; grants Ledger read, lock read/write, and socket access, not receipt/key access. |
| `/run/filiolae-locks/RUN/ledger.lock` | Root-owned, group `filiolae-ledger`, mode 0660, and fixed for the boot. Neither service can replace it. |
| `/var/lib/filiolae-witness/RUN` | Mode 0700 authoritative receipt chain owned by the witness. |
| `/var/lib/filiolae-gate-mirrors/RUN` | Mode 0700 Gate mirror owned by the orchestrator. |

Review every unit against the local prime-rl/GPU requirements first. Then install the assets as root
(the `/usr/local` choice for the two console scripts may be changed consistently):

```bash
install -m 0644 deploy/systemd/filiolae.sysusers /usr/lib/sysusers.d/filiolae.conf
install -m 0644 deploy/systemd/filiolae.tmpfiles /usr/lib/tmpfiles.d/filiolae.conf
install -m 0644 deploy/systemd/filiolae-governed.slice /etc/systemd/system/
install -m 0644 deploy/systemd/filiolae-{witness,orchestrator}@.service /etc/systemd/system/
install -m 0755 deploy/systemd/filiolae-witness-ready /usr/libexec/
install -m 0755 deploy/systemd/provision-unix-witness /usr/local/sbin/
systemd-sysusers /usr/lib/sysusers.d/filiolae.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/filiolae.conf
```

Install Filiolae and the patched prime-rl launcher so `/usr/bin/env filiolae` and
`/usr/bin/env filiolae-rl` resolve from systemd's service PATH. Create the key outside any governed
output and copy it with exact ownership. Do not put the private source or key in an environment file:

```bash
umask 077
filiolae anchor-keygen \
  --private-key /root/filiolae-witness-private.pem \
  --public-key /root/filiolae-witness-public.pem
install -o filiolae-witness -g filiolae-witness -m 0600 \
  /root/filiolae-witness-private.pem /etc/filiolae-witness/ed25519-private.pem
install -o root -g root -m 0644 \
  /root/filiolae-witness-public.pem /etc/filiolae/ed25519-public.pem
shred -u /root/filiolae-witness-private.pem  # best effort; SSD/filesystem caveats apply
```

For a conservative identifier such as `run-123`, provision the per-run directories, boot-persistent
tmpfiles rule, fixed lock, and numeric UID/GID environment files. The command rejects equal service
UIDs, missing group membership, unsafe identifiers, and incorrectly owned key material:

```bash
provision-unix-witness provision run-123
install -o root -g filiolae-orchestrator -m 0640 \
  /secure/input/run-123.toml /etc/filiolae/orchestrator/run-123.toml
# One-time, offline ceremony. Review the printed manifest digest before starting either service.
provision-unix-witness enroll run-123 /secure/input/run-123-charter.yaml
systemctl enable --now filiolae-orchestrator@run-123.service
provision-unix-witness validate run-123
```

Starting the orchestrator pulls in the witness and waits for its socket. The witness may start before
the Ledger exists only because its mode-0600 manifest already commits the reviewed run ID, Charter
digest, signer ID, anchor kind, enrollment digest, and normalized Ledger path. It accepts and pins an
appearing Ledger only when genesis carries that exact enrollment digest and tuple. `BindsTo=` and `After=`
stop the orchestrator if the witness exits. Both units use `KillMode=control-group`, a finite stop
timeout, and SIGKILL escalation, so descendants remaining in the service cgroup are killed rather
than relying on POSIX process-group cooperation. The slice enables CPU, memory, and task accounting
and a task ceiling. The witness additionally has no network namespace, only `AF_UNIX`, an empty
capability set, private devices, and strict read/write paths. The orchestrator keeps network/device
access for prime-rl/GPU operation but has an empty capability set, a read-only host filesystem except
for its fixed output and mirror, and the same kernel/namespace hardening. Site overrides that add GPU
devices, writable caches, credentials, or resource quotas must not broaden witness access.

The orchestrator unit exports only the pinned public key, socket, Gate mirror, shared lock, and shared
GID. The launcher creates the Ledger mode 0640 in `filiolae-ledger`; the witness can read it but cannot
write it. The root-owned lock directory is mode 0750 and the lock is 0660, allowing both services to
`flock` the same inode without allowing either to unlink it. `/run` is ephemeral, so the provisioner
writes a per-run tmpfiles fragment that recreates the lock before services start after each boot.
Never provision or restart tmpfiles for a live run in a way that replaces its lock inode.

### Failure injection and validation

The bounded native-host acceptance sequence and evidence schema are specified in
[`native-systemd-containment-game-day.md`](native-systemd-containment-game-day.md).

Run these only on a disposable non-production run. Record timestamps and `systemctl show ...
-p ControlGroup -p MainPID -p Result` before and after each case.

1. **Witness crash:** `systemctl kill -s SIGKILL filiolae-witness@run-123`. The witness becomes
   failed, `BindsTo=` deactivates the orchestrator, and after `TimeoutStopSec` every PID in the old
   orchestrator cgroup must be gone. No later promotion may be recorded.
2. **Hung witness:** `systemctl kill -s SIGSTOP filiolae-witness@run-123`. A checkpoint request must
   time out and freeze/deny without loading weights. Kill the stopped witness afterward; verify the
   same cgroup shutdown behavior.
3. **Socket loss/startup ordering:** with both units stopped, temporarily move the public key or make
   the lock unavailable and start the orchestrator. Startup must fail; it must not run without an
   active witness. Restore metadata with the provisioner before retrying. Do not delete a live socket
   as a routine test because it can leave a listening but unreachable server.
4. **Lost response:** kill the witness immediately after an authoritative receipt is fsynced (or use
   the repository protocol fault tests). A missing mirror receipt grants no authority. After restart,
   the full verified authoritative chain must catch the mirror up before approval.
5. **Metadata and identity:** run `provision-unix-witness validate run-123`, inspect both numeric UIDs,
   and confirm the private key/authoritative directory are unreadable by the orchestrator with
   `runuser -u filiolae-orchestrator -- test ! -r ...`.

CI tests validate the unit, sysusers/tmpfiles, provisioning-script, and sandbox contracts without
root or a running systemd. They do **not** prove cgroup kill propagation, boot ordering, UID isolation,
GPU compatibility, journald retention, or actual filesystem ACL/mount behavior. Those checks require
a disposable native systemd host (containers and WSL commonly do not provide the relevant PID 1 and
cgroup delegation).

### Evidence retention, rollback, and uninstall

Before rollback, stop new work, retain all three views, and make a manifest outside both service
credentials:

```bash
systemctl stop filiolae-orchestrator@run-123
journalctl -u filiolae-witness@run-123 -u filiolae-orchestrator@run-123 \
  --output=short-iso-precise > /secure/archive/run-123.journal.txt
filiolae verify-anchors /srv/filiolae/runs/run-123/control/filiolae/ledger.jsonl \
  --anchor-dir /var/lib/filiolae-witness/run-123 \
  --public-key /etc/filiolae/ed25519-public.pem
filiolae audit /srv/filiolae/runs/run-123/control/filiolae/ledger.jsonl \
  --artifact-root /srv/filiolae/runs/run-123/control/filiolae/artifacts \
  --charter /etc/filiolae/orchestrator/run-123.charter.yaml \
  --anchor-dir /var/lib/filiolae-witness/run-123 \
  --anchor-public-key /etc/filiolae/ed25519-public.pem \
  --witness-enrollment /var/lib/filiolae-witness/run-123/enrollment.json
find /srv/filiolae/runs/run-123 /var/lib/filiolae-witness/run-123 \
  /var/lib/filiolae-gate-mirrors/run-123 -type f -exec sha256sum {} + \
  > /secure/archive/run-123.sha256
provision-unix-witness uninstall run-123
```

Uninstall disables both units and removes only runtime/config/tmpfiles material. It intentionally
retains the Ledger/artifacts, authoritative receipts, Gate mirror, keys, service accounts, and pinned
public key. Delete those only after an independently verified retention/export policy permits it.
Rolling back to local-key mode is a change of trust boundary, not a continuation of the witness
claim: stop the run, use a new run ID/output and explicit genesis policy, and never copy the witness
private key into the orchestrator.

## Bootstrap and non-claims

Witness mode now requires a one-time canonical `filiolae.witness-enrollment.v1` manifest created
before Ledger creation. `O_EXCL`, empty-receipt checks, exact path/run/Charter/signer binding, and the
manifest digest committed in genesis reject enrollment replay, conflict, retroactive adoption, and
cross-run/path substitution. Witness protocol v2 carries and echoes that digest; the daemon verifies
the manifest tuple before every signing decision and pins the Ledger inode once it appears. Existing
legacy TOFU receipts can still be checked cryptographically, but they cannot be upgraded into an
explicit-enrollment claim; start a new run instead.

The public enrollment primitive refuses an existing Ledger and any retained receipts. Because the
manifest digest is predictable and the two paths cannot be created in one filesystem transaction,
creation order ultimately relies on the offline ceremony and filesystem permissions; the manifest is
not cryptographic proof of creation time. It is protected local policy, not a remote/public
authorization signature or exact trusted time. Protect its parent and retain it with receipts.
Paginated mirror sync, key rotation,
multi-witness quorum, hardware-backed keys, remote authenticated transport, and accepted
WORM/transparency retention remain future work. A provider-neutral static export/restore byte contract
now exists in [`receipt-retention.md`](receipt-retention.md); it intentionally makes no delivery claim.

Even with a separate UID, this witness attests only that it observed a fully hash-valid current Ledger
head under a cooperative lock. It does not validate governance semantics, artifacts, candidate quality,
trusted time, or weight loading. Authorized-client abuse can request extra checkpoints or cause DoS.
Witness/root/key compromise can sign forks or delete the authoritative history. Signed time remains
informational.
