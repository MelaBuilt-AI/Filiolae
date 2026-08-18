# Native systemd/cgroup-v2 acceptance evidence — 2026-08-12

This directory preserves the complete evidence archive and machine-readable summaries from private
GitHub Actions run `31561250307`.
The run passed the bounded S0–S4 and S6 verdict against Filiolae commit
`35529fec51727d360a77b41f56a19134cde94d80` on an admitted GitHub-hosted Ubuntu 24.04 Microsoft VM
with systemd as PID 1 and unified cgroup v2.

The result demonstrates, for this exact reference CPU deployment:

- distinct witness/orchestrator numeric UIDs and protected key/receipt domains;
- a root-owned fixed shared lock and tested filesystem permissions;
- witnessed baseline authorization and promotion;
- `BindsTo=` crash propagation and cgroup-wide removal of a hostile `setsid` descendant;
- witness timeout, fail-closed freeze/denial, later anchor reconciliation, and no later authority;
- missing/unusable startup prerequisites fail without a load or promotion; and
- complete cleanup with no active units, harness process, populated test cgroup, or exported private key.

S5 deterministic lost-response injection was explicitly excluded rather than approximated with a
race. Reboot persistence, production security, remote/WORM retention, trusted time, evaluator
isolation, candidate quality, GPU-device containment, and publication readiness remain non-claims.

## Independent verification

The downloaded sidecar matched the archive SHA-256. Safe extraction found 567 regular/directory
members and no unsafe member; all 469 entries in the archive's `SHA256SUMS` matched. The canonical
facts and asset hashes are in `manifest.json`. Run `sha256sum -c SHA256SUMS` in this directory to
verify the preserved files. The workflow-produced archive uses `game-day/GAME-DAY-REPORT.json` as
its semantic manifest; subsequent runner code also emits the explicitly planned `MANIFEST.json`
alias.

The two failed predecessor runs are retained by GitHub only as diagnostic artifacts. They exposed
and led to fixes for exact-once lock creation (`d6fc833`) and a service interpreter hidden by
`ProtectHome` (`35529fe`); neither is represented as acceptance.
