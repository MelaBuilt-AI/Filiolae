# Tessera loopback shadow plan (S2)

Status: **executed; bounded S2 acceptance passed**

Date: 2026-08-13

## Purpose and authorization boundary

S2 will test a thin Filiolae receipt personality over Tessera's POSIX storage on a
single POSIX host. It is a private, loopback-only laboratory using synthetic
receipts and two complete monitor processes. It does not create a public or
private-network service and does not change receipt v1, witness v2, Gate CAS, or
promotion authority.

This document was the required pre-start review artifact. Owner authorized execution on
2026-08-13. The bounded run passed; see
[the S2 acceptance report](tessera-loopback-shadow-acceptance.md). That authorization covered only
the completed synthetic loopback run and does not authorize a persistent, private-network, public,
cloud, witness, production-receipt, or Gate-coupled service.

## Pinned upstream and build inputs

The first implementation will pin the stable Tessera release `v1.0.4`, exact
commit `6bca8e8d5e23c9941f2b8a08f512b373f7131730`, rather than `main`. The reviewed
release supports the POSIX appender, tlog-tiles static resources, checkpoints,
and witness seams and requires Go 1.24 or newer. The laboratory will use the same
exact Go `1.25.12` toolchain as S1 and commit its own `go.mod` and `go.sum`.

Before execution, re-check the release tag signature/provenance, vulnerability
reports, license, transitive module graph, and any security fixes published after
this plan. A version change requires updating this plan and dependency diff before
start; it must never silently float to `main` or `latest`.

## Components and isolation

### 1. Filiolae Tessera personality

A small Go binary will import Tessera as a library; the upstream conformance server
will not be deployed unchanged. Required behavior:

- create a `posix.Config` rooted in a dedicated empty directory;
- listen through `net.Listen("tcp4", "127.0.0.1:0")`; the S2 build exposes no
  address flag and rejects inherited non-loopback listeners;
- accept only `POST /add` with the Filiolae leaf media type, a strict content
  length of at most 64 KiB, and canonical
  `filiolae.receipt-transparency-leaf.v1` bytes that pass signature validation;
- accept only keys/run IDs from the checked-in synthetic S2 trust fixture;
- serve only `GET /checkpoint`, `/tile/...`, and `/tile/entries/...`; never serve
  Tessera `.state`, directory listings, arbitrary paths, or write endpoints;
- use bounded request bodies, header/read/write/idle timeouts, connection limits,
  and explicit HTTP status/error bodies that disclose no filesystem path;
- read the synthetic signed-note private key from a mode-0600 file descriptor,
  never from an environment variable or command line;
- batch deterministically for the test, shut down cleanly, and emit a local JSONL
  event record without leaf bodies or key material.

The append response will report only the assigned index and leaf SHA-256. Duplicate
leaf handling will be explicit: duplicates are allowed by transparency semantics
and are never represented as proof that only one append occurred.

### 2. Monitor A — Filiolae/Python

A standalone process will use Filiolae's strict leaf/checkpoint parsers and Merkle
implementation. It may read only through the loopback HTTP read surface. Its own
mode-0700 mirror root stores exact leaves, immutable-resource digests, checkpoint
history, consistency evidence, and atomic state updates. It has no log-storage or
signing-key access.

### 3. Monitor B — independent Go

A separate Go process will use the pinned Transparency.Dev Merkle implementation
and `sumdb/note`, plus the C2SP tlog-tiles layout. It will independently download
all entries, reconstruct roots, verify checkpoints/growth, and maintain a separate
mode-0700 mirror. It shares no code, mutable files, lock, cache, or state database
with Monitor A.

Where native user creation is available, log, monitor A, and monitor B run under
three unprivileged UIDs. Otherwise S2 may proceed only as a process-isolation lab:
separate process groups, umask 077, disjoint roots, no direct cross-component file
access, and an explicit non-claim of UID isolation. The coordinator receives only
read-only final reports after child shutdown.

## Network containment

- IPv4 loopback only; no wildcard, IPv6, Unix-to-LAN proxy, DNS name, container
  port publication, tunnel, or reverse proxy.
- The coordinator records the kernel-assigned port through a mode-0600 pipe/file;
  no predictable fixed port is required.
- Before the first append and after every restart, inspect listening sockets and
  fail unless the sole personality listener is `127.0.0.1:<ephemeral>`.
- Test clients use an allowlisted transport that rejects redirects, proxies,
  non-loopback resolved addresses, and URLs containing user information.
- Clear proxy environment variables for every child. Packet capture is optional
  evidence, not the primary boundary.

## Acceptance sequence

Each case starts from declared state, has a deadline, and saves commands, process
identities, socket inventory, logs, exact inputs, checkpoints, mirror manifests,
and checksums.

1. **S2.0 — preflight and synthetic fixture.** Verify dependency pins, empty roots,
   file modes, loopback-only listener, disjoint process/mirror roots, and zero
   production receipts. Refuse any leaf not signed by the synthetic fixture key.
2. **S2.1 — baseline complete mirrors.** Append at least nine synthetic leaves in
   deterministic one-at-a-time order. Both monitors independently obtain every
   exact leaf, verify each receipt, reconstruct every observed checkpoint root,
   verify append-only growth, and agree on final size/root and leaf bytes.
3. **S2.2 — restart and rebuild.** Stop all processes cleanly, retain only Tessera
   POSIX state, restart on a new ephemeral port, and rebuild each monitor once from
   empty storage. Existing indices and immutable bytes must remain unchanged; new
   appends must extend the prior checkpoint with valid consistency evidence.
4. **S2.3 — partial tile/read interruption.** A loopback-only fault shim truncates
   one entry/tile response and then disappears. Neither monitor advances its
   accepted checkpoint or writes a complete-resource marker; both report bounded
   `suspect` state and recover after receiving the exact resource.
5. **S2.4 — lost append response.** The shim forwards one valid append and drops
   the response. The coordinator treats outcome as unknown, never as failure or
   success, and resolves it only through complete monitor observation. A retry may
   create a duplicate; if so, both indices and identical leaves must be visible and
   valid. No missing or mutated accepted leaf is permitted.
6. **S2.5 — immutable-resource conflict.** The shim serves changed bytes for a URL
   previously recorded as immutable. Both monitors preserve old/new bytes and
   metadata, enter `forked` or `suspect` according to whether signed checkpoints
   conflict, and refuse silent replacement or checkpoint advancement.
7. **S2.6 — crash and cleanup.** Kill the personality during a bounded batch,
   restart, and require Tessera recovery to expose either no assigned index or a
   fully integrated exact leaf—never a false success. Stop every process, verify
   zero listeners/descendants, remove synthetic private keys, and retain only the
   checksummed acceptance bundle.

## Pass criteria

S2 passes only when all cases are deterministic and both monitors:

- preserve complete exact leaf sequences and independently reconstruct each
  accepted root;
- reject invalid signatures, noncanonical leaves, rollback, inconsistent growth,
  same-size forks, truncated resources, and changed immutable bytes;
- never advance durable state on an unverified checkpoint/resource;
- recover from restart using only their own empty or prior mirror plus the public
  read surface;
- alarm within declared local deadlines and leave self-contained evidence;
- terminate with no listener, child process, or synthetic private key remaining.

The acceptance archive will contain a canonical manifest and SHA-256 inventory,
source/dependency lockfiles, tool versions, process/socket evidence, injected fault
scripts, exact synthetic leaves, signed checkpoints, both complete mirrors, alarm
packets, and a plain-language result. Any exclusion is listed as an exclusion, not
a pass.

## Execution result

All S2.0–S2.6 cases passed in the canonical rerun. The personality and both monitors are retained as
source and CI build/test targets, not as a running service. The final size was 16 with root
`f9d6db4e49cbf86a0fb06f4444b3950bfcb1eb8f73191a54ae283a84ac10790d`. The complete result,
including the pre-acceptance harness correction and evidence checksum, is in
[the S2 acceptance report](tessera-loopback-shadow-acceptance.md).

## Stop conditions and non-claims

Stop immediately on a non-loopback listener, production-looking receipt/key,
unexpected egress, unbounded memory/disk growth, inability to distinguish the two
mirror roots, residual process, unverifiable checkpoint, or dependency drift.

Even a full S2 pass does **not** establish public reachability, independent
administration, witness quorum, trusted time, durable public retention, split-view
resistance across networks, cloud suitability, production containment, or release
readiness. S3 remains the first isolated witness/split-view game day. Gate coupling
remains deferred to S6 and requires a separate Owner decision.
