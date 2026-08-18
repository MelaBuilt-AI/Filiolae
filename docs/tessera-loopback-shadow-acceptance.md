# Tessera loopback shadow acceptance (S2)

Status: **passed bounded local acceptance**

Date: 2026-08-13

Tested Filiolae implementation/evidence commit:
`f940d1e9493de50c6561f83b3a11f88d0ed5ac8f`

Tessera: `v1.0.4`, commit `6bca8e8d5e23c9941f2b8a08f512b373f7131730`

## Result

The reviewed S2 plan passed in a synthetic, same-host, separate-process laboratory. A strict Go
Filiolae personality used Tessera's POSIX driver and listened only on kernel-selected IPv4 loopback
ports. A Filiolae/Python monitor and an independent Go/Transparency.Dev monitor maintained disjoint
mode-0700 complete mirrors and agreed on every accepted final size/root.

Final tree size: **16**.

Final root:

```text
f9d6db4e49cbf86a0fb06f4444b3950bfcb1eb8f73191a54ae283a84ac10790d
```

Canonical evidence: `evidence/acceptance/transparency-s2-20260813/`.

`SHA256SUMS` SHA-256:

```text
09f275d3f02f645228a30bebba95c5c63403b77f18ff1be1a518ef8a2340eafc
```

All 204 inventoried files passed fresh checksum verification. The retained bundle contains no
synthetic checkpoint private key or Tessera private `.state` directory. Before repository retention,
machine-local absolute paths in the command transcript and coordinator's toolchain bootstrap were
replaced with portable placeholders/`Path.home()`; `PACKAGE.json` preserves the original file and
pre-sanitization inventory hashes and records that no semantic acceptance artifact changed.

## Cases

| Case | Result | Evidence established |
|---|---|---|
| S2.0 preflight | Passed | Exact pins and file modes; the personality was the sole S2 personality and had exactly one `127.0.0.1:<ephemeral>` listener; malformed leaf, `.state`, directory, and arbitrary paths were rejected. |
| S2.1 baseline | Passed | Nine deterministic signed synthetic leaves received contiguous indices. Both complete mirrors validated every leaf and agreed on the checkpoint root. |
| S2.2 restart/rebuild | Passed | Clean stop and restart selected a new ephemeral port. Both monitors rebuilt size 9 from empty independent roots; growth 9→11 preserved old bytes and produced matching consistency proofs. |
| S2.3 partial resource | Passed | A loopback fault shim truncated the size-12 entry bundle for both monitors. Both entered `suspect`, wrote no accepted state, then recovered from the exact resource. |
| S2.4 lost response | Passed | The shim forwarded and published an append but dropped its response. The caller retained `unknown`; complete mirrors resolved inclusion. Retrying created a second explicit identical leaf at a different index. |
| S2.5 immutable conflict | Passed | The shim changed bytes at the previously observed `/tile/entries/000.p/9` URL. Both monitors preserved conflict bytes, refused state growth 14→15, and recovered only after exact bytes returned. |
| S2.6 crash/cleanup | Passed | The personality received SIGKILL during an append. The client outcome was `unknown`; restart exposed the valid prior size 15, never false success or partial authority. A later exact append reached size 16. Final clean stop left no S2 process, listener, or private key. |

## Implementation boundary

The personality:

- imports pinned Tessera as a library rather than deploying its conformance server;
- obtains its synthetic note key only through an already-open mode-0600 descriptor;
- accepts only canonical, correctly signed `filiolae.receipt-transparency-leaf.v1` leaves under the
  checked-in synthetic key/run namespace;
- exposes only `POST /add`, `GET /checkpoint`, and validated tile/entry paths;
- uses bounded bodies, connection count, deadlines, error bodies, and static immutable-resource
  serving; and
- returns only index and leaf digest after Tessera reports publication.

Both monitor transports reject proxies, redirects, credentials in URLs, and non-loopback dials.
Accepted state is atomically replaced only after checkpoint signature, complete leaf sequence,
root, immutable-resource history, and growth checks pass.

## Dependency review

At execution, Tessera `v1.0.4` remained the latest stable release and GitHub listed no repository
security advisories. Its exact release commit is unsigned; this fact is retained rather than
presented as provenance. The project is Apache-2.0. `govulncheck v1.1.4` reported **zero called-symbol
vulnerabilities**. It also reported one advisory in an imported package and 23 in required modules
whose vulnerable symbols/packages were not reached by the S2 call graph. The verbose report is in
the evidence bundle. This is acceptable only for the bounded synthetic loopback result, not a
production dependency approval.

## Pre-acceptance correction

An initial non-canonical rehearsal aborted because its socket checker incorrectly treated the normal
peer column `0.0.0.0:*` in `ss` output as a wildcard local bind. Because startup had raised before
returning its process handle, that rehearsal process was not cleaned by the first harness version.
The independent post-run process check found it; the process was terminated, the contaminated
provisional evidence was deleted, and the harness was corrected to clean children on startup
exceptions and require that the new personality is the sole active S2 personality. The acceptance
reported above was then rerun from a clean preflight and passed fresh checksum/process/listener checks.
No production receipt or non-loopback service was involved.

## Non-claims

S2 used separate processes and disjoint mode-0700 roots under the **same Unix UID**. It is not a
separate-credential or production containment result. It does not establish public transparency,
independent administration, witness quorum, trusted time, durable public retention, multi-network
split-view resistance, cloud suitability, Gate coupling, real candidate quality, or release
readiness. S3 remains the isolated witness/split-view game day and requires a new authorization.
