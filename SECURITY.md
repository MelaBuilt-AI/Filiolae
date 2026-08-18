# Security boundary

Filiolae Phase 1 is pre-alpha research software. The canonical evidence scope and open gaps are in
the [`capability-and-gap matrix`](docs/capability-and-gap-matrix.md).

## Fail-closed claims implemented and tested

- Any malformed Ledger, broken hash link, modified bound artifact, missing evidence type, false or
  stale source version, skipped target version, wrong pending weights, unknown Charter rule, replayed
  approval, or prior tripwire denies promotion.
- The Gate returns a gate-owned content-addressed weights path; an integration must load that exact
  path, never the trainer-owned source after authorization.
- An authorization intent without a promotion or failure outcome is an audit error requiring freeze
  and human reconciliation.
- Authorization denial/fault/timeout causes zero calls to the weight loader; load or outcome failure
  freezes before version state may advance.
- The CPU supervisor holds target exec until a post-spawn freeze check, latches observed freeze state,
  and signals the dedicated POSIX process group with TERM then KILL.
- When configured as required, the Gate obtains and verifies an Ed25519 receipt for its exact evidence
  head before approval; outcome heads are checkpointed and signature/store failure freezes.
- Experimental witness mode removes the private key from the governed orchestrator, requires a
  one-time path/run/Charter/signer enrollment digest in genesis, restricts the socket by peer UID,
  verifies the actual locked head, and requires a pinned public key plus durable Gate mirror.
- When a hard candidate shadow-evaluation clause is present, a missing, malformed, stale, failed,
  wrong-key/digest, below-quality, or over-regression receipt denies/freezes before any weight load;
  offline audit reverifies the signed receipt with its explicitly supplied public key.

## Deployment preconditions not supplied by this repository

- independent host/credential domain for Gate, Ledger, content store, and supervisor;
- OS permissions preventing governed processes from deleting freeze state or modifying governance
  artifacts;
- cgroup/service-manager termination wired to freeze state (the included POSIX process group is not
  an adversarial child-tree boundary);
- independently monitored transparency publication of signed Ledger-head receipts to resist joint
  Ledger+receipt rollback and expose signer/log forks. The Unix witness separates credentials, the static
  exporter prepares exact bytes, and bounded local S1/S2 acceptance verifies RFC 6962/C2SP
  interoperability plus a same-UID Tessera loopback/two-monitor failure laboratory; accepted public
  inclusion, separate administration, witness cosigning, gossip/cross-logging, and Gate coupling remain
  deployment work;
- fresh site validation of the governed launcher and fatal propagation after any governed-runtime,
  adapter, payload, topology, or safety-control change;
- sandboxing and network/resource policy for rollout environments;
- a separately credentialed candidate evaluator whose private key and terminal-result write authority
  are unreachable by the controller/learner. Bounded distinct-UID CPU protocol acceptance and one
  narrow Priority 6 v2 final path passed, but fresh-site production evaluator administration and
  independent reproduction remain deployment work.

## Explicit non-claims

- Stock `VersionObserver` is not an enforcement point.
- Local SHA-256 is not a digital signature. Ed25519 checkpoint receipts are signatures, but local
  storage is not a public timestamp, transparency-log inclusion, WORM retention, or third-party proof.
  `retention-export` and `retention-verify` prove only package/restore byte integrity against an
  out-of-band key; their JSON output intentionally reports `provider_retention_verified: false`. Local
  transparency roots, proofs, checkpoints, and bounded loopback monitor tests are local protocol
  evidence—not proof that any third party observed, cosigned, retained, timestamped, or publicly served
  a receipt. S2 used disjoint processes/directories under one Unix UID, not independent administration.
- Unix witness enrollment is explicit and one-time, but remains protected local policy rather than a
  remote/public authorization signature. The witness uses advisory locks and attests only hash-chain
  observation—not governance semantics, artifact truth, candidate quality, or trusted time. Separate
  UIDs, protected ownership, and the shared lock remain deployment preconditions.
- `source_eval.result` is not proof that candidate weights passed a shadow evaluation. The Priority 6
  worker verifies the exact executing evaluator bundle, source/candidate inputs, terminal recovery,
  and signed complete-output package. Stage 1 passed a bounded distinct-UID CPU rehearsal, and Priority
  6 v2 passed one bounded one-use real-model path (256/256 readiness; 127/128 final) with a single
  disposable promotion. Those results do not establish independent reproduction, general model
  quality, production evaluator security, or deployment fitness; the candidate and suites are consumed.
- JSONL cannot make weight loading and durable outcome recording one atomic transaction; ambiguous
  crash states must freeze and reconcile.
- The CPU demo does not validate the two-GPU `prime-rl` topology.
- A POSIX process group cannot contain a child permitted to call `setsid`/`setpgid`; use cgroup v2 or
  an equivalent service boundary before claiming hostile child-tree termination.


## Supported versions and vulnerability reporting

No Filiolae version is production-supported yet. Pre-alpha commits may receive security fixes only on
the current development branch; there is no stability, response-time, embargo, or support guarantee.

Use GitHub Private Vulnerability Reporting at
<https://github.com/MelaBuilt-AI/Filiolae/security/advisories/new>. Do not place sensitive exploit
details in a public issue, discussion, or pull request. Include the affected commit, threat-boundary
assumptions, minimal reproducer, impact, and suggested coordination window.

GitHub exposes that route only after the repository is public and private reporting is enabled. The
visibility runbook therefore requires enabling and verifying it before announcement; failure closes
or reverts the preview gate rather than silently falling back to public disclosure.
