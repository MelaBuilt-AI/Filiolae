# Priority 6 v2 Gate D replacement pre-training stop — 2026-08-13

This package preserves the Owner-authorized replacement Gate D lifecycle as a **failed-closed
pre-training attempt**, not candidate-quality evidence.

Exact replacement pod `90c6ea20fe7a4fa9abd680248f4789ed` was created from a fresh Massed
Compute A6000 48 GB quote at $0.54/hour. Its independent external exact-ID watchdog was active
before uploads or remote commands, with absolute deadline `2026-08-14T02:26:56Z`.

The first immutable detached driver ran as root while the host-preparation contract requires a
non-root user and stopped before dependency installation. Owner's explicit follow-up authorization
was applied to one corrected invocation on the same pod, not another resource. That invocation ran
as `ubuntu` with managed Python 3.12.3 and completed pinned dependency installation, metadata
retrieval, GPU checks, and network-isolation preflight. It then stopped before loading a model:
the driver had created `run-output` for lifecycle logging, while `gate_d_runtime.py` correctly
refuses to overwrite any existing output root.

Consequently, there was no source inference, SFT batch or round, visible evaluation, candidate
freeze, readiness plaintext release, readiness attempt, final-suite release, or Gate F operation.
Gate D has no score and the holdback is unburned.

Exact-ID cleanup terminated the pod after 20 minutes. Prime history reports raw `total_cost=1603`;
using the account's established 1/10,000 normalization gives $0.1603 (also below the $0.18
quote-times-duration bound). The idempotent exact route now returns `already-terminated`, its
watchdog is disabled, and the account lists zero active pods.

`STOP-RECORD.json` is the canonical interpretation. `REMOTE-OBSERVATIONS.json` preserves the exact
bounded execution facts; the other JSON files preserve quote, identity, watchdog, termination,
history, and zero-resource evidence. No private machine path or credential is retained.

The replacement and its authorized same-pod follow-up are consumed. Another driver invocation or
Gate D pod requires renewed Owner authorization. Gate F remains unused and ineligible. The repaired
repository driver keeps lifecycle records outside the model runtime output root and has a regression
test, but it has not been executed as Gate D evidence.

Run `sha256sum -c SHA256SUMS` here to verify every retained file except the checksum manifest.
