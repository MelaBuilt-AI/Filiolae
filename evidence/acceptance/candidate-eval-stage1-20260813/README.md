# Priority 6 Stage 1 CPU protocol rehearsal evidence

Status: **process-separated protocol rehearsal passed; separate-OS-credential acceptance pending**.

This package records a network-free deterministic CPU fixture run over the exact preserved r18
step-1 source and step-2 candidate trees. The evaluator worker required its exact request digest on an evaluator-owned allowlist, independently rehashed both model
trees, verified the frozen source manifest/suite/config and its exact code bundle, signed the receipt
and complete per-case output package, durably committed the terminal result, intentionally returned a
lost-response exit, and the controller recovered and reverified the byte-identical terminal result.

The recorded 10,000-bps fixture scores are **not model inference or model-quality evidence**. The
worker had a distinct PID but the same UID as the controller. Passwordless `sudo` was unavailable and
an unprivileged `setpriv` UID transition failed, so this daily WSL host could not honestly execute the
planned separate-UID stage. `credential-probe.json` records that boundary. No private signing key is
retained.

Exact large source/candidate model trees are not duplicated here. They remain bound to the preserved
r18 archive SHA-256 `99dfa460d2ff1266ffb27183eae7988f866178b842c804a7862e983d047e3bde`.
`controller-summary.json`, the canonical request, public key, signed receipt, signed complete-output
evidence, frozen inputs, and checksum inventory are retained here.
