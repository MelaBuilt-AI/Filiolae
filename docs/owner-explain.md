# Owner-readable run explanation

`filiolae explain RUN_DIRECTORY` turns retained governance evidence into a bounded human report. It
auto-detects only the two supported layouts (`control/` for the CPU demo and `control/filiolae/` for
the governed launcher), refuses ambiguous layouts, verifies the Ledger, Charter, and retained artifact
bytes, then summarizes recorded approvals, denials, load outcomes, freeze reasons, exact recorded
Gate-owned weight identities, ambiguities, and current non-claims.

```bash
filiolae explain /srv/filiolae/runs/run-123
filiolae explain /srv/filiolae/runs/run-123 --json
```

External trust roots are never searched for automatically. Supply them explicitly when applicable:

```bash
filiolae explain RUN \
  --anchor-dir /var/lib/filiolae-witness/run-123 \
  --anchor-public-key /etc/filiolae/ed25519-public.pem \
  --witness-enrollment /var/lib/filiolae-witness/run-123/enrollment.json \
  --candidate-eval-public-key /etc/filiolae/evaluator-public.pem
```

A Unix-witness run requires the retained enrollment manifest as well as its receipts and public key;
omitting any of those trust inputs makes the audit incomplete and the command exits nonzero. The
anchor verification path used by `explain` opens only existing lock/store state and never provisions
evidence directories or lock files. Output arrays are capped (`--max-items`, maximum 100), and a
pre-hash traversal rejects retained artifact sets above 1,000,000 filesystem entries or 64 GiB of
actual regular-file bytes.
If structural Ledger verification fails, all event-derived history is intentionally suppressed. An
unconsumed approval is reported as ambiguous and requires freeze/reconciliation. Exit 0 means the
checks required by the retained policy passed; exit 1 means invalid, incomplete, ambiguous, or
required external verification material was absent.

The report explains what retained bytes support. It does not independently prove event completeness,
an actual model load, external/WORM retention, witness independence, production containment, GPU
execution, or model quality.
