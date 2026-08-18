# Owner CPU walkthrough and governance game day

This is the pre-GPU, Owner-facing acceptance drill for Filiolae's current CPU governance kernel. It
uses the real CLI, Gate, content-addressed artifact store, Ledger auditor, Ed25519 receipt verifier,
prime-rl promotion barrier, and weight-update controller. It deliberately covers both authority being
granted and authority being withheld.

**Pass condition:** every stage in the driver ends successfully, including the *expected* nonzero
artifact audit. A pass is evidence for the bounded CPU behaviors below; it is not evidence that a GPU
training run or hostile sandbox is complete.

## Safety and prerequisites

Run on POSIX Linux (WSL2 is suitable) from a trusted checkout. The package supports Python 3.11 and
3.12. Install [`uv`](https://docs.astral.sh/uv/), then prepare exactly the locked repository
environment:

```bash
cd /path/to/filiolae       # your checkout
uv sync --locked
uv lock --check
```

The drill creates new files only under the root you supply and refuses to overwrite an existing root.
The default is the gitignored `.demo/owner-cpu-game-day`. It creates an **unencrypted, disposable
private key** under that root. Do not point the drill at production paths and do not reuse its key.
No GPU, prime-rl checkout, model download, or network service is needed after dependencies exist.

## Run the complete drill

```bash
cd /path/to/filiolae
GAME_ROOT="$PWD/.demo/owner-cpu-game-day"
scripts/owner_cpu_game_day.sh "$GAME_ROOT"
```

The script prints each command, streams its output, and retains command logs alongside the generated
happy and tamper runs. It deliberately leaves evidence in place for inspection. The final lines must
be:

```text
GAME DAY PASS
Evidence and command logs: .../.demo/owner-cpu-game-day
The private key under keys/ is disposable demo material; do not reuse it.
```

Timestamps, PIDs, hashes, key IDs, and absolute paths vary. The semantic expectations below do not.

## What each stage demonstrates

### 1. Happy authorization and Ledger audit

The driver runs the equivalent of:

```bash
uv run filiolae demo "$GAME_ROOT/happy" --charter examples/charter.demo.yaml
uv run filiolae audit "$GAME_ROOT/happy/control/ledger.jsonl" \
  --artifact-root "$GAME_ROOT/happy/control/artifacts" \
  --charter "$GAME_ROOT/happy/control/charter.yaml"
```

Expected demo fields:

```json
{
  "allowed": true,
  "reason": "promotion evidence satisfies Charter",
  "frozen": false,
  "audit": "Governance audit valid: 7 records, 1 promotion(s)"
}
```

Expected audit invariants are `"ok": true`, `"records": 7`, and `"issues": []`. The seven events are
`run.genesis`, the four evidence events, `gate.approved`, and `policy.promoted`. Inspect them without a
special parser:

```bash
uv run python - "$GAME_ROOT/happy/control/ledger.jsonl" <<'PY'
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    record = json.loads(line)
    print(record["seq"], record["event"], record["hash"][:12])
PY
```

Authorization is not a bare Boolean: `gate.approved` binds the Charter digest, evidence sequences,
prior Ledger head, source/target policy versions, attempt ID, and the Gate-owned candidate artifact.
The following `policy.promoted` consumes that approval exactly once.

### 2. Signed-head receipt and combined audit

The driver generates an Ed25519 keypair outside the happy run, signs its terminal Ledger head, checks
the receipt chain with the public key, and supplies that result to the governance audit:

```bash
uv run filiolae anchor-keygen \
  --private-key "$GAME_ROOT/keys/private.pem" \
  --public-key "$GAME_ROOT/keys/public.pem"
uv run filiolae anchor-head "$GAME_ROOT/happy/control/ledger.jsonl" \
  --artifact-root "$GAME_ROOT/happy/control/artifacts" \
  --anchor-dir "$GAME_ROOT/anchors" \
  --private-key "$GAME_ROOT/keys/private.pem"
uv run filiolae verify-anchors "$GAME_ROOT/happy/control/ledger.jsonl" \
  --artifact-root "$GAME_ROOT/happy/control/artifacts" \
  --anchor-dir "$GAME_ROOT/anchors" \
  --public-key "$GAME_ROOT/keys/public.pem"
uv run filiolae audit "$GAME_ROOT/happy/control/ledger.jsonl" \
  --artifact-root "$GAME_ROOT/happy/control/artifacts" \
  --charter "$GAME_ROOT/happy/control/charter.yaml" \
  --anchor-dir "$GAME_ROOT/anchors" \
  --anchor-public-key "$GAME_ROOT/keys/public.pem"
```

`verify-anchors` must report `"ok": true`, `"current_head_anchored": true`, and `"receipts": 1`.
The combined audit must additionally report `"anchors_checked": true`, `"anchor_receipts": 1`, and
`"unanchored_tail_records": 0`.

This is a **post-run local checkpoint demonstration**. The CPU demo's genesis does not require signed
pre-authorization heads. The governed prime-rl launcher can require those by configuring its local or
Unix-witness mode; see [signed-head-checkpoints.md](signed-head-checkpoints.md) and
[unix-witness.md](unix-witness.md). Do not infer that this drill's same-user local key is an
independent witness.

### 3. Artifact tampering, denial, and freeze

The tamper scenario corrupts the Gate-owned stored rollout batch after attestation and before asking
the Gate for promotion:

```bash
uv run filiolae demo "$GAME_ROOT/tamper" \
  --charter examples/charter.demo.yaml --tamper
```

The demo command itself exits zero because successful detection is the expected scenario. Its result
must include `"allowed": false`, `"frozen": true`, and a reason beginning `artifact integrity
failure`. The durable freeze marker is:

```bash
cat "$GAME_ROOT/tamper/control/freeze.json"
```

It must use schema `filiolae.freeze.v1`, name the artifact mismatch, and bind `details.step` to `1`.
Within this run there is no unfreeze API; a subsequent Gate request remains denied. This demo does not
launch a workload process, so the marker is the demonstrated brake here, not process termination.

A full artifact audit is also required to fail:

```bash
set +e
uv run filiolae audit "$GAME_ROOT/tamper/control/ledger.jsonl" \
  --artifact-root "$GAME_ROOT/tamper/control/artifacts" \
  --charter "$GAME_ROOT/tamper/control/charter.yaml"
status=$?
set -e
test "$status" -eq 1
```

Expected JSON includes `"ok": false` and an issue with `"code": "artifact_mismatch"` at sequence 2.
The Ledger hash chain can remain structurally intact while a bound artifact is corrupt; this is why a
normal (not `--chain-only`) audit is mandatory for acceptance.

### 4. Bounded authorization timeout

The driver runs two fault-injection tests:

```bash
uv run pytest -vv \
  tests/test_anchor.py::test_anchor_timeout_causes_zero_loads_and_no_late_approval \
  tests/test_prime_rl_entrypoint.py::test_real_barrier_timeout_freezes_and_never_loads
```

Expected result: `2 passed`. Together these exercise a timeout through the real promotion barrier and
a delayed signed-head acknowledgement. The assertions require: no call to the weight loader, a
latched freeze, and (for the signed case) no `gate.approved` record appearing after cancellation. The
slow operation is intentional test injection, not a performance benchmark.

### 5. Approved load failure

The driver runs:

```bash
uv run pytest -vv \
  tests/test_owner_cpu_walkthrough.py::test_real_load_failure_freezes_and_is_auditable
```

Expected result: `1 passed`. This uses the real Gate and `PrimeRLPromotionBarrier`. The controller
receives only the Gate-owned staged path, the injected loader fails, and the durable event suffix must
be:

```text
gate.approved, tripwire.fired, weights.load_failed
```

`policy.promoted` must be absent, the run must be frozen, and the full governance audit must still be
valid. “Audit valid” here means the failure was consistently and completely recorded; it does **not**
mean the run succeeded. Pytest owns and removes this scenario's temporary directory, while the
retained script log records the assertion result.

## Component boundary and non-claim review

| Component exercised | Bounded claim | Explicit boundary / non-claim |
|---|---|---|
| Charter | The Gate checks the genesis Charter digest and required hard rules. | The demo Charter is not a human multisignature amendment system and does not establish policy quality. |
| ArtifactStore | Exact regular-file/directory bytes are copied into a content-addressed Gate store and rehashed before authorization. | A same-UID or root attacker can modify local files; Filiolae detects checked corruption rather than making the filesystem WORM. |
| Ledger + auditor | Canonical JSONL records form a hash chain; semantic audit binds approvals, outcomes, Charter, and artifacts. | A local file is not independently retained. Omitted events before observation and joint rollback/deletion require an external control or witness to address. |
| Promotion Gate/barrier | Evidence precedes single-use authority; timeout, denial, and load failure do not return authority to advance policy state. | The CPU demo simulates the pipeline. Enforcement in prime-rl requires the pinned fail-closed host patch and filesystem weight transport. |
| Freeze + supervisor | Freeze state is fail-closed; separate tests cover process-group TERM/KILL behavior. | This drill's demo does not spawn a supervised tree. A POSIX process group is not a hostile sandbox; `setsid`, same-host root/kernel, and missing cgroup/service-manager isolation remain boundaries. |
| Ed25519 receipt | The public key detects receipt/chain/head mismatch, stale heads, reordering, and deletion visible to the verifier. | A local receipt is not trusted time, public timestamping, transparency-log inclusion, WORM storage, signer non-equivocation, or proof to a third party. |
| Evaluation evidence | The source-policy/run lineage artifact is bound into promotion evidence. | Candidate-quality evaluation, Watchtower independence, remote witness retention, GPU execution, and the two-GPU smoke run are not demonstrated. |

Also note that `--chain-only` intentionally skips artifact verification and semantic governance checks;
it is diagnostic, never the Owner acceptance command.

## Evidence to retain and sign-off checklist

Retain the whole game root (excluding the private key if evidence leaves the trusted machine). At
minimum review:

- `happy-demo.log`, `happy-audit.log`, `signed-audit.log`, and `anchor-verify.log`;
- `happy/control/ledger.jsonl`, the copied Charter, artifact tree, public key, and receipt directory;
- `tamper-demo.log`, `tamper-audit.log`, and `tamper/control/freeze.json`;
- `timeout-tests.log` and `load-failure-test.log`;
- the Filiolae git commit ID (`git rev-parse HEAD`) and `uv.lock` digest (`sha256sum uv.lock`).

Owner sign-off requires all of the following:

- [ ] Happy Gate approval and exactly one promotion audited.
- [ ] Current Ledger head verified by the disposable public key and combined audit.
- [ ] Stored-artifact tampering denied, frozen, and independently rediscovered by audit.
- [ ] Both timeout tests passed with zero loads and no late signed approval.
- [ ] Load failure produced a failure outcome, no promotion, a freeze, and a valid failure trail.
- [ ] The boundary/non-claim table was reviewed without upgrading any claim.

## Troubleshooting

- **Exit 64 / root already exists:** preservation is deliberate. Inspect or rename the prior root, then
  remove it explicitly before rerunning. The demo itself also refuses an existing scenario root.
- **`uv` or environment failure:** run `uv sync --locked`, then `uv lock --check`. Do not substitute a
  globally installed `filiolae`; all commands above intentionally use the repository environment.
- **Tamper audit exits 1:** this is the required result. The driver captures and checks that status. A
  zero exit is a game-day failure.
- **Wrong artifact root:** use the copied run paths exactly as shown. Passing `happy/control` instead
  of `happy/control/artifacts` produces missing-artifact findings.
- **Private-key rejection:** private keys must be regular, non-symlink files with no group/other read
  bits. The key generator creates mode 0600. Do not weaken the mode; create a fresh game root.
- **`current_head_anchored: false`:** the Ledger changed after its last receipt. Investigate the new
  tail first; if legitimate, append a new checkpoint with `anchor-head` and verify the entire receipt
  chain again. Do not use `--allow-stale` for acceptance.
- **A timeout test fails on an overloaded host:** preserve the log and rerun once on an otherwise idle
  host. These are deliberately short deterministic fault injections; do not reinterpret a failure as
  a successful safety result.
- **Need process-kill evidence:** additionally run
  `uv run pytest -vv tests/test_supervisor.py`; that validates freeze-killed descendants and
  TERM-to-KILL escalation, still subject to the process-group non-claim above.

## Cleanup

First capture anything needed for review, and confirm the exact target:

```bash
printf 'Removing %q\n' "$GAME_ROOT"
find "$GAME_ROOT" -maxdepth 2 -type f -print
rm -rf -- "$GAME_ROOT"
unset GAME_ROOT
```

Cleanup destroys the disposable key, receipts, logs, and generated evidence. It does not alter tracked
repository files.
