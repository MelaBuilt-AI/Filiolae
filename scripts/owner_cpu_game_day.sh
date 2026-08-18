#!/usr/bin/env bash
# Reproducible Owner-facing CPU governance walkthrough. Run from any directory.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GAME_ROOT="${1:-$REPO_ROOT/.demo/owner-cpu-game-day}"

if [[ -e "$GAME_ROOT" ]]; then
  printf 'Refusing to overwrite existing game-day root: %s\n' "$GAME_ROOT" >&2
  printf 'Inspect it, then remove it explicitly before rerunning.\n' >&2
  exit 64
fi
mkdir -p "$GAME_ROOT"
cd "$REPO_ROOT"

section() {
  printf '\n========== %s ==========\n' "$1"
}

run_logged() {
  local name="$1"
  shift
  printf '+ '
  printf '%q ' "$@"
  printf '\n'
  "$@" 2>&1 | tee "$GAME_ROOT/$name.log"
}

section '1/5 happy authorization and full Ledger audit'
run_logged happy-demo uv run filiolae demo "$GAME_ROOT/happy" \
  --charter examples/charter.demo.yaml
run_logged happy-audit uv run filiolae audit "$GAME_ROOT/happy/control/ledger.jsonl" \
  --artifact-root "$GAME_ROOT/happy/control/artifacts" \
  --charter "$GAME_ROOT/happy/control/charter.yaml"

section '2/5 local signed-head checkpoint and combined audit'
run_logged anchor-keygen uv run filiolae anchor-keygen \
  --private-key "$GAME_ROOT/keys/private.pem" \
  --public-key "$GAME_ROOT/keys/public.pem"
run_logged anchor-head uv run filiolae anchor-head "$GAME_ROOT/happy/control/ledger.jsonl" \
  --artifact-root "$GAME_ROOT/happy/control/artifacts" \
  --anchor-dir "$GAME_ROOT/anchors" \
  --private-key "$GAME_ROOT/keys/private.pem"
run_logged anchor-verify uv run filiolae verify-anchors \
  "$GAME_ROOT/happy/control/ledger.jsonl" \
  --artifact-root "$GAME_ROOT/happy/control/artifacts" \
  --anchor-dir "$GAME_ROOT/anchors" \
  --public-key "$GAME_ROOT/keys/public.pem"
run_logged signed-audit uv run filiolae audit "$GAME_ROOT/happy/control/ledger.jsonl" \
  --artifact-root "$GAME_ROOT/happy/control/artifacts" \
  --charter "$GAME_ROOT/happy/control/charter.yaml" \
  --anchor-dir "$GAME_ROOT/anchors" \
  --anchor-public-key "$GAME_ROOT/keys/public.pem"

section '3/5 artifact tampering, denial, and irreversible freeze'
run_logged tamper-demo uv run filiolae demo "$GAME_ROOT/tamper" \
  --charter examples/charter.demo.yaml --tamper
printf '+ uv run filiolae audit ... (exit 1 is required here)\n'
set +e
uv run filiolae audit "$GAME_ROOT/tamper/control/ledger.jsonl" \
  --artifact-root "$GAME_ROOT/tamper/control/artifacts" \
  --charter "$GAME_ROOT/tamper/control/charter.yaml" \
  2>&1 | tee "$GAME_ROOT/tamper-audit.log"
tamper_audit_status="${PIPESTATUS[0]}"
set -e
if [[ "$tamper_audit_status" -ne 1 ]]; then
  printf 'Expected tampered audit to exit 1, got %s\n' "$tamper_audit_status" >&2
  exit 1
fi
printf 'Expected audit failure observed (exit 1). Freeze marker:\n'
cat "$GAME_ROOT/tamper/control/freeze.json"

section '4/5 bounded timeout: zero loads, frozen, no late approval'
run_logged timeout-tests uv run pytest -vv \
  tests/test_anchor.py::test_anchor_timeout_causes_zero_loads_and_no_late_approval \
  tests/test_prime_rl_entrypoint.py::test_real_barrier_timeout_freezes_and_never_loads

section '5/5 approved load failure: failure outcome, freeze, valid audit trail'
run_logged load-failure-test uv run pytest -vv \
  tests/test_owner_cpu_walkthrough.py::test_real_load_failure_freezes_and_is_auditable

printf '\nGAME DAY PASS\nEvidence and command logs: %s\n' "$GAME_ROOT"
printf 'The private key under keys/ is disposable demo material; do not reuse it.\n'
