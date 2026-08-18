#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 || $# -ne 3 ]]; then
  echo "usage: sudo $0 /absolute/repository /absolute/uv /absolute/filiolae-wheel" >&2
  exit 64
fi
repo=$(realpath "$1")
uv=$(realpath "$2")
wheel=$(realpath "$3")
controller=filiolae-p6v2-controller
evaluator=filiolae-p6v2-evaluator
shared=filiolae-p6v2-shared
work=/tmp/filiolae-p6-v2-separate-uid
runtime=/opt/filiolae-p6-v2-evaluator-runtime
evidence=/tmp/filiolae-p6-v2-separate-uid-evidence
runtime_python="$runtime/bin/python"
controller_harness="$runtime/controller_acceptance.py"
evaluator_service="$runtime/evaluator_service.py"
finalizer="$runtime/finalize_evidence.py"
contract="$runtime/acceptance-contract-v1.json"
evaluator_pid=""

cleanup() {
  set +e
  if [[ -n "$evaluator_pid" ]]; then
    kill -KILL "$evaluator_pid" 2>/dev/null || true
  fi
  pkill -KILL -u "$evaluator" 2>/dev/null || true
  rm -rf "$work" "$runtime"
  userdel "$controller" 2>/dev/null || true
  userdel "$evaluator" 2>/dev/null || true
  groupdel "$shared" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
rm -rf "$work" "$runtime" "$evidence"
"$uv" venv --python 3.12 "$runtime"
"$uv" pip install --python "$runtime_python" "$wheel"
install -m 0555 "$repo/ops/priority-6-v2/controller_acceptance.py" "$controller_harness"
install -m 0555 "$repo/ops/priority-6-v2/evaluator_service.py" "$evaluator_service"
install -m 0555 "$repo/ops/priority-6-v2/finalize_evidence.py" "$finalizer"
install -m 0444 "$repo/examples/priority-6-v2/acceptance-contract-v1.json" "$contract"
chown -R root:root "$runtime"
chmod -R go-w "$runtime"
chmod 0755 "$runtime" "$runtime/bin"
find "$runtime/bin" -maxdepth 1 -type f -exec chmod a+rx {} +
"$runtime_python" -c 'import filiolae; assert not filiolae.__file__.startswith("/home/")'

groupadd --system "$shared"
useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$shared" "$controller"
useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$shared" "$evaluator"
controller_uid=$(id -u "$controller")
evaluator_uid=$(id -u "$evaluator")
[[ "$controller_uid" != "$evaluator_uid" ]]
install -d -m 2750 -o "$controller" -g "$shared" "$work"
install -d -m 2750 -o "$controller" -g "$shared" "$work/requests"
install -d -m 0710 -o "$evaluator" -g "$shared" "$work/key"
install -d -m 2750 -o "$evaluator" -g "$shared" "$work/terminal"
install -d -m 2750 -o "$evaluator" -g "$shared" "$work/evaluator-proof"

sudo -u "$evaluator" -g "$shared" -- "$runtime_python" -c \
  'from filiolae.cli import main; raise SystemExit(main())' anchor-keygen \
  --private-key "$work/key/private.pem" --public-key "$work/key/public.pem"
chmod 0600 "$work/key/private.pem"
chmod 0640 "$work/key/public.pem"

sudo -u "$evaluator" -g "$shared" -- "$runtime_python" "$evaluator_service" \
  --request-root "$work/requests" \
  --terminal-root "$work/terminal" \
  --source "$work/inputs/source" \
  --candidate "$work/run/broadcasts/step_1" \
  --evaluator-bundle "$work/inputs/evaluator-bundle.json" \
  --suite "$work/inputs/suite.jsonl" \
  --config "$work/inputs/config.json" \
  --source-manifest "$work/inputs/source-manifest.json" \
  --private-key "$work/key/private.pem" \
  --allowed-request "$work/key/allowed-request.sha256" \
  --fixture "$work/inputs/fixture.json" \
  --proof "$work/evaluator-proof/service.json" \
  --timeout-seconds 60 &
evaluator_pid=$!

sudo -u "$controller" -g "$shared" -- "$runtime_python" "$controller_harness" \
  --work "$work" \
  --private-key "$work/key/private.pem" \
  --public-key "$work/key/public.pem" \
  --contract "$contract" \
  --evaluator-user "$evaluator"
wait "$evaluator_pid"
evaluator_pid=""

if pgrep -u "$evaluator" >/dev/null; then
  echo "evaluator process survived rehearsal" >&2
  exit 1
fi
if pgrep -u "$controller" >/dev/null; then
  echo "controller process survived rehearsal" >&2
  exit 1
fi
rm -f "$work/key/private.pem"
test ! -e "$work/key/private.pem"
mkdir -m 0755 "$evidence"
cp -a "$work/acceptance-package/." "$evidence/"
"$runtime_python" "$finalizer" "$evidence" \
  --controller-uid "$controller_uid" \
  --evaluator-uid "$evaluator_uid"
find "$evidence" -type d -exec chmod 0755 {} +
find "$evidence" -type f -exec chmod 0644 {} +
chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$evidence"
(
  cd "$evidence"
  sha256sum --check SHA256SUMS
)
cat "$evidence/SUMMARY.json"
cat "$evidence/CLEANUP.json"
