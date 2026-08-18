#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 || $# -ne 10 ]]; then
  echo "usage: sudo $0 REPOSITORY UV WHEEL SOURCE CANDIDATE MODEL_META FINAL_SUITE CONFIG BUNDLE SOURCE_MANIFEST" >&2
  exit 64
fi
repo=$(realpath "$1")
uv=$(realpath "$2")
wheel=$(realpath "$3")
source_tree=$(realpath "$4")
candidate_tree=$(realpath "$5")
model_meta=$(realpath "$6")
final_suite=$(realpath "$7")
config_input=$(realpath "$8")
bundle_input=$(realpath "$9")
source_manifest_input=$(realpath "${10}")
controller=filiolae-p6v2-gatef-controller
evaluator=filiolae-p6v2-gatef-evaluator
shared=filiolae-p6v2-gatef-shared
work=/tmp/filiolae-p6-v2-gate-f
runtime=/opt/filiolae-p6-v2-gate-f-runtime
python_root=/opt/filiolae-p6-v2-gate-f-python
python_bin="$python_root/cpython-3.12.3-linux-x86_64-gnu/bin/python3"
evidence=/tmp/filiolae-p6-v2-gate-f-evidence
archive=/tmp/filiolae-p6-v2-gate-f-evidence.tar.gz
runtime_python="$runtime/bin/python"
controller_harness="$runtime/gate_f_controller_acceptance.py"
evaluator_service="$runtime/gate_f_evaluator_service.py"
gate_runtime="$runtime/gate_d_runtime.py"
finalizer="$runtime/gate_f_finalize_evidence.py"
contract="$runtime/acceptance-contract-v1.json"
evaluator_pid=""

cleanup() {
  set +e
  if [[ -n "$evaluator_pid" ]]; then
    kill -KILL "$evaluator_pid" 2>/dev/null || true
  fi
  pkill -KILL -u "$evaluator" 2>/dev/null || true
  pkill -KILL -u "$controller" 2>/dev/null || true
  rm -rf "$work" "$runtime" "$python_root"
  userdel "$controller" 2>/dev/null || true
  userdel "$evaluator" 2>/dev/null || true
  groupdel "$shared" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
rm -rf "$work" "$runtime" "$python_root" "$evidence" "$archive" "$archive.sha256"
"$uv" python install 3.12.3 --install-dir "$python_root" --no-bin --no-cache --managed-python
chmod -R a+rX "$python_root"
"$uv" venv --python "$python_bin" "$runtime"
"$uv" pip install --python "$runtime_python" \
  "$wheel" cryptography==46.0.5 torch==2.7.0 transformers==4.52.4 safetensors==0.5.3
install -m 0555 "$repo/ops/priority-6-v2/gate_f_controller_acceptance.py" "$controller_harness"
install -m 0555 "$repo/ops/priority-6-v2/gate_f_evaluator_service.py" "$evaluator_service"
install -m 0555 "$repo/ops/priority-6-v2/gate_d_runtime.py" "$gate_runtime"
install -m 0555 "$repo/ops/priority-6-v2/gate_f_finalize_evidence.py" "$finalizer"
install -m 0444 "$repo/examples/priority-6-v2/acceptance-contract-v1.json" "$contract"
chown -R root:root "$runtime"
chmod -R go-w "$runtime"
chmod 0755 "$runtime" "$runtime/bin"
find "$runtime/bin" -maxdepth 1 -type f -exec chmod a+rx {} +
"$runtime_python" -c 'import filiolae; assert not filiolae.__file__.startswith("/home/")'

groupadd --system "$shared"
useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$shared" "$controller"
useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$shared" "$evaluator"
getent group video >/dev/null && usermod -aG video "$evaluator"
getent group render >/dev/null && usermod -aG render "$evaluator"
controller_uid=$(id -u "$controller")
evaluator_uid=$(id -u "$evaluator")
[[ "$controller_uid" != "$evaluator_uid" ]]
install -d -m 2750 -o "$controller" -g "$shared" "$work"
install -d -m 2750 -o "$controller" -g "$shared" "$work/requests"
install -d -m 0710 -o "$evaluator" -g "$shared" "$work/key"
install -d -m 2750 -o "$evaluator" -g "$shared" "$work/terminal"
install -d -m 2750 -o "$evaluator" -g "$shared" "$work/evaluator-proof"
install -d -m 2750 -o "$controller" -g "$shared" "$work/run"
install -d -m 2750 -o "$controller" -g "$shared" "$work/run/broadcasts"
install -d -m 0750 -o root -g "$shared" "$work/run/broadcasts/step_1"
install -d -m 0750 -o root -g "$shared" "$work/inputs"
cp -a "$candidate_tree/." "$work/run/broadcasts/step_1/"
cp -a "$source_tree" "$work/inputs/source"
cp -a "$model_meta" "$work/inputs/model-meta"
find "$work/run/broadcasts/step_1" "$work/inputs/source" "$work/inputs/model-meta" -type d -exec chmod 0550 {} +
find "$work/run/broadcasts/step_1" "$work/inputs/source" "$work/inputs/model-meta" -type f -exec chmod 0440 {} +
chown -R root:"$shared" "$work/run/broadcasts/step_1" "$work/inputs/source" "$work/inputs/model-meta"
install -m 0440 -o "$evaluator" -g "$shared" "$final_suite" "$work/inputs/final.jsonl"
install -m 0440 -o root -g "$shared" "$config_input" "$work/inputs/config.json"
install -m 0440 -o root -g "$shared" "$bundle_input" "$work/inputs/evaluator-bundle.json"
install -m 0440 -o root -g "$shared" "$source_manifest_input" "$work/inputs/source-manifest.json"

runuser -u "$evaluator" -g "$shared" -- "$runtime_python" -c \
  'from filiolae.cli import main; raise SystemExit(main())' anchor-keygen \
  --private-key "$work/key/private.pem" --public-key "$work/key/public.pem"
chmod 0600 "$work/key/private.pem"
chmod 0640 "$work/key/public.pem"

runuser -u "$evaluator" -g "$shared" -- "$runtime_python" "$evaluator_service" \
  --request-root "$work/requests" \
  --terminal-root "$work/terminal" \
  --source "$work/inputs/source" \
  --candidate "$work/run/broadcasts/step_1" \
  --model-metadata "$work/inputs/model-meta" \
  --evaluator-bundle "$work/inputs/evaluator-bundle.json" \
  --suite "$work/inputs/final.jsonl" \
  --config "$work/inputs/config.json" \
  --source-manifest "$work/inputs/source-manifest.json" \
  --private-key "$work/key/private.pem" \
  --allowed-request "$work/key/allowed-request.sha256" \
  --outputs "$work/evaluator-proof/model-outputs.json" \
  --proof "$work/evaluator-proof/service.json" \
  --gate-runtime "$gate_runtime" \
  --service-path "$evaluator_service" \
  --timeout-seconds 600 \
  --batch-size 64 &
evaluator_pid=$!

runuser -u "$controller" -g "$shared" -- "$runtime_python" "$controller_harness" \
  --work "$work" \
  --private-key "$work/key/private.pem" \
  --public-key "$work/key/public.pem" \
  --contract "$contract" \
  --evaluator-user "$evaluator" \
  --source "$work/inputs/source" \
  --candidate "$work/run/broadcasts/step_1" \
  --suite "$work/inputs/final.jsonl" \
  --config "$work/inputs/config.json" \
  --source-manifest "$work/inputs/source-manifest.json" \
  --evaluator-bundle "$work/inputs/evaluator-bundle.json" \
  --expected-candidate-sha256 741fda92eada7ff04d5e10882af9c253d3a0d4cb80bb7c7d530c600004826b57
wait "$evaluator_pid"
evaluator_pid=""

if pgrep -u "$evaluator" >/dev/null; then
  echo "evaluator process survived Gate F" >&2
  exit 1
fi
if pgrep -u "$controller" >/dev/null; then
  echo "controller process survived Gate F" >&2
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
chown -R root:root "$evidence"
(
  cd "$evidence"
  sha256sum --check SHA256SUMS
)
tar -C /tmp -czf "$archive" "$(basename "$evidence")"
sha256sum "$archive" > "$archive.sha256"
chmod 0644 "$archive" "$archive.sha256"
cat "$evidence/SUMMARY.json"
cat "$evidence/CLEANUP.json"
cat "$archive.sha256"
