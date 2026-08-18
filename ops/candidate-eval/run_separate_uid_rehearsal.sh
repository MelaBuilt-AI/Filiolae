#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 || $# -ne 3 ]]; then
  echo "usage: sudo $0 /absolute/repository /absolute/uv /absolute/filiolae-wheel" >&2
  exit 64
fi
repo=$(realpath "$1")
uv=$(realpath "$2")
wheel=$(realpath "$3")
controller=filiolae-p6-controller
evaluator=filiolae-p6-evaluator
shared=filiolae-p6-shared
work=/tmp/filiolae-p6-separate-uid
summary=/tmp/filiolae-p6-separate-uid-summary.json
sudoers=/etc/sudoers.d/filiolae-p6-evaluator
runtime=/opt/filiolae-p6-evaluator-runtime
runtime_python="$runtime/bin/python"
harness="$runtime/separate_uid_rehearsal.py"

cleanup() {
  set +e
  pkill -KILL -u "$evaluator" 2>/dev/null || true
  rm -f "$sudoers"
  rm -rf "$work" "$runtime"
  userdel "$controller" 2>/dev/null || true
  userdel "$evaluator" 2>/dev/null || true
  groupdel "$shared" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
rm -rf "$work" "$summary" "$runtime"
"$uv" venv --python 3.12 "$runtime"
"$uv" pip install --python "$runtime_python" "$wheel"
install -m 0555 "$repo/ops/candidate-eval/separate_uid_rehearsal.py" "$harness"
chown -R root:root "$runtime"
chmod -R go-w "$runtime"
chmod 0755 "$runtime" "$runtime/bin"
find "$runtime/bin" -maxdepth 1 -type f -exec chmod a+rx {} +
"$runtime_python" -c 'import filiolae; assert not filiolae.__file__.startswith("/home/")'
groupadd --system "$shared"
useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$shared" "$controller"
useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$shared" "$evaluator"
install -d -m 2750 -o "$controller" -g "$shared" "$work"
install -d -m 0710 -o "$evaluator" -g "$shared" "$work/key"
install -d -m 2750 -o "$evaluator" -g "$shared" "$work/terminal"

sudo -u "$evaluator" -g "$shared" -- "$runtime_python" -c \
  'from filiolae.cli import main; raise SystemExit(main())' anchor-keygen \
  --private-key "$work/key/private.pem" --public-key "$work/key/public.pem"
chmod 0600 "$work/key/private.pem"
chmod 0640 "$work/key/public.pem"

printf '%s ALL=(%s:%s) NOPASSWD: %s -m filiolae.paired_eval_worker *\n' \
  "$controller" "$evaluator" "$shared" "$runtime_python" > "$sudoers"
chmod 0440 "$sudoers"
visudo -cf "$sudoers"

sudo -u "$controller" -g "$shared" -- "$runtime_python" "$harness" \
  --work "$work" \
  --private-key "$work/key/private.pem" \
  --public-key "$work/key/public.pem" \
  --allowed-request-file "$work/key/allowed-request.sha256" \
  --evaluator-user "$evaluator" \
  --evaluator-python "$runtime_python" \
  --shared-group "$shared" &
harness_pid=$!
for _ in $(seq 1 600); do
  [[ -f "$work/prepared-request.sha256" ]] && break
  sleep 0.05
done
test -f "$work/prepared-request.sha256"
request_digest=$(cat "$work/prepared-request.sha256")
[[ $request_digest =~ ^[0-9a-f]{64}$ ]]
printf '%s\n' "$request_digest" > "$work/key/allowed-request.sha256"
chown "$evaluator:$shared" "$work/key/allowed-request.sha256"
chmod 0400 "$work/key/allowed-request.sha256"
wait "$harness_pid"

if pgrep -u "$evaluator" >/dev/null; then
  echo "evaluator process survived rehearsal" >&2
  exit 1
fi
cp "$work/separate-uid-summary.json" "$summary"
chmod 0644 "$summary"
rm -f "$work/key/private.pem"
test ! -e "$work/key/private.pem"
cat "$summary"
