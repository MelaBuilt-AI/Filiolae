#!/bin/sh
# Python-3.10-safe entrypoint: verify bundled uv, install/select Python 3.12, then exec a smoke tool.
set -eu
payload=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
uv_bin=$payload/bin/uv
expected=646adf5cf12ba17d1a41fa77c8dd6496f73651dcfeeed6b5f4ec019b36bc7153
actual=$(sha256sum "$uv_bin" | awk '{print $1}')
[ "$actual" = "$expected" ] || { echo "bundled uv digest mismatch" >&2; exit 1; }
chmod 0755 "$uv_bin"
[ "$#" -ge 1 ] || { echo "usage: $0 {preflight|happy|tamper|inject|collect} ARGS..." >&2; exit 64; }
tool=$1
shift
case "$tool" in
  preflight) script=remote_preflight.py ;;
  happy) script=run_happy.py ;;
  tamper) script=run_tamper.py ;;
  inject) script=tamper_after_step1.py ;;
  collect) script=collect_evidence.py ;;
  *) echo "unknown smoke tool: $tool" >&2; exit 64 ;;
esac
"$uv_bin" python install 3.12
# The manifest is an exact file-set contract; do not create runtime __pycache__ entries inside it.
export PYTHONDONTWRITEBYTECODE=1
exec "$uv_bin" run --no-project --python 3.12 python -B "$payload/bin/$script" "$@"
