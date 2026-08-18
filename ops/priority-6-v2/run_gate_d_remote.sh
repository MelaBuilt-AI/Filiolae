#!/usr/bin/env bash
set -euo pipefail
umask 077

root=/opt/filiolae-p6-v2-gate-d
output="$root/run-output"
lifecycle="$root/lifecycle"
driver_sha256=$(sha256sum "$0" | awk '{print $1}')
test ! -e "$output"
mkdir -m 0700 "$lifecycle"
exec > >(tee -a "$lifecycle/remote-driver.log") 2>&1
printf 'driver_started_utc=%s\n' "$(date -u +%FT%TZ)"
printf 'driver_sha256=%s\n' "$driver_sha256"

terminal_record() {
  rc=$?
  set +e
  python3 - "$lifecycle/REMOTE-DRIVER-TERMINAL.json.tmp" "$lifecycle/REMOTE-DRIVER-TERMINAL.json"     "$driver_sha256" "$rc" <<'PY'
import datetime as dt
import json
import os
import sys
from pathlib import Path

temporary, target, digest, returncode = sys.argv[1:]
payload = {
    "driver_sha256": digest,
    "finished_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "returncode": int(returncode),
    "schema": "filiolae.priority6-v2-gate-d-remote-driver-terminal.v1",
}
path = Path(temporary)
path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
os.chmod(path, 0o600)
os.replace(path, target)
PY
  exit "$rc"
}
trap terminal_record EXIT

cd "$root"
test ! -e "$output/candidate-freeze.json"
test ! -e "$output/run-terminal.json"
./prepare_gate_d_host.sh "$root"

test -x "$root/.venv/bin/python"
sudo -n systemd-run --quiet --wait --collect   --unit=filiolae-p6-v2-gate-d-training   --property=Type=oneshot   --property="User=$(id -un)"   --property=PrivateNetwork=yes   --property="WorkingDirectory=$root"   /bin/bash -c   'exec /opt/filiolae-p6-v2-gate-d/.venv/bin/python /opt/filiolae-p6-v2-gate-d/gate_d_runtime.py train-visible --root /opt/filiolae-p6-v2-gate-d --manifest /opt/filiolae-p6-v2-gate-d/execution-manifest-v1.json --output /opt/filiolae-p6-v2-gate-d/run-output --source-tree-sha256 c047cbef4cca5dc09de95acd9f4a2ea884e8abd4f1e47dd34c2608165307c0c7 --seed 684021 --learning-rate 5e-5 --batch-size 32 --accumulation-steps 2 --eval-batch-size 64 > /opt/filiolae-p6-v2-gate-d/lifecycle/training.log 2>&1'

test -f "$output/run-terminal.json"
printf 'driver_finished_utc=%s\n' "$(date -u +%FT%TZ)"
