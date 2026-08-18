#!/usr/bin/env bash
set -euo pipefail

root=${1:-/opt/filiolae-p6-v2-gate-d}
[[ "$root" == /opt/filiolae-p6-v2-gate-d ]]
cd "$root"
exec > >(tee -a prepare-host.log) 2>&1
printf 'prepare_started_utc=%s\n' "$(date -u +%FT%TZ)"
test "$(id -u)" -ne 0
test -f execution-manifest-v1.json
test -f source/model.safetensors
test -f source/STABLE
sudo -n true
command -v systemd-run
command -v nvidia-smi
gpu_count=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits | wc -l)
test "$gpu_count" -eq 1
gpu_memory=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits | tr -d ' ')
test "$gpu_memory" -ge 49140
python3 -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check -r requirements.txt
.venv/bin/python - <<'PY'
from huggingface_hub import snapshot_download
snapshot_download(
    "PrimeIntellect/Qwen3-0.6B-Reverse-Text-SFT",
    revision="c97a910849ec6aa962add3dc253a0817d61c0210",
    local_dir="model-meta",
    allow_patterns=["*.json", "*.txt", "*.jinja"],
)
PY
rm -rf model-meta/.cache
find model-meta -type f -exec chmod 0444 {} +
chmod 0444 training.jsonl visible-development.jsonl source/model.safetensors source/STABLE   source-manifest.json gate_d_runtime.py requirements.txt execution-manifest-v1.json
# Prove that systemd can create the no-external-interface namespace used by the real service.
sudo -n systemd-run --quiet --wait --collect --unit=filiolae-p6-v2-network-preflight   --property=Type=oneshot --property=User="$(id -un)" --property=PrivateNetwork=yes   --property=WorkingDirectory="$root"   /bin/bash -c 'set -euo pipefail; ip -j address > network-preflight.json; test "$(ip -o route | wc -l)" -eq 0'
.venv/bin/python - <<'PY'
import json
import platform
import subprocess
from pathlib import Path

import safetensors
import torch
import transformers

payload = {
    "cuda_available": torch.cuda.is_available(),
    "cuda_version": torch.version.cuda,
    "gpu": subprocess.check_output(
        ["nvidia-smi", "--query-gpu=name,uuid,memory.total,driver_version", "--format=csv,noheader"],
        text=True,
    ).strip(),
    "network_preflight": json.loads(Path("network-preflight.json").read_text()),
    "python": platform.python_version(),
    "safetensors": safetensors.__version__,
    "schema": "filiolae.priority6-v2-gate-d-host-preflight.v1",
    "torch": torch.__version__,
    "transformers": transformers.__version__,
}
assert payload["cuda_available"] is True
Path("HOST-PREFLIGHT.json").write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
PY
printf 'prepare_finished_utc=%s\n' "$(date -u +%FT%TZ)"
