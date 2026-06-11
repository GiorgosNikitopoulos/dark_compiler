#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/gnikitopoulos/sima_binpool/dark_compiler/dark_orchestrator"
cd "$ROOT"

python3 -m dark_orchestrator run \
  --input-results-dir "$ROOT/test_inputs/100_realistic" \
  --output-dir dark_100_realistic \
  --jobs 10
