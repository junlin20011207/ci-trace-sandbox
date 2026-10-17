#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONPATH="$PWD:$PWD/core"
mkdir -p results
python -m pytest -q tests/test_product.py | tee results/product_test.log
python -m unittest discover -s core -p test_protocol.py -v > results/legacy_protocol_tests.log 2>&1
python demo_engine.py --all > results/end_to_end.json
python experiments/paired_baselines.py
python formal/exhaustive.py
python experiments/latency.py
python experiments/baseline_latency.py
if [[ "${CI_TRACE_TEST_UID_LAB:-0}" = "1" ]]; then
  if [[ "$(id -u)" = 0 ]]; then
    python -m unittest -v core.test_ipc_lab | tee results/ipc_integration.log
  else
    echo 'Skipping UID laboratory: requires disposable root container' >&2
  fi
fi
echo 'CI-TRACE R22 local laboratory suite complete.'
