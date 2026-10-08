#!/usr/bin/env bash
#
# Render sim-swarm time-series to a PNG (share rate, pool difficulty, uncle
# rate, block-finds, emission-vs-hashrate). Bootstraps a local matplotlib venv
# on first run. Run after/during a swarm; re-run to refresh.
#
# Usage: load-tests/sim/plot-metrics.sh [output.png]
# Env:   RUN_DIR (default /tmp/p2pool-sim)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv"

if [ ! -x "$VENV/bin/python" ]; then
  echo "Setting up plotting venv (one-time: installs matplotlib)..."
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q --upgrade pip
  "$VENV/bin/pip" install -q matplotlib
fi

"$VENV/bin/python" "$SCRIPT_DIR/plot-metrics.py" "$@"
