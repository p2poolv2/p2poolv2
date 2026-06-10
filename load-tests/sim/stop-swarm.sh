#!/usr/bin/env bash
#
# Stop a sim swarm started by run-swarm.sh (sends SIGTERM to recorded PIDs).
#
# Usage: load-tests/sim/stop-swarm.sh
# Env:   RUN_DIR  (default /tmp/p2pool-sim)
set -euo pipefail

RUN_DIR="${RUN_DIR:-/tmp/p2pool-sim}"
PIDS_FILE="$RUN_DIR/pids.txt"

n=0
if [ -f "$PIDS_FILE" ]; then
  while read -r pid; do
    [ -z "$pid" ] && continue
    if kill "$pid" 2>/dev/null; then
      n=$((n + 1))
    fi
  done < "$PIDS_FILE"
fi

# Fallback: catch orphans this RUN_DIR spawned that aren't in pids.txt (e.g.
# a prior run whose pids file was overwritten). Match on the config path.
orphans=$(pgrep -f "$RUN_DIR/node-" 2>/dev/null || true)
if [ -n "$orphans" ]; then
  # shellcheck disable=SC2086
  kill $orphans 2>/dev/null || true
  sleep 1
  # SIGKILL any that ignored SIGTERM
  orphans=$(pgrep -f "$RUN_DIR/node-" 2>/dev/null || true)
  # shellcheck disable=SC2086
  [ -n "$orphans" ] && kill -9 $orphans 2>/dev/null || true
fi

echo "Stopped swarm (pids.txt: $n; plus any orphans matching $RUN_DIR/node-)."
