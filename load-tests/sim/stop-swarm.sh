#!/usr/bin/env bash
#
# Stop a sim swarm started by run-swarm.sh (sends SIGTERM to recorded PIDs).
#
# Returns only once the node processes have actually exited. Callers read the
# RocksDB stores immediately afterwards, and a node that has logged its
# shutdown sequence but not yet exited still holds the store LOCK -- every
# read-write open then fails, which looks like an empty/corrupt store rather
# than a stop that was not waited for.
#
# Usage: load-tests/sim/stop-swarm.sh
# Env:   RUN_DIR              (default /tmp/p2pool-sim)
#        STOP_GRACE_SECONDS   how long to wait for a clean exit before
#                             escalating to SIGKILL (default 10)
set -euo pipefail

RUN_DIR="${RUN_DIR:-/tmp/p2pool-sim}"
STOP_GRACE_SECONDS="${STOP_GRACE_SECONDS:-10}"
PIDS_FILE="$RUN_DIR/pids.txt"

# Processes still running for this RUN_DIR, matched on the config path so we
# don't touch an unrelated single-node run.
running_nodes() {
  pgrep -f "$RUN_DIR/node-" 2>/dev/null || true
}

# Poll until no node processes remain, up to the given number of seconds.
wait_for_exit() {
  local deadline="$1" waited=0
  while [ "$waited" -lt "$deadline" ]; do
    if [ -z "$(running_nodes)" ]; then
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  [ -z "$(running_nodes)" ]
}

n=0
if [ -f "$PIDS_FILE" ]; then
  while read -r pid; do
    [ -z "$pid" ] && continue
    if kill "$pid" 2>/dev/null; then
      n=$((n + 1))
    fi
  done < "$PIDS_FILE"
fi

# Also catch orphans this RUN_DIR spawned that aren't in pids.txt (e.g. a prior
# run whose pids file was overwritten).
orphans="$(running_nodes)"
if [ -n "$orphans" ]; then
  # shellcheck disable=SC2086
  kill $orphans 2>/dev/null || true
fi

exit_status=0
if ! wait_for_exit "$STOP_GRACE_SECONDS"; then
  survivors="$(running_nodes)"
  echo "Nodes still running after ${STOP_GRACE_SECONDS}s, sending SIGKILL: $(echo "$survivors" | tr '\n' ' ')"
  # shellcheck disable=SC2086
  kill -9 $survivors 2>/dev/null || true
  if ! wait_for_exit 5; then
    echo "WARNING: nodes survived SIGKILL and still hold their store locks: $(running_nodes | tr '\n' ' ')" >&2
    exit_status=1
  fi
fi

echo "Stopped swarm (pids.txt: $n; all node processes for $RUN_DIR have exited)."
exit "$exit_status"
