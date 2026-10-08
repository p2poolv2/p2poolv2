#!/usr/bin/env bash
#
# Failure-mode injection for a running sim swarm.
#
# Runs ONE named scenario against a swarm already started by run-swarm.sh:
# kills nodes with SIGKILL, brings them back, and verifies each one rejoins
# and catches up to the rest of the swarm. Writes a plain-text summary to
# stdout and to $RUN_DIR/failure-results.txt; nightly.sh greps that summary
# for its verdict (same contract metrics.sh has with nightly.sh).
#
# Usage:
#   load-tests/sim/failures.sh <scenario>
#
# Scenarios:
#   clean             no-op (today's nightly behaviour)
#   restart-fast      one node fails and comes back immediately
#   restart-delayed   one node fails and comes back after a long delay, so we
#                     validate it catches up; the default downtime crosses the
#                     300s tip-age threshold, so the node rejoins "not current"
#                     and must bulk-sync via getheaders rather than inv gossip
#   partition         DIAL_FANOUT consecutive nodes fail at once, cutting the
#                     dial chain, then all come back. Kademlia may keep the two
#                     sides connected; the summary reports which happened
#   all               the three above in sequence (local use, not CI)
#
# Env overrides:
#   RUN_DIR                   swarm work dir                (default /tmp/p2pool-sim)
#   BASE_P2P / BASE_API       first libp2p / API port       (default 7000 / 7600)
#   PROFILE                   cargo profile: release|debug  (default release)
#   SIM_BIN                   sim binary path               (default from PROFILE)
#   DIAL_FANOUT               peers each node dials         (default 3)
#   FAILURE_SEED              target selection seed         (default 42)
#   FAILURE_WARMUP            settle before injecting (s)   (default 60)
#   FAILURE_FAST_DOWN         restart-fast downtime (s)     (default 10)
#   FAILURE_SLOW_DOWN         restart-delayed downtime (s)  (default 330)
#   FAILURE_PARTITION_DOWN    partition downtime (s)        (default 90)
#   FAILURE_CATCHUP_TIMEOUT   max wait for catch-up (s)     (default 240)
#
# Node 0 is never a target: metrics.sh derives the share rate and uncle rate
# from node-0.log alone, so killing it would corrupt the run's own metrics.
#
# (no `set -e`: a node that fails to catch up must still reach the summary)
set -uo pipefail

show_help() {
  cat <<'HELP'
failures.sh -- inject one failure scenario into a running sim swarm

Kills nodes with SIGKILL, brings them back, and verifies each one rejoins and
catches up. Writes a summary to stdout and $RUN_DIR/failure-results.txt.

Usage:
  load-tests/sim/failures.sh <scenario>

Scenarios:
  clean             no-op (today's nightly behaviour)
  restart-fast      one node fails and comes back immediately
  restart-delayed   one node fails and comes back after a long delay, so we
                    validate it catches up; the default downtime crosses the
                    300s tip-age threshold, so the node rejoins "not current"
                    and must bulk-sync via getheaders rather than inv gossip
  partition         DIAL_FANOUT consecutive nodes fail at once, cutting the
                    dial chain, then all come back. Kademlia may keep the two
                    sides connected; the summary reports which happened
  all               the three above in sequence (local use, not CI)

Env vars:
  RUN_DIR                   swarm work dir                (default /tmp/p2pool-sim)
  BASE_P2P / BASE_API       first libp2p / API port       (default 7000 / 7600)
  PROFILE                   cargo profile: release|debug  (default release)
  SIM_BIN                   sim binary path               (default from PROFILE)
  DIAL_FANOUT               peers each node dials         (default 3)
  FAILURE_SEED              target selection seed         (default 42)
  FAILURE_WARMUP            settle before injecting (s)   (default 60)
  FAILURE_FAST_DOWN         restart-fast downtime (s)     (default 10)
  FAILURE_SLOW_DOWN         restart-delayed downtime (s)  (default 330)
  FAILURE_PARTITION_DOWN    partition downtime (s)        (default 90)
  FAILURE_CATCHUP_TIMEOUT   max wait for catch-up (s)     (default 240)

Node 0 is never a target: metrics.sh derives the share rate and uncle rate
from node-0.log alone, so killing it would corrupt the run's own metrics.

Examples:
  load-tests/sim/failures.sh restart-fast
  FAILURE_WARMUP=20 FAILURE_SLOW_DOWN=60 load-tests/sim/failures.sh restart-delayed

Related scripts:
  load-tests/sim/run-swarm.sh N    launch the swarm this operates on
  load-tests/sim/observe.sh        live per-node view (tip, peers, alive)
  load-tests/sim/nightly.sh        automated runner; calls this script
HELP
  exit 0
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  show_help
fi

SCENARIO="${1:-clean}"

RUN_DIR="${RUN_DIR:-/tmp/p2pool-sim}"
BASE_P2P="${BASE_P2P:-7000}"
BASE_API="${BASE_API:-7600}"
PROFILE="${PROFILE:-release}"
DIAL_FANOUT="${DIAL_FANOUT:-3}"
FAILURE_SEED="${FAILURE_SEED:-42}"
FAILURE_WARMUP="${FAILURE_WARMUP:-60}"
FAILURE_FAST_DOWN="${FAILURE_FAST_DOWN:-10}"
FAILURE_SLOW_DOWN="${FAILURE_SLOW_DOWN:-330}"
FAILURE_PARTITION_DOWN="${FAILURE_PARTITION_DOWN:-90}"
FAILURE_CATCHUP_TIMEOUT="${FAILURE_CATCHUP_TIMEOUT:-240}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
if [ "$PROFILE" = "release" ]; then
  BIN="${SIM_BIN:-$REPO_ROOT/target/release/p2poolv2_sim}"
else
  BIN="${SIM_BIN:-$REPO_ROOT/target/debug/p2poolv2_sim}"
fi

PIDS_FILE="$RUN_DIR/pids.txt"
RESULTS_FILE="$RUN_DIR/failure-results.txt"

# Summary state, printed by write_summary at the end.
SUMMARY_LINES=()
OBSERVATION_LINES=()
TARGET_LIST=""
REJOINED_OK=0
REJOINED_TOTAL=0
# Tip height of each node just before it was killed, indexed by node number.
TIP_AT_KILL=()

log_message() {
  echo "[$(date +%H:%M:%S)] $*"
}

# ---------------------------------------------------------------------------
# Node lifecycle
# ---------------------------------------------------------------------------

node_pid() {
  sed -n "$(($1 + 1))p" "$PIDS_FILE" 2>/dev/null
}

# Rewrite line i+1 of pids.txt so nightly.sh's alive check and observe.sh keep
# reading the current pid for this node.
set_node_pid() {
  local index="$1" pid="$2" tmp
  tmp="$(mktemp "$RUN_DIR/pids.XXXXXX")"
  awk -v line="$((index + 1))" -v pid="$pid" 'NR == line { print pid; next } { print }' \
    "$PIDS_FILE" > "$tmp"
  mv "$tmp" "$PIDS_FILE"
}

# SIGKILL a node and wait for the process to go away. The marker written into
# the node log must not contain "error" or "panic": observe.sh greps for those.
kill_node() {
  local index="$1" pid attempt
  pid="$(node_pid "$index")"
  TIP_AT_KILL[index]="$(log_tip_height "$index")"

  if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
    log_message "  node $index already down (no live pid)"
    return 1
  fi

  echo "=== failure injection: SIGKILL node $index at $(date +%H:%M:%S), tip ${TIP_AT_KILL[index]} ===" \
    >> "$RUN_DIR/node-$index.log"
  kill -9 "$pid" 2>/dev/null

  attempt=0
  while [ "$attempt" -lt 10 ]; do
    if ! kill -0 "$pid" 2>/dev/null; then
      log_message "  killed node $index (pid $pid, tip ${TIP_AT_KILL[index]})"
      return 0
    fi
    sleep 1
    attempt=$((attempt + 1))
  done
  log_message "  node $index (pid $pid) did not exit after SIGKILL"
  return 1
}

# Relaunch a node against its existing config and store. The log is APPENDED
# to: truncating it would destroy the promotion history metrics.sh reads.
start_node() {
  local index="$1" pid
  echo "=== failure injection: restarting node $index at $(date +%H:%M:%S) ===" \
    >> "$RUN_DIR/node-$index.log"
  "$BIN" --config "$RUN_DIR/node-$index.toml" >> "$RUN_DIR/node-$index.log" 2>&1 &
  pid=$!
  set_node_pid "$index" "$pid"
  log_message "  restarted node $index (pid $pid)"
}

# ---------------------------------------------------------------------------
# Observation (logs and API only: RocksDB is locked while a node runs, so the
# store-based checks in nightly.sh cannot be used mid-run)
# ---------------------------------------------------------------------------

log_tip_height() {
  local height
  height="$(grep -oE "to confirmed height Some\([0-9]+\)" "$RUN_DIR/node-$1.log" 2>/dev/null \
    | grep -oE "[0-9]+" | sort -n | tail -1)"
  echo "${height:-0}"
}

swarm_max_tip() {
  local index height max=0
  for index in $(seq 0 $((NODE_TOTAL - 1))); do
    height="$(log_tip_height "$index")"
    if [ "$height" -gt "$max" ]; then max="$height"; fi
  done
  echo "$max"
}

# Poll a restarted node's log until its confirmed tip reaches target_height.
# Sets CATCHUP_SECS. Returns non-zero on timeout or if the process died.
wait_for_catchup() {
  local index="$1" target="$2" timeout="$3" start now height pid
  start="$(date +%s)"
  CATCHUP_SECS=0
  while true; do
    now="$(date +%s)"
    CATCHUP_SECS=$((now - start))
    height="$(log_tip_height "$index")"
    if [ "$height" -ge "$target" ]; then
      return 0
    fi
    pid="$(node_pid "$index")"
    if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
      log_message "  node $index died while catching up (tip $height, target $target)"
      return 1
    fi
    if [ "$CATCHUP_SECS" -ge "$timeout" ]; then
      log_message "  node $index did not reach height $target within ${timeout}s (tip $height)"
      return 1
    fi
    sleep 5
  done
}

# Listen ports of the peers a node has dialled OUT to. Inbound entries carry an
# ephemeral send_back port, so only outbound links map back to a node index --
# which is enough, because every link is outbound from one of its two ends.
outbound_peer_ports() {
  curl -s -m 2 "http://127.0.0.1:$((BASE_API + $1))/peers" 2>/dev/null \
    | jq -r '.[] | select(.direction == "Outbound") | .address' 2>/dev/null \
    | grep -oE "/tcp/[0-9]+" | cut -d/ -f3
}

# Count links from the nodes in $1 (space-separated) to the nodes in $2.
count_links_between() {
  local sources="$1" targets="$2" index port target_ports="" links=0
  for index in $targets; do
    target_ports="$target_ports $((BASE_P2P + index))"
  done
  for index in $sources; do
    while read -r port; do
      [ -z "$port" ] && continue
      case " $target_ports " in
        *" $port "*) links=$((links + 1)) ;;
      esac
    done < <(outbound_peer_ports "$index")
  done
  echo "$links"
}

# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

# Kill every node in the argument list, recording its pre-kill tip.
kill_nodes() {
  local index
  for index in "$@"; do
    kill_node "$index"
  done
}

# Restart every node in the argument list and verify each one catches up to
# where the surviving swarm has got to. Accumulates the summary rows.
restart_and_verify() {
  local index target gap rejoined
  target="$(swarm_max_tip)"
  log_message "Restarting node(s) '$*'; catch-up target is height $target"
  for index in "$@"; do
    start_node "$index"
  done
  for index in "$@"; do
    gap=$((target - ${TIP_AT_KILL[index]:-0}))
    if wait_for_catchup "$index" "$target" "$FAILURE_CATCHUP_TIMEOUT"; then
      rejoined="yes"
      REJOINED_OK=$((REJOINED_OK + 1))
      log_message "  node $index caught up to height $target in ${CATCHUP_SECS}s (gap ${gap} heights)"
    else
      rejoined="no"
    fi
    REJOINED_TOTAL=$((REJOINED_TOTAL + 1))
    SUMMARY_LINES+=("node $index: rejoined=$rejoined catchup_secs=$CATCHUP_SECS gap_heights=$gap target_height=$target")
  done
}

scenario_restart_fast() {
  log_message "--- restart-fast: node $TARGET_FAST down for ${FAILURE_FAST_DOWN}s ---"
  TARGET_LIST="$TARGET_LIST $TARGET_FAST"
  kill_nodes "$TARGET_FAST"
  sleep "$FAILURE_FAST_DOWN"
  restart_and_verify "$TARGET_FAST"
}

scenario_restart_delayed() {
  log_message "--- restart-delayed: node $TARGET_SLOW down for ${FAILURE_SLOW_DOWN}s ---"
  TARGET_LIST="$TARGET_LIST $TARGET_SLOW"
  kill_nodes "$TARGET_SLOW"
  sleep "$FAILURE_SLOW_DOWN"
  restart_and_verify "$TARGET_SLOW"
}

# Kill the nodes that bridge the dial chain, so nodes below and above the cut
# have no configured path to each other, then bring them back. Whether this is
# a real partition depends on Kademlia, which discovers and dials peers that
# were never in dial_peers; the observation lines record what actually happened.
scenario_partition() {
  local killed="" lower="" upper="" index links_down links_up elapsed sample
  for index in $(seq "$PARTITION_START" $((PARTITION_START + PARTITION_WIDTH - 1))); do
    killed="$killed $index"
  done
  for index in $(seq 0 $((PARTITION_START - 1))); do
    lower="$lower $index"
  done
  for index in $(seq $((PARTITION_START + PARTITION_WIDTH)) $((NODE_TOTAL - 1))); do
    upper="$upper $index"
  done

  log_message "--- partition: nodes$killed down for ${FAILURE_PARTITION_DOWN}s (lower side$lower, upper side$upper) ---"
  TARGET_LIST="$TARGET_LIST$killed"
  # shellcheck disable=SC2086
  kill_nodes $killed

  elapsed=0
  for sample in 15 45; do
    if [ "$sample" -le "$FAILURE_PARTITION_DOWN" ]; then
      sleep $((sample - elapsed))
      elapsed="$sample"
      links_down="$(count_links_between "$lower" "$upper")"
      links_up="$(count_links_between "$upper" "$lower")"
      OBSERVATION_LINES+=("cross-side links at +${sample}s: lower_to_upper=$links_down upper_to_lower=$links_up")
      log_message "  cross-side links at +${sample}s: lower->upper=$links_down upper->lower=$links_up"
    fi
  done
  if [ "$FAILURE_PARTITION_DOWN" -gt "$elapsed" ]; then
    sleep $((FAILURE_PARTITION_DOWN - elapsed))
  fi

  # shellcheck disable=SC2086
  restart_and_verify $killed
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

write_summary() {
  local unrecovered=$((REJOINED_TOTAL - REJOINED_OK)) line
  {
    echo "=== failure injection summary (scenario: $SCENARIO) ==="
    echo "targets:${TARGET_LIST:- none}"
    for line in "${OBSERVATION_LINES[@]+"${OBSERVATION_LINES[@]}"}"; do
      echo "$line"
    done
    for line in "${SUMMARY_LINES[@]+"${SUMMARY_LINES[@]}"}"; do
      echo "$line"
    done
    echo "rejoined: $REJOINED_OK/$REJOINED_TOTAL"
    echo "unrecovered nodes: $unrecovered"
  } | tee "$RESULTS_FILE"
  [ "$unrecovered" -eq 0 ]
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

case "$SCENARIO" in
  clean|restart-fast|restart-delayed|partition|all) ;;
  *)
    echo "ERROR: unknown scenario '$SCENARIO' (expected clean, restart-fast, restart-delayed, partition or all)" >&2
    exit 2
    ;;
esac

if [ ! -d "$RUN_DIR" ]; then
  echo "ERROR: no run dir at $RUN_DIR; start a swarm with run-swarm.sh first." >&2
  exit 1
fi
NODE_TOTAL=$(ls "$RUN_DIR"/node-*.toml 2>/dev/null | wc -l | tr -d ' ')
if [ "$NODE_TOTAL" -eq 0 ]; then
  echo "ERROR: no node configs in $RUN_DIR; start a swarm with run-swarm.sh first." >&2
  exit 1
fi

if [ "$SCENARIO" = "clean" ]; then
  log_message "scenario 'clean': no failures injected"
  write_summary
  exit $?
fi

if [ ! -x "$BIN" ]; then
  echo "ERROR: sim binary not found at $BIN (set PROFILE, or build with run-swarm.sh)." >&2
  exit 1
fi
if [ "$NODE_TOTAL" -lt 3 ]; then
  echo "ERROR: failure injection needs at least 3 nodes (node 0 is never a target); have $NODE_TOTAL." >&2
  exit 1
fi

# Seeded target selection, so a failing nightly is reproducible. Same
# single-awk-with-srand idiom run-swarm.sh uses for its distributions.
# Targets are drawn from [1, N-1]; the partition cut keeps at least one node on
# each side of it.
read -r TARGET_FAST TARGET_SLOW PARTITION_START PARTITION_WIDTH < <(
  awk -v seed="$FAILURE_SEED" -v n="$NODE_TOTAL" -v fanout="$DIAL_FANOUT" 'BEGIN {
    srand(seed + 0)
    fast = 1 + int(rand() * (n - 1))
    slow = 1 + int(rand() * (n - 1))
    while (slow == fast && n > 2) { slow = 1 + int(rand() * (n - 1)) }
    width = fanout
    if (width > n - 2) width = n - 2
    if (width < 1) width = 1
    max_start = n - width - 1
    if (max_start < 1) max_start = 1
    start = 1 + int(rand() * max_start)
    printf "%d %d %d %d\n", fast, slow, start, width
  }'
)

log_message "scenario '$SCENARIO' on $NODE_TOTAL nodes (seed $FAILURE_SEED)"
log_message "Warming up for ${FAILURE_WARMUP}s before injecting failures..."
sleep "$FAILURE_WARMUP"

case "$SCENARIO" in
  restart-fast)    scenario_restart_fast ;;
  restart-delayed) scenario_restart_delayed ;;
  partition)       scenario_partition ;;
  all)
    scenario_restart_fast
    scenario_restart_delayed
    scenario_partition
    ;;
esac

write_summary
