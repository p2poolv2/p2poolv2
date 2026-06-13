#!/usr/bin/env bash
#
# Live snapshot of a running sim swarm: per-node tip height/hash (from logs —
# load-immune), peer count (from the API — live state), and convergence.
# For the authoritative, comprehensive post-run summary, use metrics.sh.
#
# Usage: load-tests/sim/observe.sh
# Env:   RUN_DIR (default /tmp/p2pool-sim), BASE_API (default 7600)
# (no `set -e`: this is a best-effort reporter, partial data is fine)
set -uo pipefail

RUN_DIR="${RUN_DIR:-/tmp/p2pool-sim}"
BASE_API="${BASE_API:-7600}"

if [ ! -d "$RUN_DIR" ]; then
  echo "No run dir at $RUN_DIR." >&2
  exit 1
fi

# Infer N from generated configs.
N=$(ls "$RUN_DIR"/node-*.toml 2>/dev/null | wc -l | tr -d ' ')
if [ "$N" -eq 0 ]; then echo "No node configs in $RUN_DIR." >&2; exit 1; fi

printf "%-5s %-7s %-12s %-8s %-6s\n" "node" "tip_h" "tip_hash" "peers" "alive"
echo "-------------------------------------------------------------"

declare -a tips=()
max_h=-1
alive_total=0
for i in $(seq 0 $((N - 1))); do
  # tip height/hash from the LOG — load-immune and authoritative for convergence
  # (the HTTP API can time out while a node is busy). peer count is live state,
  # so the API is the natural, advisory source.
  last=$(grep "to confirmed height Some" "$RUN_DIR/node-$i.log" 2>/dev/null | tail -1)
  tip_h=$(echo "$last" | grep -oE "Some\([0-9]+\)" | grep -oE "[0-9]+"); tip_h="${tip_h:--1}"
  tip_hash=$(echo "$last" | sed -nE 's/.*Promoted block ([0-9a-f]{16,}).*/\1/p' | cut -c1-12)
  tip_hash="${tip_hash:--}"

  peers_json=$(curl -s -m 2 "http://127.0.0.1:$((BASE_API + i))/peers" 2>/dev/null || echo "")
  if [ -n "$peers_json" ] && echo "$peers_json" | jq -e . >/dev/null 2>&1; then
    peers=$(echo "$peers_json" | jq 'length')
  else
    peers="-"
  fi

  pid=$(sed -n "$((i + 1))p" "$RUN_DIR/pids.txt" 2>/dev/null || echo "")
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then alive="yes"; alive_total=$((alive_total + 1)); else alive="NO"; fi

  printf "%-5s %-7s %-12s %-8s %-6s\n" "$i" "$tip_h" "$tip_hash" "$peers" "$alive"

  if [ "$tip_h" -ge 0 ] 2>/dev/null; then
    tips+=("$tip_hash@$tip_h")
    if [ "$tip_h" -gt "$max_h" ]; then max_h="$tip_h"; fi
  fi
done

echo "-------------------------------------------------------------"
echo "alive: $alive_total/$N   max tip height: $max_h"

# Convergence: how many distinct (hash@height) tips across nodes.
if [ "${#tips[@]}" -gt 0 ]; then
  distinct=$(printf "%s\n" "${tips[@]}" | sort -u | wc -l | tr -d ' ')
  echo "distinct tips: $distinct (1 = fully converged)"
  echo "tip distribution:"
  printf "%s\n" "${tips[@]}" | sort | uniq -c | sort -rn | head -8 | sed 's/^/  /'
fi

# Error / uncle scan across logs.
echo
errs=$(grep -ihE "error|panic|failed to build emission" "$RUN_DIR"/node-*.log 2>/dev/null \
        | grep -ivE "max_workbase|0 warnings" | wc -l | tr -d ' ')
promos=$(grep -ih "Promoted block" "$RUN_DIR"/node-*.log 2>/dev/null | wc -l | tr -d ' ')
echo "log scan (all nodes):  promotions=$promos  error-lines=$errs"

# Uncle rate measured on node 0 only (each node confirms independently, so
# all-node sums double-count). uncle rate = uncle-referencing blocks / confirmed.
n0="$RUN_DIR/node-0.log"
if [ -f "$n0" ]; then
  n0_promos=$(grep -c "Promoted block" "$n0" 2>/dev/null || echo 0)
  n0_uncle_blocks=$(grep -c "sim-uncle:" "$n0" 2>/dev/null || echo 0)
  n0_uncle_refs=$(grep -oE "references [0-9]+ uncle" "$n0" 2>/dev/null \
                    | grep -oE "[0-9]+" | paste -sd+ - | bc 2>/dev/null || echo 0)
  rate="n/a"
  if [ "${n0_promos:-0}" -gt 0 ] 2>/dev/null; then
    rate=$(awk "BEGIN{printf \"%.1f%%\", 100*${n0_uncle_blocks:-0}/${n0_promos}}")
  fi
  echo "node 0:  confirmed=$n0_promos  uncle-blocks=$n0_uncle_blocks  uncle-refs=${n0_uncle_refs:-0}  uncle-rate=$rate"
fi
if [ "$errs" -gt 0 ]; then
  echo "sample errors:"
  grep -ihE "error|panic|failed to build emission" "$RUN_DIR"/node-*.log 2>/dev/null \
    | grep -ivE "max_workbase|0 warnings" | sort | uniq -c | sort -rn | head -5 | sed 's/^/  /'
fi
