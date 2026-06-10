#!/usr/bin/env bash
#
# Snapshot a running sim swarm: per-node tip height, tip hash, candidate
# height and peer count, plus convergence / error / uncle summaries.
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

printf "%-5s %-7s %-12s %-10s %-6s %-6s\n" "node" "tip_h" "tip_hash" "cand_h" "peers" "alive"
echo "-------------------------------------------------------------"

declare -a tips=()
max_h=-1
alive_total=0
for i in $(seq 0 $((N - 1))); do
  api_port=$((BASE_API + i))
  info=$(curl -s -m 2 "http://127.0.0.1:$api_port/chain_info" 2>/dev/null || echo "")
  peers_json=$(curl -s -m 2 "http://127.0.0.1:$api_port/peers" 2>/dev/null || echo "")

  pid=$(sed -n "$((i + 1))p" "$RUN_DIR/pids.txt" 2>/dev/null || echo "")
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then alive="yes"; alive_total=$((alive_total + 1)); else alive="NO"; fi

  if [ -n "$info" ] && echo "$info" | jq -e . >/dev/null 2>&1; then
    tip_h=$(echo "$info" | jq -r '.chain_tip_height // -1')
    tip_hash=$(echo "$info" | jq -r '.chain_tip_blockhash // "?"' | cut -c1-12)
    cand_h=$(echo "$info" | jq -r '.top_candidate_height // -1')
  else
    tip_h="-"; tip_hash="(no api)"; cand_h="-"
  fi
  if [ -n "$peers_json" ] && echo "$peers_json" | jq -e . >/dev/null 2>&1; then
    peers=$(echo "$peers_json" | jq 'length')
  else
    peers="-"
  fi

  printf "%-5s %-7s %-12s %-10s %-6s %-6s\n" "$i" "$tip_h" "$tip_hash" "$cand_h" "$peers" "$alive"

  if [ "$tip_h" != "-" ] && [ "$tip_h" -ge 0 ] 2>/dev/null; then
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
