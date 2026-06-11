# Sim load-test runbook (local, manual)

A step-by-step guide to running the no-PoW sim by hand and seeing the outcomes.
This file is gitignored. Companion to `load-test-plan.md` (the design).

Mental model: there is **no proof-of-work**. Each node runs a "miner" that just
*sleeps* between shares (interval ≈ difficulty·2³²/hashrate) and emits
structurally-valid synthetic shares. They propagate over real libp2p, build a
real share chain (ASERT, uncles, reorgs, PPLNS), and on a random "block-find"
a node submits a **real regtest bitcoin block** carrying the PPLNS payout.

Everything below assumes you start from the repo root. These instructions were prepared for a Mac ; it should be fairly trivial to adapt for a Linux machine:

```sh
cd ~/code/p2poolv2
```

Tools used: `jq`, `curl`, and `bitcoin-cli` (all already present here).

---

## 0. One-time shell helpers

Paste these into your terminal; the rest of the runbook uses them.

```sh
# bitcoin-cli against the isolated regtest node used for the sim
B() { /opt/homebrew/bin/bitcoin-cli -datadir=/tmp/p2pool-regtest "$@"; }

# raw JSON-RPC (same creds as the configs)
rpc() {
  curl -s --user p2pool:p2pool \
    --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"r\",\"method\":\"$1\",\"params\":${2:-[]}}" \
    -H 'content-type: text/plain;' http://127.0.0.1:19443/
}
```

---

## 1. Prerequisites: the regtest bitcoind

The sim talks to one local **regtest** bitcoind (RPC + ZMQ). Check it's up:

```sh
B getblockchaininfo | jq '{chain, blocks}'
```

Expect `"chain": "regtest"` and some block count (≥101). If it errors / isn't
running, start it and prime a wallet + coins:

```sh
mkdir -p /tmp/p2pool-regtest
/opt/homebrew/bin/bitcoind -regtest -datadir=/tmp/p2pool-regtest -daemon -rpcport=19443 -rpcuser=p2pool -rpcpassword=p2pool -zmqpubhashblock=tcp://127.0.0.1:28332 -fallbackfee=0.0001
sleep 2
B createwallet p2pool 2>/dev/null || B loadwallet p2pool
ADDR=$(B getnewaddress)
B generatetoaddress 101 "$ADDR"     # spendable coinbase + a chain to build on
```

Sanity:

```sh
B getblockcount          # height
rpc getnewaddress '["x","bech32"]' | jq -r .result   # wallet works -> prints a bcrt1q... address
```

> The sim never needs you to mine manually again — block-finds do it. The only
> reason for the wallet here is to hand each node a distinct payout address.

---

## 2. Build the binary (with the `sim` feature)

Two builds matter:

```sh
# debug — fine for a single node
cargo build -p p2poolv2_node --features sim

# release — REQUIRED for multi-node swarms (see gotcha #1)
cargo build -p p2poolv2_node --features sim --release
```


---

## 3. Test A — single node grows the share chain (Phase 1)

Config lives in `config-dev.toml` (already has a `[sim]` block). Run with a
throwaway store so existing data is untouched, logging to a file:

Run it as a **single line** (don't split it with a `\` — pasting the
continuation often drops you into a `dquote>` prompt; if that happens, Ctrl-C):

```sh
P2POOL_STORE_PATH=/tmp/store-sim-A.db ./target/debug/p2poolv2 --config config-dev.toml > /tmp/sim-A.log 2>&1 &
```

zsh prints the background pid itself (e.g. `[1] 12345`).

Watch the chain grow (each line = one confirmed synthetic share):

```sh
sleep 20
grep "Promoted block" /tmp/sim-A.log | tail -5
```

Expect heights climbing (`... to confirmed height Some(1)`, `Some(2)`, …) every
few seconds. Cross-check via the API:

```sh
curl -s http://127.0.0.1:46884/chain_info | jq '{tip: .chain_tip_height}'
```

**What you're seeing:** the closed-loop emitter pacing at ≈ difficulty·2³²/H,
shares passing the *real* validation/organise path (no errors = ASERT, merkle,
commitment all check out). No p2p, no blocks yet.

Stop it:

```sh
kill %1    # or: pkill -f 'target/debug/p2poolv2'
```

---

## 4. Test B — 20-node swarm: propagation + convergence (Phase 2)

The harness lives in `load-tests/sim/`. Launch 20 nodes (release):

```sh
./load-tests/sim/run-swarm.sh 20
```

It builds release, generates one config per node under `/tmp/p2pool-sim/`
(distinct ports, distinct seed, distinct payout address, fresh store, a
`dial_peers` topology), launches them, and writes PIDs. Give them ~30 s, then:

```sh
./load-tests/sim/observe.sh
```

Read the table:
- **peers = 19** on every node → full mesh formed.
- **tip_h** all equal (or split across the latest 1–2 heights) → converged. A
  snapshot often straddles two heights because the tip is advancing; that's
  normal, not a partition.
- **distinct tips: 1** (or 2 transiently) and **alive: 20/20**.
- bottom line shows `error-lines=0`.

Re-run `observe.sh` a few times — heights should climb together. This proves
synthetic shares propagate and validate across 20 independent processes.

Leave it running for the next test, or stop with:

```sh
./load-tests/sim/stop-swarm.sh
```

---

## 5. Test C — latency makes uncles appear (Phase 2 headline)

Over loopback, propagation beats the block interval, so with no delay the chain
is near-linear (≈0% uncles). Inject per-node announcement latency and the uncle
rate rises. Run three swarms and compare (stop between each):

```sh
for L in 0 200 750; do
  ./load-tests/sim/stop-swarm.sh >/dev/null 2>&1
  LATENCY_MS=$L ./load-tests/sim/run-swarm.sh 20 >/dev/null 2>&1
  sleep 45
  echo "=== LATENCY_MS=$L ==="
  ./load-tests/sim/observe.sh | grep "node 0:"
done
./load-tests/sim/stop-swarm.sh
```

`observe.sh`'s `node 0:` line reports `uncle-rate`. Expect roughly:
`0 ms → ~0%`, `200 ms → ~35%`, `750 ms → ~50%` — monotonic, saturating.

Under the hood it greps the `sim-uncle:` log lines:

```sh
grep "sim-uncle:" /tmp/p2pool-sim/node-0.log | tail -3
```

---

## 6. Test D — block-finds submit real regtest blocks (Phase 3)

Each emitted share is a block with probability `1/RATIO`. Lower `RATIO` to make
this frequent and watch the **bitcoin** height climb (the sim nodes are mining
real regtest blocks).

```sh
./load-tests/sim/stop-swarm.sh >/dev/null 2>&1
echo "bitcoin height before: $(B getblockcount)"
RATIO=20 LATENCY_MS=100 ./load-tests/sim/run-swarm.sh 20
sleep 40
echo "bitcoin height after:  $(B getblockcount)"
grep -h "sim block-find" /tmp/p2pool-sim/node-*.log | wc -l        # attempts
grep -h "Block submitted successfully" /tmp/p2pool-sim/node-*.log | wc -l   # accepted
```

Expect the bitcoin height to jump several blocks and "submitted successfully"
lines. The full real path runs for free: block submit → ZMQ `hashblock` → GBT
refresh → the share chain continues on the new bitcoin tip.

---

## 7. Test E — the PPLNS payout is a real multi-way split

Decode the coinbase of a recently sim-mined block (keep the swarm from Test D
running so the window has accumulated shares from several distinct miners):

```sh
TIP=$(B getblockcount)
for ht in $((TIP-2)) $((TIP-1)) $TIP; do
  h=$(B getblockhash $ht)
  echo "=== block $ht coinbase ==="
  B getblock "$h" 2 | jq -r '.tx[0].vout | "outputs: \(length)",
    (.[] | "  \(.value)  \(.scriptPubKey.address // .scriptPubKey.type)")'
done
```

Expect some blocks paying **several distinct `bcrt1q…` addresses** with amounts
that sum to the subsidy (e.g. `13.75 + 11.25`), plus a `nulldata` output (the
witness commitment). That split is the PPLNS distribution, proportional to each
miner's share contribution in the window.

> Breadth: the number of payees = distinct miners with weight in the PPLNS
> window, and the window spans `WINDOW_SHARES` shares (default = `RATIO`). With
> 20 nodes and `WINDOW_SHARES=50` you'll see ~17–20 payees per block once the
> chain is deeper than the window. (On regtest the window would otherwise
> collapse to one payee — the `pplns_window_shares` sim knob is what makes it
> mainnet-like; see the plan's findings. A 2- or 3-payee block at tiny windows
> is just a share + its uncle(s), split 55/45 or 40/30/30.)

Stop everything:

```sh
./load-tests/sim/stop-swarm.sh
```

---

## 8. Where things live

| Thing | Path |
|---|---|
| Single-node config | `config-dev.toml` (has `[sim]`) |
| Swarm run dir | `/tmp/p2pool-sim/` |
| Per-node config | `/tmp/p2pool-sim/node-<i>.toml` |
| Per-node log | `/tmp/p2pool-sim/node-<i>.log` |
| Per-node store | `/tmp/p2pool-sim/store-<i>.db` |
| PIDs | `/tmp/p2pool-sim/pids.txt` |
| Node APIs | `http://127.0.0.1:760<i>` (node i) |
| regtest bitcoind | datadir `/tmp/p2pool-regtest`, RPC `:19443`, ZMQ `:28332` |

Useful log greps (per node or across all):

```sh
grep "Promoted block" /tmp/p2pool-sim/node-0.log | tail        # chain growth
grep "sim-uncle:"      /tmp/p2pool-sim/node-0.log | wc -l       # uncles
grep "sim block-find"  /tmp/p2pool-sim/node-*.log | wc -l       # block-finds
grep -iE "error|panic" /tmp/p2pool-sim/node-*.log | grep -v median   # problems
```

Useful API calls (node 0):

```sh
curl -s :7600/chain_info | jq            # tip/candidate heights, total work
curl -s :7600/peers | jq length          # peer count
```

---

## 9. Env knobs for `run-swarm.sh`

`run-swarm.sh [N]` (default N=20). Override with env vars:

| Var | Default | Meaning |
|---|---|---|
| `RATIO` | 10000 | shares per block-find (lower = more blocks) |
| `LATENCY_MS` | 0 | per-node outbound announce delay (raise for uncles) |
| `WINDOW_SHARES` | = `RATIO` | PPLNS payout window in shares (how many miners appear in a coinbase) |
| `HASHRATE` | 1.0e12 | modeled per-node hashrate (higher = faster shares) |
| `DISTINCT_ADDR` | 1 | each node gets its own payout address via the wallet |
| `DIAL_FANOUT` | 3 | how many earlier peers each node dials |
| `PROFILE` | release | `release` or `debug` |
| `RUN_DIR` | /tmp/p2pool-sim | where configs/logs/stores go |
| `BASE_P2P`/`BASE_STRATUM`/`BASE_API` | 7000/7300/7600 | first ports |

---

## 10. Gotchas

1. **Swarms must run release.** A debug build hits a `debug_assert_eq!` inside
   `libp2p-request-response` under connection churn and nodes abort (you'd see
   ~most of 20 die). `run-swarm.sh` defaults to release; don't override
   `PROFILE=debug` for multi-node runs.
2. **Nodes run in the background.** `run-swarm.sh` returns to your prompt while
   20 nodes keep running. Always end a session with `stop-swarm.sh` (or
   `pkill -f release/p2poolv2`) or you'll have orphans on the next run (port
   clashes).
3. **High block rates drop a few shares.** At very fast chains you'll see
   `Share timestamp … not greater than median time past` rejections — a benign
   1-second-granularity artifact, not a failure.
4. **`getnewaddress` needs a loaded wallet.** If `DISTINCT_ADDR=1` can't reach a
   wallet it silently falls back to one shared address (you'd see one payout
   address). Confirm the wallet with the sanity check in step 1.
