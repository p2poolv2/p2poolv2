#!/usr/bin/env python3
"""Plot sim-swarm time series to a PNG from the per-node logs.

Reads RUN_DIR (env, default /tmp/p2pool-sim) and renders stacked time-series
panels — share rate, pool difficulty, uncle rate, cumulative block-finds — plus
a per-node emission-vs-hashrate bar. Run after (or during) a swarm; re-run to
refresh. Output: RUN_DIR/metrics.png, or the path given as argv[1].

Data sources (all timestamped) from the logs:
  "Promoted block … confirmed height Some(N)"  -> main-chain share rate
  "sim-uncle: … references N uncle(s)"          -> uncle rate
  "sim stats: … pool_difficulty=D …"            -> ASERT difficulty / emitted
  "Block submitted successfully"                -> bitcoin block-finds
"""
import os
import re
import sys
import glob
import bisect
from datetime import datetime

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

RUN_DIR = os.environ.get("RUN_DIR", "/tmp/p2pool-sim")
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(RUN_DIR, "metrics.png")

TS = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{1,6})")


def parse_ts(line):
    m = TS.search(line)
    if not m:
        return None
    return datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S.%f").timestamp()


def events(path, pattern):
    pat = re.compile(pattern)
    out = []
    try:
        with open(path, errors="replace") as f:
            for line in f:
                if pat.search(line):
                    t = parse_ts(line)
                    if t is not None:
                        out.append((t, line))
    except FileNotFoundError:
        pass
    return out


node0 = os.path.join(RUN_DIR, "node-0.log")
# Main chain / uncles: node 0's view (the confirmed chain is shared, so one
# node is representative and avoids cross-node double counting).
promos = events(node0, r"to confirmed height Some\(")
uncles = events(node0, r"sim-uncle:")
# Difficulty + block-finds: aggregate across ALL nodes. Difficulty is a shared
# pool quantity, so pooling every node's periodic samples gives a dense series
# (node 0 alone logs only every ~15s and slowly). Block-finds happen on whatever
# node draws the hit.
stats, subs = [], []
for p in glob.glob(os.path.join(RUN_DIR, "node-*.log")):
    stats += events(p, r"sim stats:")
    subs += events(p, r"sim block-find:")
stats.sort()
subs.sort()

all_ts = [t for t, _ in promos + uncles + stats + subs]
if not all_ts:
    print("no plottable data in", RUN_DIR, file=sys.stderr)
    sys.exit(1)
t0 = min(all_ts)
span = max(max(all_ts) - t0, 1.0)
bin_s = max(5.0, span / 40.0)
nb = int(span // bin_s) + 1


def bin_counts(ev):
    counts = [0] * nb
    for t, _ in ev:
        b = int((t - t0) // bin_s)
        if 0 <= b < nb:
            counts[b] += 1
    return counts


# Uncle rate = uncles / (main-chain blocks + uncles), i.e. the % of all
# produced shares that became uncles instead of extending the main chain.
# Each "sim-uncle:" line reports how many uncles that block referenced (N).
uncle_ev = []
for t, l in uncles:
    m = re.search(r"references (\d+) uncle", l)
    uncle_ev.append((t, int(m.group(1)) if m else 1))
uncle_ev.sort()
ut = [t - t0 for t, _ in uncle_ev]
uprefix = [0]
for _, n in uncle_ev:
    uprefix.append(uprefix[-1] + n)

xs = [(i + 0.5) * bin_s for i in range(nb)]
pc = bin_counts(promos)
share_rate = [c / bin_s for c in pc]
uc = [0] * nb  # uncles (summing N) per bin
for t, n in uncle_ev:
    b = int((t - t0) // bin_s)
    if 0 <= b < nb:
        uc[b] += n
uncle_rate = [(100.0 * u / (p + u) if (p + u) > 0 else 0.0) for u, p in zip(uc, pc)]

# Cumulative (running-average) overlays — converge to the run's characteristic
# value, so they're readable and comparable across runs even when the binned
# series is spiky at the regulated ~0.1/s rate.
pt = sorted(t - t0 for t, _ in promos)
cum_rate_y = [(i + 1) / pt[i] if pt[i] > 0 else 0.0 for i in range(len(pt))]
cum_uncle_y = []
for i in range(len(pt)):
    u = uprefix[bisect.bisect_right(ut, pt[i])]  # uncles up to this block
    b = i + 1                                     # main-chain blocks so far
    cum_uncle_y.append(100.0 * u / (b + u) if (b + u) > 0 else 0.0)

dxs = [t - t0 for t, _ in stats]
dys = [float(re.search(r"pool_difficulty=([0-9.]+)", l).group(1)) for _, l in stats]
sxs = [t - t0 for t, _ in subs]
scum = list(range(1, len(subs) + 1))

# Per-node emission vs hashrate (proportionality bar).
nodes = sorted(glob.glob(os.path.join(RUN_DIR, "node-*.toml")))
N = len(nodes)
hrs, ems = [], []
for i in range(N):
    hr = 0.0
    try:
        with open(os.path.join(RUN_DIR, f"node-{i}.toml")) as f:
            for line in f:
                if line.strip().startswith("hashrate "):
                    hr = float(line.split("=")[1])
    except FileNotFoundError:
        pass
    em = 0
    s = events(os.path.join(RUN_DIR, f"node-{i}.log"), r"sim stats:")
    if s:
        m = re.search(r"emitted=(\d+)", s[-1][1])
        em = int(m.group(1)) if m else 0
    hrs.append(hr)
    ems.append(em)
hr_tot = sum(hrs) or 1.0
em_tot = sum(ems) or 1.0

# Title from node-0 params.
params = {}
try:
    with open(os.path.join(RUN_DIR, "node-0.toml")) as f:
        for line in f:
            for k in ("block_to_share_ratio", "propagation_delay_ms",
                      "pplns_window_shares", "network_hashrate",
                      "ideal_block_time_secs"):
                if line.strip().startswith(k + " "):
                    params[k] = line.split("=")[1].strip()
except FileNotFoundError:
    pass
title = (f"sim swarm  N={N}  ratio=1:{params.get('block_to_share_ratio','?')}  "
         f"window={params.get('pplns_window_shares','?')}  "
         f"latency(node0)={params.get('propagation_delay_ms','?')}ms  "
         f"span={span:.0f}s")
# Target share rate = 1 / ideal_block_time (sim override, else the production 10s).
ibt = float(params.get("ideal_block_time_secs") or 10)
tgt_rate = 1.0 / (ibt if ibt > 0 else 10)

fig, ax = plt.subplots(5, 1, figsize=(11, 15))
ax[0].plot(xs, share_rate, marker=".", alpha=0.25, color="C0", label="binned")
ax[0].plot(pt, cum_rate_y, color="C0", lw=2, label="cumulative avg")
ax[0].axhline(tgt_rate, ls="--", color="gray", label=f"{tgt_rate:.3g}/s target")
ax[0].set_ylabel("share rate /s")
ax[0].legend(loc="upper right", fontsize=8)
ax[0].set_title(title, fontsize=10)

# Difficulty: scatter (samples pooled from all nodes at independent times, so
# don't connect them with a line).
ax[1].plot(dxs, dys, ".", ms=4, color="C1")
ax[1].set_ylabel("pool difficulty")

# Uncle rate: the binned series spikes to 100% in low-count bins, so scale the
# axis to the cumulative line (the meaningful, comparable value) and let binned
# spikes clip.
ax[2].plot(xs, uncle_rate, marker=".", alpha=0.2, color="C2", label="binned")
ax[2].plot(pt, cum_uncle_y, color="C2", lw=2, label="cumulative avg")
ax[2].set_ylabel("uncle rate %\n(uncles ÷ all shares)")
cum_max = max(cum_uncle_y) if cum_uncle_y else 0.0
ax[2].set_ylim(0, max(cum_max * 1.3, 1.0))
ax[2].legend(loc="upper right", fontsize=8)

ax[3].plot(sxs, scum, drawstyle="steps-post", marker=".", color="C3")
ax[3].set_ylabel("block-finds\n(cumulative)")
if not subs:
    ax[3].text(0.5, 0.5, "no block-finds in this run\n(lower RATIO or run longer)",
               transform=ax[3].transAxes, ha="center", va="center",
               color="gray", fontsize=9)

for a in ax[:4]:
    a.grid(alpha=0.3)
    a.set_xlim(0, span)
    a.set_xlabel("time since start (s)")

# Bottom panel: hashrate share vs emission share per node (bars).
idx = list(range(N))
w = 0.4
ax[4].bar([i - w / 2 for i in idx], [100 * h / hr_tot for h in hrs], w, label="hashrate %")
ax[4].bar([i + w / 2 for i in idx], [100 * e / em_tot for e in ems], w, label="emitted %")
ax[4].set_ylabel("% of total")
ax[4].set_xlabel("node")
ax[4].set_xticks(idx)
ax[4].legend(loc="upper right", fontsize=8)
ax[4].grid(alpha=0.3, axis="y")

fig.tight_layout()
fig.savefig(OUT, dpi=110)
print(f"wrote {OUT}  "
      f"({len(promos)} promotions, {len(uncles)} uncle-blocks, "
      f"{len(subs)} block-finds, {span:.0f}s span)")
