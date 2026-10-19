#!/usr/bin/env python3
"""Check from the outside that sim block-finds pay a late miner only once mature.

The late-miner scenario (failures.sh late-miner) starts one node with its
emitter off and turns it on once the chain is past the maturity depth. This
script reads only the node logs, the node API and bitcoind, never the payout
code, and checks the payout maturity rule against the real regtest coinbases:

  * the late miner's bitcoin address is never paid by a block whose paying
    share is less than COINBASE_MATURITY above the late miner's first share
    (confirmed or uncle), and
  * it is paid by the first block whose paying share is at least
    COINBASE_MATURITY above the late miner's first confirmed share.

A share is paid through a nephew too, but an uncle is never above its nephew,
so the first bound uses the lowest of the late miner's confirmed and uncle
heights. The second uses confirmed shares only, since an uncle is paid only
once its nephew matures.

Exit codes: 0 pass, 1 rule violated, 2 inconclusive (no block has reached the
maturity depth for the late miner yet), 3 setup error.

Env: RUN_DIR (default /tmp/p2pool-sim), LATE_MINER (node index, required),
BASE_API (default 7600), RPC_URL, RPC_USER, RPC_PASS (regtest bitcoind).
"""
import base64
import glob
import json
import os
import re
import sys
import tomllib
import traceback
import urllib.error
import urllib.request

EXIT_PASS = 0
EXIT_VIOLATION = 1
EXIT_INCONCLUSIVE = 2
EXIT_SETUP_ERROR = 3

# Shares per /shares request; the API caps it at 100.
SHARES_PAGE_SIZE = 100

BLOCK_FIND_LINE = re.compile(
    r"sim block-find: .* submitting block (?P<bitcoin_hash>[0-9a-f]{64}) "
    r"at height \d+ prev_share (?P<prev_share>[0-9a-f]{64})"
)


class SetupError(Exception):
    """The run cannot be checked: missing config, unreachable service, etc."""


def read_node_config(run_dir, node_index):
    path = os.path.join(run_dir, f"node-{node_index}.toml")
    try:
        with open(path, "rb") as config_file:
            return tomllib.load(config_file)
    except OSError as error:
        raise SetupError(f"cannot read {path}: {error}") from error


def node_config_paths(run_dir):
    return sorted(glob.glob(os.path.join(run_dir, "node-*.toml")))


def require_distinct_address(run_dir, late_address):
    """The check is meaningless if another node pays to the same address."""
    sharing_nodes = []
    for path in node_config_paths(run_dir):
        with open(path, "rb") as config_file:
            config = tomllib.load(config_file)
        if config["sim"]["miner_address"] == late_address:
            sharing_nodes.append(os.path.basename(path))
    if len(sharing_nodes) > 1:
        raise SetupError(
            f"late miner address {late_address} is shared by {', '.join(sharing_nodes)}; "
            "run the swarm with DISTINCT_ADDR=1 and a loaded wallet"
        )


def http_json(url, payload=None, headers=None):
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(url, data=data, headers=headers or {})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def api_get(api_port, path):
    return http_json(f"http://127.0.0.1:{api_port}{path}")


def bitcoind_call(method, params):
    url = os.environ.get("RPC_URL", "http://127.0.0.1:19443")
    user = os.environ.get("RPC_USER", "p2pool")
    password = os.environ.get("RPC_PASS", "p2pool")
    credentials = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {"Authorization": f"Basic {credentials}", "Content-Type": "text/plain"}
    payload = {"jsonrpc": "1.0", "id": "maturity-check", "method": method, "params": params}
    try:
        response = http_json(url, payload, headers)
    except urllib.error.HTTPError as error:
        # bitcoind answers RPC errors (e.g. unknown block) with HTTP 500 and a
        # JSON body carrying the error.
        response = json.load(error)
    if response.get("error"):
        return None
    return response["result"]


def collect_block_finds(run_dir):
    """Every block-find logged by any node: (bitcoin block hash, prev share)."""
    block_finds = []
    for log_path in sorted(glob.glob(os.path.join(run_dir, "node-*.log"))):
        with open(log_path, errors="replace") as log_file:
            for line in log_file:
                match = BLOCK_FIND_LINE.search(line)
                if match:
                    block_finds.append((match["bitcoin_hash"], match["prev_share"]))
    return block_finds


def coinbase_payees(block):
    coinbase = block["tx"][0]
    return {
        output["scriptPubKey"]["address"]
        for output in coinbase["vout"]
        if "address" in output["scriptPubKey"]
    }


def paying_height(api_port, prev_share):
    """Height of the share whose parent is `prev_share`, or None when the
    queried node does not know `prev_share` or has no height for it."""
    try:
        # The endpoint answers with a list of shares; a hash lookup has one.
        shares = api_get(api_port, f"/share?hash={prev_share}")
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise
    if not shares or shares[0].get("height") is None:
        return None
    return shares[0]["height"] + 1


def late_miner_first_heights(api_port, late_address):
    """Lowest confirmed height and lowest confirmed-or-uncle height mined by
    the late miner, or None for either when it has none."""
    tip = api_get(api_port, "/shares?num=1")["to_height"]
    first_confirmed = None
    first_any = None
    page_top = tip
    while page_top >= 0:
        page = api_get(api_port, f"/shares?to={page_top}&num={SHARES_PAGE_SIZE}")
        for share in page["shares"]:
            if share["miner_bitcoin_address"] == late_address:
                first_confirmed = min_height(first_confirmed, share["height"])
                first_any = min_height(first_any, share["height"])
            for uncle in share["uncles"]:
                if uncle["miner_bitcoin_address"] == late_address and uncle["height"] is not None:
                    first_any = min_height(first_any, uncle["height"])
        page_top = page["from_height"] - 1
    return first_confirmed, first_any


def min_height(current, candidate):
    return candidate if current is None else min(current, candidate)


def evaluate(rows, maturity, first_confirmed, first_any):
    """Return (exit code, reason) for the per-block rows."""
    early_payments = [
        row for row in rows if row["late_paid"] and row["paying_height"] - first_any < maturity
    ]
    if early_payments:
        heights = ", ".join(str(row["paying_height"]) for row in early_payments)
        return EXIT_VIOLATION, f"late miner paid before maturity at paying height(s) {heights}"

    mature_rows = [row for row in rows if row["paying_height"] - first_confirmed >= maturity]
    if not mature_rows:
        return EXIT_INCONCLUSIVE, "no block-find has reached the maturity depth for the late miner yet"
    first_mature = min(mature_rows, key=lambda row: row["paying_height"])
    if not first_mature["late_paid"]:
        return (
            EXIT_VIOLATION,
            f"late miner not paid by the first mature block-find at paying height "
            f"{first_mature['paying_height']}",
        )
    return EXIT_PASS, f"late miner first paid at paying height {first_mature['paying_height']}"


def print_report(rows, late_index, late_address, maturity, first_confirmed, first_any):
    print(f"late miner: node {late_index} ({late_address}), coinbase maturity {maturity}")
    print(f"first late share: confirmed {first_confirmed}, confirmed or uncle {first_any}")
    print(f"{'bitcoin block':<20} {'paying_h':>9} {'p-first':>8} {'mature':>7} {'late_paid':>10}")
    for row in sorted(rows, key=lambda row: row["paying_height"]):
        depth = row["paying_height"] - first_confirmed
        print(
            f"{row['bitcoin_hash'][:16] + '..':<20} {row['paying_height']:>9} {depth:>8} "
            f"{'yes' if depth >= maturity else 'no':>7} {'yes' if row['late_paid'] else 'no':>10}"
        )


def run():
    run_dir = os.environ.get("RUN_DIR", "/tmp/p2pool-sim")
    late_index = os.environ.get("LATE_MINER")
    if late_index is None or late_index == "":
        raise SetupError("LATE_MINER is not set")
    api_port = int(os.environ.get("BASE_API", "7600"))

    late_config = read_node_config(run_dir, late_index)
    late_address = late_config["sim"]["miner_address"]
    maturity = late_config["sim"].get("coinbase_maturity")
    if maturity is None:
        raise SetupError(f"node-{late_index}.toml has no [sim] coinbase_maturity")
    require_distinct_address(run_dir, late_address)

    first_confirmed, first_any = late_miner_first_heights(api_port, late_address)
    if first_confirmed is None:
        print("maturity check: INCONCLUSIVE (late miner has no confirmed share yet)")
        return EXIT_INCONCLUSIVE

    rows = []
    for bitcoin_hash, prev_share in collect_block_finds(run_dir):
        block = bitcoind_call("getblock", [bitcoin_hash, 2])
        if block is None:
            # Rejected by bitcoind, so it pays nobody.
            continue
        height = paying_height(api_port, prev_share)
        if height is None:
            continue
        rows.append(
            {
                "bitcoin_hash": bitcoin_hash,
                "paying_height": height,
                "late_paid": late_address in coinbase_payees(block),
            }
        )

    print_report(rows, late_index, late_address, maturity, first_confirmed, first_any)
    exit_code, reason = evaluate(rows, maturity, first_confirmed, first_any)
    verdict = {EXIT_PASS: "PASS", EXIT_VIOLATION: "FAIL", EXIT_INCONCLUSIVE: "INCONCLUSIVE"}[exit_code]
    print(f"maturity check: {verdict} ({reason})")
    return exit_code


def main():
    try:
        exit_code = run()
    except (SetupError, urllib.error.URLError, KeyError) as error:
        print(f"maturity check: SETUP ERROR ({error})")
        exit_code = EXIT_SETUP_ERROR
    except Exception:
        # A bug in this script must not read as a payout rule violation.
        traceback.print_exc()
        print("maturity check: SETUP ERROR (checker crashed)")
        exit_code = EXIT_SETUP_ERROR
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
