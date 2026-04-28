#!/usr/bin/env python3
"""
share_latency.py -- Compute share propagation and confirmation latencies
across P2Poolv2 nodes by parsing their log files.

Propagation latency: time from a share being mined at one node until it
is validated at another node.

Confirmation latency: time from a share first appearing at a node (mined
or received) until it is promoted to the confirmed chain at that node.

By default only confirmed chain shares are included. Use --include-uncles
to also include uncle shares in the statistics.

Usage:
  python3 debug_tools/share_latency.py 'logs/node-*.log'
  python3 debug_tools/share_latency.py --include-uncles logs/node1.log logs/node2.log
  python3 debug_tools/share_latency.py 'logs/**/*.log'

Accepts a glob pattern (quoted to avoid shell expansion) or multiple
explicit file paths. Pipe through `less -R` for colour support.
"""

import argparse
import glob
import math
import os
import re
import sys
from datetime import datetime


# -- ANSI colours -------------------------------------------------------------

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"


# -- regex patterns ------------------------------------------------------------

TIMESTAMP_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)Z")
ANSI_ESCAPE_RE = re.compile(r"\033\[[0-9;]*m")

MINED_RE = re.compile(r"Adding share to chain: ([0-9a-f]{64})")
STORE_PEER_RE = re.compile(
    r"Adding share and organising header atomically: ([0-9a-f]{64})"
)
VALID_OK_RE = re.compile(r"Share block ([0-9a-f]{64}) validated successfully")
CONFIRMED_RE = re.compile(
    r"Promoted block ([0-9a-f]{64}) to confirmed height (Some\(\d+\)|None)"
)


# -- helpers -------------------------------------------------------------------

def parse_timestamp(timestamp_string):
    """Parse an ISO 8601 timestamp, truncating sub-microsecond precision."""
    # Python datetime only handles up to 6 fractional digits
    parts = timestamp_string.split(".")
    if len(parts) == 2:
        fractional = parts[1][:6].ljust(6, "0")
        timestamp_string = f"{parts[0]}.{fractional}"
    return datetime.fromisoformat(timestamp_string)


def short(block_hash):
    """Return first 8 characters of a hash for display."""
    if not block_hash or len(block_hash) < 8:
        return block_hash or "???"
    return block_hash[:8]


def compute_statistics(values):
    """Return (count, mean, stddev) for a list of float values."""
    count = len(values)
    if count == 0:
        return 0, 0.0, 0.0
    mean = sum(values) / count
    if count < 2:
        return count, mean, 0.0
    variance = sum((value - mean) ** 2 for value in values) / (count - 1)
    stddev = math.sqrt(variance)
    return count, mean, stddev


def format_duration(seconds):
    """Format seconds as a human-readable duration string."""
    if seconds < 1.0:
        return f"{seconds * 1000:.1f}ms"
    if seconds < 60.0:
        return f"{seconds:.3f}s"
    minutes = int(seconds // 60)
    remaining = seconds - minutes * 60
    return f"{minutes}m {remaining:.1f}s"


# -- per-node event extraction ------------------------------------------------

def extract_events(filepath):
    """Parse a single log file and return dicts keyed by block hash for
    each event type: mined, received, validated, confirmed, uncles."""
    mined = {}
    received = {}
    validated = {}
    confirmed = {}
    uncles = {}

    with open(filepath, "r") as file_handle:
        for line in file_handle:
            clean_line = ANSI_ESCAPE_RE.sub("", line)
            timestamp_match = TIMESTAMP_RE.search(clean_line)
            if not timestamp_match:
                continue
            timestamp = parse_timestamp(timestamp_match.group(1))

            mined_match = MINED_RE.search(clean_line)
            if mined_match:
                block_hash = mined_match.group(1)
                if block_hash not in mined:
                    mined[block_hash] = timestamp

            peer_match = STORE_PEER_RE.search(clean_line)
            if peer_match:
                block_hash = peer_match.group(1)
                if block_hash not in received:
                    received[block_hash] = timestamp

            valid_match = VALID_OK_RE.search(clean_line)
            if valid_match:
                block_hash = valid_match.group(1)
                if block_hash not in validated:
                    validated[block_hash] = timestamp

            confirmed_match = CONFIRMED_RE.search(clean_line)
            if confirmed_match:
                block_hash = confirmed_match.group(1)
                height_str = confirmed_match.group(2)
                if height_str == "None":
                    if block_hash not in uncles:
                        uncles[block_hash] = timestamp
                else:
                    if block_hash not in confirmed:
                        confirmed[block_hash] = timestamp

    return {
        "mined": mined,
        "received": received,
        "validated": validated,
        "confirmed": confirmed,
        "uncles": uncles,
    }


def confirmed_hashes_for_node(events, include_uncles):
    """Return the set of block hashes to include in latency stats."""
    hashes = set(events["confirmed"].keys())
    if include_uncles:
        hashes.update(events["uncles"].keys())
    return hashes


# -- latency computation ------------------------------------------------------

def compute_propagation_latencies(all_node_events, include_uncles):
    """For each share mined at one node, compute time until it was
    validated at each other node. Only includes shares that reached
    confirmed status (or uncle status if include_uncles is set) at
    any node. Returns a list of
    (block_hash, miner_label, receiver_label, latency_seconds) tuples."""
    # Build the set of hashes to include across all nodes
    included_hashes = set()
    for events in all_node_events.values():
        included_hashes.update(confirmed_hashes_for_node(events, include_uncles))

    results = []
    node_labels = list(all_node_events.keys())

    for miner_label in node_labels:
        miner_events = all_node_events[miner_label]
        for block_hash, mined_time in miner_events["mined"].items():
            if block_hash not in included_hashes:
                continue
            for receiver_label in node_labels:
                if receiver_label == miner_label:
                    continue
                receiver_events = all_node_events[receiver_label]
                validated_time = receiver_events["validated"].get(block_hash)
                if validated_time is not None:
                    latency = (validated_time - mined_time).total_seconds()
                    results.append(
                        (block_hash, miner_label, receiver_label, latency)
                    )
    return results


def compute_confirmation_latencies(all_node_events, include_uncles):
    """For each share at a node, compute time from first appearance
    (mined or received) to confirmed/uncle promotion. Returns a list of
    (block_hash, node_label, latency_seconds) tuples."""
    results = []

    for node_label, events in all_node_events.items():
        promoted = dict(events["confirmed"])
        if include_uncles:
            for block_hash, timestamp in events["uncles"].items():
                if block_hash not in promoted:
                    promoted[block_hash] = timestamp

        for block_hash, confirmed_time in promoted.items():
            first_seen = None
            mined_time = events["mined"].get(block_hash)
            received_time = events["received"].get(block_hash)
            if mined_time is not None and received_time is not None:
                first_seen = min(mined_time, received_time)
            elif mined_time is not None:
                first_seen = mined_time
            elif received_time is not None:
                first_seen = received_time

            if first_seen is not None:
                latency = (confirmed_time - first_seen).total_seconds()
                results.append((block_hash, node_label, latency))
    return results


# -- display -------------------------------------------------------------------

def print_propagation_report(propagation_results, include_uncles):
    """Print per-pair and aggregate propagation latency statistics."""
    scope = "confirmed + uncles" if include_uncles else "confirmed chain only"
    print(f"\n{BOLD}{GREEN}=== Share Propagation Latency ({scope}) ==={RESET}")
    print(f"{DIM}(time from mined at source to validated at receiver){RESET}\n")

    if not propagation_results:
        print(f"  {YELLOW}No cross-node propagation data found.{RESET}")
        print(f"  {DIM}(Need 2+ log files with shares mined at one node")
        print(f"   and validated at another){RESET}")
        return

    # Group by (miner, receiver) pair
    pair_latencies = {}
    for block_hash, miner, receiver, latency in propagation_results:
        pair_key = (miner, receiver)
        if pair_key not in pair_latencies:
            pair_latencies[pair_key] = []
        pair_latencies[pair_key].append((block_hash, latency))

    all_latency_values = []

    for (miner, receiver), entries in sorted(pair_latencies.items()):
        latency_values = [latency for _, latency in entries]
        all_latency_values.extend(latency_values)
        count, mean, stddev = compute_statistics(latency_values)
        minimum = min(latency_values)
        maximum = max(latency_values)

        print(f"  {CYAN}{miner}{RESET} -> {MAGENTA}{receiver}{RESET}")
        print(f"    samples: {count}")
        print(f"    mean:    {format_duration(mean)}")
        print(f"    stddev:  {format_duration(stddev)}")
        print(f"    min:     {format_duration(minimum)}")
        print(f"    max:     {format_duration(maximum)}")

        # Show top 3 outliers (highest latency)
        sorted_entries = sorted(entries, key=lambda entry: entry[1], reverse=True)
        top_outliers = sorted_entries[:3]
        print(f"    top outliers:")
        for block_hash, latency in top_outliers:
            marker = ""
            if latency < 0:
                marker = f" {RED}(negative - clock skew?){RESET}"
            print(
                f"      {DIM}{short(block_hash)}{RESET}"
                f"  {format_duration(latency)}{marker}"
            )
        print()

    # Aggregate across all pairs
    count, mean, stddev = compute_statistics(all_latency_values)
    print(f"  {BOLD}Aggregate (all pairs):{RESET}")
    print(f"    samples: {count}")
    print(f"    mean:    {BOLD}{format_duration(mean)}{RESET}")
    print(f"    stddev:  {format_duration(stddev)}")
    print(f"    min:     {format_duration(min(all_latency_values))}")
    print(f"    max:     {format_duration(max(all_latency_values))}")


def print_confirmation_report(confirmation_results, include_uncles):
    """Print per-node and aggregate confirmation latency statistics."""
    scope = "confirmed + uncles" if include_uncles else "confirmed chain only"
    print(f"\n{BOLD}{BLUE}=== Share Confirmation Latency ({scope}) ==={RESET}")
    print(f"{DIM}(time from first seen to confirmed at each node){RESET}\n")

    if not confirmation_results:
        print(f"  {YELLOW}No confirmation data found.{RESET}")
        return

    # Group by node
    node_latencies = {}
    for block_hash, node_label, latency in confirmation_results:
        if node_label not in node_latencies:
            node_latencies[node_label] = []
        node_latencies[node_label].append((block_hash, latency))

    all_latency_values = []

    for node_label, entries in sorted(node_latencies.items()):
        latency_values = [latency for _, latency in entries]
        all_latency_values.extend(latency_values)
        count, mean, stddev = compute_statistics(latency_values)
        minimum = min(latency_values)
        maximum = max(latency_values)

        print(f"  {CYAN}{node_label}{RESET}")
        print(f"    samples: {count}")
        print(f"    mean:    {format_duration(mean)}")
        print(f"    stddev:  {format_duration(stddev)}")
        print(f"    min:     {format_duration(minimum)}")
        print(f"    max:     {format_duration(maximum)}")

        # Show top 3 outliers (highest latency)
        sorted_entries = sorted(entries, key=lambda entry: entry[1], reverse=True)
        top_outliers = sorted_entries[:3]
        print(f"    top outliers:")
        for block_hash, latency in top_outliers:
            print(
                f"      {DIM}{short(block_hash)}{RESET}"
                f"  {format_duration(latency)}"
            )
        print()

    # Aggregate across all nodes
    count, mean, stddev = compute_statistics(all_latency_values)
    print(f"  {BOLD}Aggregate (all nodes):{RESET}")
    print(f"    samples: {count}")
    print(f"    mean:    {BOLD}{format_duration(mean)}{RESET}")
    print(f"    stddev:  {format_duration(stddev)}")
    print(f"    min:     {format_duration(min(all_latency_values))}")
    print(f"    max:     {format_duration(max(all_latency_values))}")


def print_overview(all_node_events):
    """Print a quick overview of shares seen per node."""
    print(f"\n{BOLD}=== Node Overview ==={RESET}\n")
    for node_label, events in sorted(all_node_events.items()):
        mined_count = len(events["mined"])
        received_count = len(events["received"])
        validated_count = len(events["validated"])
        confirmed_count = len(events["confirmed"])
        uncle_count = len(events["uncles"])
        print(
            f"  {CYAN}{node_label}{RESET}: "
            f"mined={MAGENTA}{mined_count}{RESET}  "
            f"received={CYAN}{received_count}{RESET}  "
            f"validated={GREEN}{validated_count}{RESET}  "
            f"confirmed={GREEN}{BOLD}{confirmed_count}{RESET}  "
            f"uncles={YELLOW}{uncle_count}{RESET}"
        )


# -- file resolution -----------------------------------------------------------

def resolve_files(file_arguments):
    """Resolve arguments as file paths or glob patterns.
    Returns a sorted list of unique file paths."""
    resolved = set()
    for argument in file_arguments:
        expanded = glob.glob(argument, recursive=True)
        if expanded:
            for path in expanded:
                if os.path.isfile(path):
                    resolved.add(path)
        elif os.path.isfile(argument):
            resolved.add(argument)
        else:
            print(
                f"Warning: '{argument}' did not match any files",
                file=sys.stderr,
            )
    return sorted(resolved)


# -- main ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Compute share propagation and confirmation latencies "
                    "across P2Poolv2 nodes.",
    )
    parser.add_argument(
        "--include-uncles",
        action="store_true",
        default=False,
        help="Include uncle shares in latency statistics (default: confirmed chain only)",
    )
    parser.add_argument(
        "files",
        nargs="+",
        help="Log files or glob patterns to parse",
    )
    args = parser.parse_args()

    filepaths = resolve_files(args.files)

    if not filepaths:
        print("Error: no log files found", file=sys.stderr)
        sys.exit(1)

    print(f"{DIM}Parsing {len(filepaths)} log file(s)...{RESET}")
    for filepath in filepaths:
        print(f"  {DIM}{filepath}{RESET}")

    all_node_events = {}
    for filepath in filepaths:
        label = os.path.basename(filepath)
        all_node_events[label] = extract_events(filepath)

    print_overview(all_node_events)
    propagation_results = compute_propagation_latencies(
        all_node_events, args.include_uncles
    )
    print_propagation_report(propagation_results, args.include_uncles)
    confirmation_results = compute_confirmation_latencies(
        all_node_events, args.include_uncles
    )
    print_confirmation_report(confirmation_results, args.include_uncles)


if __name__ == "__main__":
    main()
