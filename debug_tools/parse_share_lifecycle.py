#!/usr/bin/env python3
"""
parse_share_lifecycle.py -- Parse P2Poolv2 logs to show the lifecycle of
each share: received headers, block fetch, validation, candidate chain,
confirmed chain. Distinguishes locally-mined shares from peer-received.

Usage:
  python3 debug_tools/parse_share_lifecycle.py logs/p2pool.log.2026-04-23
  python3 debug_tools/parse_share_lifecycle.py logs/p2pool.log logs/p2pool.1.log

When multiple files are given, each is labelled so you can compare side by
side. Pipe through `less -R` for colour support.
"""

import re
import sys
import os


# -- colours (ANSI) ----------------------------------------------------------

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


# -- short hash helper -------------------------------------------------------

def short(hash_str):
    if not hash_str or len(hash_str) < 5:
        return hash_str or "???"
    return hash_str[:5]


# -- pattern definitions -----------------------------------------------------
# Each tuple: (compiled_regex, handler_function)
# handler(match, events, timestamp) -> None

def handle_header_batch(match, events, timestamp):
    events.append({
        "timestamp": timestamp,
        "type": "HEADER_BATCH",
        "source": "peer",
        "detail": f"Received {match.group(1)} headers from peer",
    })


def handle_candidate_add(match, events, timestamp):
    block_hash = match.group(1)
    events.append({
        "timestamp": timestamp,
        "type": "CANDIDATE_ADD",
        "hash": block_hash,
        "source": "organise",
        "detail": f"Header {short(block_hash)} organised into candidate chain",
    })


def handle_block_recv(match, events, timestamp):
    events.append({
        "timestamp": timestamp,
        "type": "BLOCK_RECV",
        "source": "peer",
        "peer": match.group(1),
        "detail": f"Block received from peer {match.group(1)[:16]}..",
    })


def handle_block_store_peer(match, events, timestamp):
    block_hash = match.group(1)
    events.append({
        "timestamp": timestamp,
        "type": "BLOCK_STORE",
        "hash": block_hash,
        "source": "peer",
        "detail": f"Block {short(block_hash)} stored + header organised (from peer)",
    })


def handle_block_store_local(match, events, timestamp):
    block_hash = match.group(1)
    events.append({
        "timestamp": timestamp,
        "type": "BLOCK_STORE",
        "hash": block_hash,
        "source": "local",
        "detail": f"Block {short(block_hash)} added to chain (locally mined)",
    })


def handle_valid_ok(match, events, timestamp):
    block_hash = match.group(1)
    events.append({
        "timestamp": timestamp,
        "type": "VALID_OK",
        "hash": block_hash,
        "detail": f"Block {short(block_hash)} validated OK",
    })


def handle_valid_fail(match, events, timestamp):
    block_hash = match.group(1)
    reason = match.group(2)
    events.append({
        "timestamp": timestamp,
        "type": "VALID_FAIL",
        "hash": block_hash,
        "detail": f"Block {short(block_hash)} FAILED: {reason}",
    })


def handle_confirmed(match, events, timestamp):
    block_hash = match.group(1)
    raw_height = match.group(2)
    if raw_height.startswith("Some"):
        height = raw_height.replace("Some(", "").replace(")", "")
    else:
        height = "none"
    events.append({
        "timestamp": timestamp,
        "type": "CONFIRMED",
        "hash": block_hash,
        "height": height,
        "detail": f"Block {short(block_hash)} CONFIRMED at height {height}",
    })


def handle_reorg(match, events, timestamp):
    events.append({
        "timestamp": timestamp,
        "type": "REORG",
        "detail": "Confirmed chain REORG triggered",
    })


def handle_reschedule(match, events, timestamp):
    block_hash = match.group(1)
    parent_hash = match.group(2)
    events.append({
        "timestamp": timestamp,
        "type": "RESCHEDULE",
        "hash": block_hash,
        "detail": f"Reschedule {short(block_hash)} after {short(parent_hash)}",
    })


def handle_inv_send(match, events, timestamp):
    block_hash = match.group(1)
    events.append({
        "timestamp": timestamp,
        "type": "INV_SEND",
        "hash": block_hash,
        "detail": f"INV sent for {short(block_hash)}",
    })


def handle_inv_recv(match, events, timestamp):
    block_hash = match.group(1)
    events.append({
        "timestamp": timestamp,
        "type": "INV_RECV",
        "hash": block_hash,
        "detail": f"INV received for {short(block_hash)}",
    })


def handle_notfound(match, events, timestamp):
    block_hash = match.group(1)
    events.append({
        "timestamp": timestamp,
        "type": "NOTFOUND",
        "hash": block_hash,
        "detail": f"Block {short(block_hash)} exists but NOT served (not confirmed/uncle)",
    })


def handle_fetch_timeout(match, events, timestamp):
    block_hash = match.group(1)
    events.append({
        "timestamp": timestamp,
        "type": "FETCH_TIMEOUT",
        "hash": block_hash,
        "detail": f"Fetch TIMEOUT for {short(block_hash)}",
    })


def handle_header_err(match, events, timestamp):
    events.append({
        "timestamp": timestamp,
        "type": "HEADER_ERR",
        "detail": f"Header chain ERROR: {match.group(1)}",
    })


PATTERNS = [
    (re.compile(r"Received (\d+) ShareHeaders"), handle_header_batch),
    (re.compile(r"Organised header ([0-9a-f]{64}) into candidate chain"), handle_candidate_add),
    (re.compile(r"Received response ShareBlock from peer: ([0-9A-Za-z]+)"), handle_block_recv),
    (re.compile(r"Adding share and organising header atomically: ([0-9a-f]{64})"), handle_block_store_peer),
    (re.compile(r"Adding share to chain: ([0-9a-f]{64})"), handle_block_store_local),
    (re.compile(r"Share block ([0-9a-f]{64}) validated successfully"), handle_valid_ok),
    (re.compile(r"Share block ([0-9a-f]{64}) validation failed: (.+)"), handle_valid_fail),
    (re.compile(r"Promoted block ([0-9a-f]{64}) to confirmed height (Some\(\d+\)|None)"), handle_confirmed),
    (re.compile(r"Confirmed reorg needed"), handle_reorg),
    (re.compile(r"Scheduling dependent ([0-9a-f]{64}) for validation after ([0-9a-f]{64})"), handle_reschedule),
    (re.compile(r"Sending Inv for block ([0-9a-f]{64}) to peer"), handle_inv_send),
    (re.compile(r"Received Inv: BlockHashes\(\[([0-9a-f]{64})\]\)"), handle_inv_recv),
    (re.compile(r"Block ([0-9a-f]{64}) exists but is not confirmed or uncle of confirmed"), handle_notfound),
    (re.compile(r"Block request timed out for ([0-9a-f]{64})"), handle_fetch_timeout),
    (re.compile(r"Error handling received share headers: (.+)"), handle_header_err),
]

TIMESTAMP_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)")

# Pattern to extract parentage from "Received ShareBlock" debug lines.
# Captures the block_hash from the next "Adding share" line and the
# prev_share_blockhash + uncles from the ShareBlock dump.
SHAREBLOCK_RE = re.compile(
    r"prev_share_blockhash: ([0-9a-f]{64}), uncles: \[([^\]]*)\]"
)


def build_parentage(filepath):
    """Scan log for ShareBlock debug lines and return a dict mapping
    block_hash -> (prev_hash, [uncle_hashes])."""
    parentage = {}
    pending_prev = None
    pending_uncles = None
    with open(filepath, "r") as fh:
        for line in fh:
            share_match = SHAREBLOCK_RE.search(line)
            if share_match:
                pending_prev = share_match.group(1)
                raw_uncles = share_match.group(2).strip()
                if raw_uncles:
                    pending_uncles = [
                        uncle.strip()
                        for uncle in raw_uncles.split(",")
                        if uncle.strip()
                    ]
                else:
                    pending_uncles = []
            elif pending_prev is not None:
                # The line right after contains "Adding share ... atomically: <hash>"
                # or "Adding share to chain: <hash>"
                add_match = re.search(
                    r"Adding share (?:and organising header atomically|to chain): ([0-9a-f]{64})",
                    line,
                )
                if add_match:
                    block_hash = add_match.group(1)
                    parentage[block_hash] = (pending_prev, pending_uncles)
                pending_prev = None
                pending_uncles = None
    return parentage


def parentage_suffix(block_hash, parentage):
    """Return a string like ' (prev:abcde uncles:12345,67890)' if parentage
    is known for this hash, otherwise empty string."""
    if block_hash not in parentage:
        return ""
    prev_hash, uncle_hashes = parentage[block_hash]
    parts = [f"prev:{short(prev_hash)}"]
    if uncle_hashes:
        uncle_str = ",".join(short(uncle) for uncle in uncle_hashes)
        parts.append(f"uncles:{uncle_str}")
    return f" ({' '.join(parts)})"


# -- colour an event line ----------------------------------------------------

TAG_STYLES = {
    "HEADER_BATCH": (f"{CYAN}[HEADERS]{RESET}", None),
    "CANDIDATE_ADD": (f"{BLUE}[CAND +] {RESET}", None),
    "BLOCK_RECV": (f"{CYAN}[RECV]  {RESET}", None),
    "VALID_OK": (f"{GREEN}[OK]    {RESET}", None),
    "VALID_FAIL": (f"{RED}[FAIL]  {RESET}", RED),
    "CONFIRMED": (f"{GREEN}{BOLD}[CONF]  {RESET}", GREEN),
    "REORG": (f"{RED}{BOLD}[REORG] {RESET}", f"{RED}{BOLD}"),
    "RESCHEDULE": (f"{YELLOW}[RESCHED]{RESET}", None),
    "INV_SEND": (f"{DIM}[INV->] {RESET}", DIM),
    "INV_RECV": (f"{DIM}[INV<-] {RESET}", DIM),
    "NOTFOUND": (f"{RED}[NOTFND]{RESET}", RED),
    "FETCH_TIMEOUT": (f"{RED}[TMOUT] {RESET}", RED),
    "HEADER_ERR": (f"{RED}{BOLD}[HDRERR]{RESET}", RED),
}


def colour_event(event):
    time = f"{DIM}{event['timestamp']}{RESET}"

    event_type = event["type"]

    if event_type == "BLOCK_STORE":
        if event.get("source") == "local":
            tag = f"{MAGENTA}[MINED] {RESET}"
        else:
            tag = f"{CYAN}[RECV]  {RESET}"
        detail = event["detail"]
    elif event_type in TAG_STYLES:
        tag, detail_colour = TAG_STYLES[event_type]
        detail = event["detail"]
        if detail_colour:
            detail = f"{detail_colour}{detail}{RESET}"
    else:
        tag = f"[{event_type}]"
        detail = event["detail"]

    return f"{time}  {tag} {detail}"


# -- parse a single log file -------------------------------------------------

def parse_log(filepath):
    parentage = build_parentage(filepath)
    events = []
    with open(filepath, "r") as fh:
        for line in fh:
            timestamp_match = TIMESTAMP_RE.match(line)
            if not timestamp_match:
                continue
            timestamp = timestamp_match.group(1)

            for pattern, handler in PATTERNS:
                match = pattern.search(line)
                if match:
                    handler(match, events, timestamp)

    for event in events:
        block_hash = event.get("hash")
        if block_hash:
            event["detail"] += parentage_suffix(block_hash, parentage)

    return events


# -- print summary stats -----------------------------------------------------

def print_summary(events, label):
    counts = {}
    hashes = set()
    local_count = 0
    peer_count = 0

    for event in events:
        counts[event["type"]] = counts.get(event["type"], 0) + 1
        if "hash" in event:
            hashes.add(event["hash"])
        if event["type"] == "BLOCK_STORE" and event.get("source") == "local":
            local_count += 1
        if event["type"] == "BLOCK_STORE" and event.get("source") == "peer":
            peer_count += 1

    print(f"\n{BOLD}=== Summary: {label} ==={RESET}")
    print(f"  Unique shares seen:   {len(hashes)}")
    print(f"  Locally mined:        {MAGENTA}{local_count}{RESET}")
    print(f"  Received from peers:  {CYAN}{peer_count}{RESET}")
    print(f"  Headers organised:    {counts.get('CANDIDATE_ADD', 0)}")
    print(f"  Confirmed:            {GREEN}{counts.get('CONFIRMED', 0)}{RESET}")
    print(f"  Validation OK:        {GREEN}{counts.get('VALID_OK', 0)}{RESET}")
    print(f"  Validation FAIL:      {RED}{counts.get('VALID_FAIL', 0)}{RESET}")
    print(f"  Reorgs:               {counts.get('REORG', 0)}")
    print(f"  Fetch timeouts:       {RED}{counts.get('FETCH_TIMEOUT', 0)}{RESET}")
    print(f"  NotFound responses:   {RED}{counts.get('NOTFOUND', 0)}{RESET}")
    print(f"  Header chain errors:  {RED}{counts.get('HEADER_ERR', 0)}{RESET}")


# -- strip ANSI escape codes for width calculation ----------------------------

ANSI_ESCAPE_RE = re.compile(r"\033\[[0-9;]*m")


def visible_length(text):
    return len(ANSI_ESCAPE_RE.sub("", text))


def pad_to_width(text, width):
    padding = width - visible_length(text)
    if padding > 0:
        return text + " " * padding
    return text


# -- format a compact event line for column display --------------------------

def compact_event(event):
    event_type = event["type"]

    if event_type == "BLOCK_STORE":
        if event.get("source") == "local":
            tag = f"{MAGENTA}[MINED]{RESET}"
        else:
            tag = f"{CYAN}[RECV]{RESET}"
        detail = event["detail"]
    elif event_type in TAG_STYLES:
        tag, detail_colour = TAG_STYLES[event_type]
        tag = tag.rstrip()
        detail = event["detail"]
        if detail_colour:
            detail = f"{detail_colour}{detail}{RESET}"
    else:
        tag = f"[{event_type}]"
        detail = event["detail"]

    time_short = event["timestamp"][11:23]
    return f"{DIM}{time_short}{RESET} {tag} {detail}"


# -- two-column merged display -----------------------------------------------

def print_two_columns(events_left, events_right, label_left, label_right):
    try:
        terminal_width = os.get_terminal_size().columns
    except OSError:
        terminal_width = 160
    col_width = (terminal_width - 3) // 2
    separator = f"{DIM}|{RESET}"

    header_left = pad_to_width(f"{BOLD}{WHITE} {label_left}{RESET}", col_width)
    header_right = f"{BOLD}{YELLOW} {label_right}{RESET}"
    print(f"\n{header_left} {separator} {header_right}")
    print(f"{DIM}{'-' * col_width} + {'-' * col_width}{RESET}")

    merged = []
    for event in events_left:
        merged.append((event["timestamp"], 0, event))
    for event in events_right:
        merged.append((event["timestamp"], 1, event))
    merged.sort(key=lambda entry: entry[0])

    blank_left = " " * col_width
    for _timestamp, side, event in merged:
        line = compact_event(event)
        if side == 0:
            left_col = pad_to_width(line, col_width)
            print(f"{left_col} {separator}")
        else:
            print(f"{blank_left} {separator} {line}")


# -- main --------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 parse_share_lifecycle.py <logfile> [logfile2 ...]", file=sys.stderr)
        print("  Pass one file to see its lifecycle events.", file=sys.stderr)
        print("  Pass two files to compare nodes in two columns.", file=sys.stderr)
        sys.exit(1)

    for filepath in sys.argv[1:]:
        if not os.path.exists(filepath):
            print(f"File not found: {filepath}", file=sys.stderr)
            sys.exit(1)

    all_events = []
    labels = []
    for filepath in sys.argv[1:]:
        label = os.path.basename(filepath)
        labels.append(label)
        all_events.append(parse_log(filepath))

    node_colours = [WHITE, YELLOW, CYAN, MAGENTA, GREEN]

    for index, (events, label) in enumerate(zip(all_events, labels)):
        print_summary(events, label)

    if len(all_events) == 2:
        print_two_columns(all_events[0], all_events[1], labels[0], labels[1])
    else:
        for index, (events, label) in enumerate(zip(all_events, labels)):
            node_colour = node_colours[index % len(node_colours)]

            print(f"\n{node_colour}{BOLD}{'=' * 80}{RESET}")
            print(f"{node_colour}{BOLD}  NODE: {label}{RESET}")
            print(f"{node_colour}{BOLD}{'=' * 80}{RESET}")

            print(f"\n{BOLD}--- Events ({len(events)} total) ---{RESET}\n")

            for event in events:
                print(colour_event(event))


if __name__ == "__main__":
    main()
