#!/usr/bin/env python3
# Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)

# This file is part of P2Poolv2

# P2Poolv2 is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.

# P2Poolv2 is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along with
# P2Poolv2. If not, see <https://www.gnu.org/licenses/>.

import os
import re
import json
import glob
import gzip
import shutil
from collections import defaultdict, deque
from datetime import datetime, timezone

LAST_TS_FILE = "last_processed.txt"

def strip_ip(line: str) -> str:
    return re.sub(r'\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}', '<hidden>', line)

def open_logfile(filepath: str):
    if filepath.endswith('.gz'):
        return gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore')
    return open(filepath, 'r', encoding='utf-8', errors='ignore')

def parse_all_logs(log_dir: str, log_pattern) -> list:
    def sort_key(fname):
        base = os.path.basename(fname)
        regexp = f"{log_pattern}.(\\d{{4}}-\\d{{2}}-\\d{{2}})"
        m = re.search(regexp, base)
        if m:
            try:
                return datetime.strptime(m.group(1), "%Y-%m-%d")
            except ValueError:
                pass
        return datetime.min

    files = [f for f in glob.glob(os.path.join(log_dir, log_pattern + "*")) if os.path.isfile(f)]
    files.sort(key=sort_key)
    print(f"Processing files: {files}")
    all_lines = []
    for fname in files:
        with open_logfile(fname) as f:
            all_lines.extend(f.readlines())
    return all_lines

def load_existing_stats(stats_path: str) -> dict:
    try:
        with open(stats_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        backup_path = stats_path + ".backup"
        try:
            with open(backup_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}

def atomic_write_stats(stats: dict, stats_path='stats.json'):
    tmp_path = stats_path + '.new'
    backup_path = stats_path + '.backup'

    # Convert sets and deques for json serialization
    serializable_stats = {}
    for ua, info in stats.items():
        si = info.copy()
        if isinstance(si.get("usernames"), (set,)):
            si["usernames"] = list(si["usernames"])
        if isinstance(si.get("last_session_logs"), (deque,)):
            si["last_session_logs"] = list(si["last_session_logs"])
        serializable_stats[ua] = si

    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump(serializable_stats, f, indent=2)

    if os.path.exists(stats_path):
        shutil.copy2(stats_path, backup_path)
    os.replace(tmp_path, stats_path)

def load_last_processed_time():
    if os.path.exists(LAST_TS_FILE):
        with open(LAST_TS_FILE, 'r') as f:
            try:
                return datetime.fromisoformat(f.read().strip())
            except Exception:
                pass
    return datetime.min

def save_last_processed_time(ts: datetime):
    with open(LAST_TS_FILE, 'w') as f:
        f.write(ts.isoformat())

def process_log_lines(lines: list, old_agents: dict, last_processed: datetime) -> tuple[dict, datetime]:
    # Agents data: Store usernames, status, filename, last session's last 25 log lines
    agents = defaultdict(lambda: {
        "submits": 0,
        "successes": 0,
        "failures": 0,
        "status": "🟡 PENDING SUBMIT",
        "last_session_logs": deque(maxlen=25),
        "filename": "",
        "usernames": set(),
    })

    # Restore old data if exists for agents
    for ua, info in old_agents.items():
        agents[ua]["filename"] = info.get("filename", "")
        agents[ua]["submits"] = info.get("submits", 0)
        agents[ua]["successes"] = info.get("successes", 0)
        agents[ua]["failures"] = info.get("failures", 0)
        agents[ua]["status"] = info.get("status", "🟡 PENDING SUBMIT")
        if "usernames" in info:
            agents[ua]["usernames"] = set(info["usernames"])
        if "last_session_logs" in info:
            agents[ua]["last_session_logs"] = deque(info["last_session_logs"], maxlen=25)

    ipport_to_ua = {}
    submitid_to_ua = {}

    # Track sessions per ua: current session lines for each ua
    session_lines = defaultdict(lambda: deque(maxlen=25))
    # Track disconnected status per ua
    disconnected_agents = set()

    def finalize_session(ua):
        if ua in session_lines:
            agents[ua]["last_session_logs"] = session_lines[ua].copy()
            session_lines[ua].clear()
        disconnected_agents.add(ua)
        agents[ua]["status"] = "🔵 DISCONNECTED"

    for line in lines:
        line_strip = line.strip()
        ts_match = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line_strip)
        if not ts_match:
            continue
        try:
            line_ts = datetime.fromisoformat(ts_match.group(1))
        except ValueError:
            continue
        latest_ts = line_ts

        is_rx = "Rx" in line_strip
        is_tx = "Tx" in line_strip

        ipp_match = re.search(r'(?:Rx|Tx)\s+([\d\.]+:\d+)', line_strip)
        ipport = ipp_match.group(1) if ipp_match else None

        # Detect new connection (start of new session)
        new_conn_match = re.search(r'New connection from:\s*([\d\.]+:\d+)', line_strip)
        if new_conn_match:
            # This is a new connection - possibly assigned later to ua upon mining.subscribe
            continue

        # Detect disconnect event - finalize session
        if "Connection closed by client" in line_strip:
            disc_match = re.search(r'Connection closed by client\s+([\d\.]+:\d+)', line_strip)
            if disc_match:
                disc_ipport = disc_match.group(1)
                ua = ipport_to_ua.get(disc_ipport)
                if ua:
                    finalize_session(ua)
                # Clean up mappings
                ipport_to_ua.pop(disc_ipport, None)
                keys_to_remove = [key for key in submitid_to_ua if key[0] == disc_ipport]
                for key in keys_to_remove:
                    submitid_to_ua.pop(key, None)
            continue

        # Find JSON messages within the line
        someok_jsons = re.findall(r'Some\(Ok\("(\{.*?\})"\)\)', line_strip)
        to_parse_jsons = someok_jsons if someok_jsons else re.findall(r'\"(\{.*?\})\"', line_strip)
        if not to_parse_jsons:
            # For non-json, try associate log line to ua from ipport_to_ua
            if ipport and ipport in ipport_to_ua:
                ua = ipport_to_ua[ipport]
                hidden = strip_ip(line_strip)
                session_lines[ua].append(hidden)
            continue

        for raw_json in to_parse_jsons:
            raw_json = raw_json.replace('\\"', '"')
            try:
                msg = json.loads(raw_json)
            except json.JSONDecodeError:
                continue

            method = msg.get("method")
            ua = None

            if method == "mining.subscribe":
                params = msg.get("params")
                if not params or not isinstance(params, list) or len(params) == 0:
                    continue
                ua = params[0]
                agents[ua]["filename"] = ua.replace("/", "_").replace(" ", "_") + ".log"
                if ipport:
                    ipport_to_ua[ipport] = ua

                # Reset session lines if reconnecting fresh session
                session_lines[ua].clear()
                disconnected_agents.discard(ua)
                
                hidden = strip_ip(line_strip)
                session_lines[ua].append(hidden)

            elif method == "mining.submit":
                # Skip submit lines if already processed
                if line_ts <= last_processed:
                    continue
                if ipport and ipport in ipport_to_ua:
                    ua = ipport_to_ua[ipport]
                    submit_id = msg.get("id")
                    agents[ua]["submits"] += 1
                    if submit_id is not None:
                        submitid_to_ua[(ipport, submit_id)] = ua
                    hidden = strip_ip(line_strip)
                    session_lines[ua].append(hidden)
                    params = msg.get("params", [])
                    if len(params) > 0:
                        workername = params[0]
                        if workername:
                            agents[ua]["usernames"].add(workername)

            elif method == "mining.authorize":
                params = msg.get("params", [])
                if len(params) > 0 and ipport and ipport in ipport_to_ua:
                    ua = ipport_to_ua[ipport]
                    username = params[0]
                    if username:
                        agents[ua]["usernames"].add(username)

            elif is_tx and "result" in msg:
                # Skip result lines if already processed
                if line_ts <= last_processed:
                    continue
                tx_id = msg.get("id")
                if ipport and tx_id is not None:
                    ua = submitid_to_ua.get((ipport, tx_id))
                    if ua:
                        if msg["result"] is True:
                            agents[ua]["successes"] += 1
                        elif msg["result"] is False:
                            agents[ua]["failures"] += 1

                        hidden = strip_ip(line_strip)
                        session_lines[ua].append(hidden)

                        submitid_to_ua.pop((ipport, tx_id), None)

            else:
                # Fallback: assign line by ipport if available
                if ipport and ipport in ipport_to_ua:
                    ua = ipport_to_ua[ipport]
                    hidden = strip_ip(line_strip)
                    session_lines[ua].append(hidden)

    # Finalize sessions for agents not disconnected yet (they have active sessions)
    for ua in session_lines.keys():
        if ua not in disconnected_agents:
            agents[ua]["last_session_logs"] = session_lines[ua].copy()
        else:
            # Session already finalized at disconnection
            pass

    # Now update statuses; never demote an agent from green 🟢 ACTIVE
    for ua, info in agents.items():
        if info["status"] == "🔵 DISCONNECTED":
            continue
        # If old agent was green, keep green
        if old_agents.get(ua, {}).get("status") == "🟢 PASS" or info.get("status") == "🟢 PASS":
            info["status"] = "🟢 PASS"
        elif info["successes"] > 0:
            info["status"] = "🟢 PASS"
        elif info["failures"] > 0:
            info["status"] = "🔴 FAIL"
        elif info["submits"] > 0:
            info["status"] = "🟡 PENDING SUBMIT"
        else:
            info["status"] = "🟡 PENDING SUBMIT"

    return agents, latest_ts

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Update mining stats from logs.")
    parser.add_argument("-d", "--logdir", default="logs", help="Directory containing log files")
    parser.add_argument("-l", "--logpattern", default="p2pool-*.log*", help="Log file glob pattern")
    parser.add_argument("-o", "--outfile", default="stats.json", help="Output JSON filename")
    args = parser.parse_args()

    if not os.path.isdir(args.logdir):
        print(f"Error: Log directory '{args.logdir}' does not exist.")
        exit(1)

    old_agents = load_existing_stats(args.outfile)
    lines = parse_all_logs(args.logdir, args.logpattern)
    last_processed = load_last_processed_time()

    new_agents, latest_ts = process_log_lines(lines, old_agents, last_processed)

    # Carry over any old agents not seen in new parsing (with their prior data)
    for ua, info in old_agents.items():
        if ua not in new_agents:
            info["last_session_logs"] = deque(info.get("last_session_logs", []), maxlen=25)
            info["usernames"] = set(info.get("usernames", []))
            new_agents[ua] = info

    atomic_write_stats(new_agents, args.outfile)
    save_last_processed_time(latest_ts)

if __name__ == "__main__":
    main()

