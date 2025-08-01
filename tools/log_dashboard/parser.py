#!/usr/bin/env python3
# Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)

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
from collections import defaultdict
from datetime import datetime

LAST_TS_FILE = "last_processed.txt"

def strip_ip(line: str) -> str:
    return re.sub(r'\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}', '<redacted>', line)

def open_logfile(filepath: str):
    if filepath.endswith('.gz'):
        return gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore')
    return open(filepath, 'r', encoding='utf-8', errors='ignore')

def sort_key(fname):
    base = os.path.basename(fname)
    m = re.search(r'p2pool-(\d{4}-\d{2}-\d{2})', base)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y-%m-%d")
        except ValueError:
            pass
    return datetime.min

def parse_all_logs(log_dir: str, log_pattern="p2pool-*.log*") -> list:
    files = [f for f in glob.glob(os.path.join(log_dir, log_pattern)) if os.path.isfile(f)]
    files.sort(key=sort_key)
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
    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2)
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
    agents = defaultdict(lambda: {
        "submits": 0,
        "successes": 0,
        "failures": 0,
        "status": "🟡 PENDING SUBMIT",
        "logs": [],
        "filename": "",
    })

    # Preserve only filename from old_agents, DO NOT preload old logs to avoid mixed logs
    for ua, info in old_agents.items():
        agents[ua]["filename"] = info.get("filename", "")

    ipport_to_ua = {}
    submitid_to_ua = {}
    latest_ts = last_processed

    for line in lines:
        line = line.strip()
        ts_match = re.search(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
        if not ts_match:
            continue
        try:
            line_ts = datetime.fromisoformat(ts_match.group(1))
        except ValueError:
            continue
        if line_ts <= last_processed:
            continue
        if line_ts > latest_ts:
            latest_ts = line_ts

        is_rx = "Rx" in line
        is_tx = "Tx" in line

        ipp_match = re.search(r'(?:Rx|Tx)\s+([\d\.]+:\d+)', line)
        ipport = ipp_match.group(1) if ipp_match else None

        if re.search(r'New connection from:\s*([\d\.]+:\d+)', line):
            continue

        if "Connection closed by client" in line:
            disc_match = re.search(r'Connection closed by client\s+([\d\.]+:\d+)', line)
            if disc_match:
                disc_ipport = disc_match.group(1)
                ua = ipport_to_ua.get(disc_ipport)
                if ua:
                    agents[ua]["status"] = "🔵 DISCONNECTED"
                    redacted = strip_ip(line)
                    if redacted not in agents[ua]["logs"]:
                        agents[ua]["logs"].append(redacted)
                ipport_to_ua.pop(disc_ipport, None)
                keys_to_remove = [key for key in submitid_to_ua if key[0] == disc_ipport]
                for key in keys_to_remove:
                    submitid_to_ua.pop(key, None)
            continue

        someok_jsons = re.findall(r'Some\(Ok\("(\{.*?\})"\)\)', line)
        to_parse_jsons = someok_jsons if someok_jsons else re.findall(r'\"(\{.*?\})\"', line)
        if not to_parse_jsons:
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
                    # malformed mining.subscribe, skip
                    continue
                ua = params[0]
                agents[ua]["filename"] = ua.replace("/", "_").replace(" ", "_") + ".log"
                if ipport:
                    ipport_to_ua[ipport] = ua
                if ua not in agents:
                    agents[ua]["submits"] = 0
                redacted = strip_ip(line)
                if redacted not in agents[ua]["logs"]:
                    agents[ua]["logs"].append(redacted)

            elif method == "mining.submit":
                if ipport and ipport in ipport_to_ua:
                    ua = ipport_to_ua[ipport]
                    submit_id = msg.get("id")
                    agents[ua]["submits"] += 1
                    if submit_id is not None:
                        submitid_to_ua[(ipport, submit_id)] = ua
                    redacted = strip_ip(line)
                    if redacted not in agents[ua]["logs"]:
                        agents[ua]["logs"].append(redacted)

            elif is_tx and "result" in msg:
                tx_id = msg.get("id")
                if ipport and tx_id is not None:
                    ua = submitid_to_ua.get((ipport, tx_id))
                    if ua:
                        if msg["result"] is True:
                            agents[ua]["successes"] += 1
                        elif msg["result"] is False:
                            agents[ua]["failures"] += 1

                        redacted = strip_ip(line)
                        if redacted not in agents[ua]["logs"]:
                            agents[ua]["logs"].append(redacted)

                        submitid_to_ua.pop((ipport, tx_id), None)

            else:
                if ipport and ipport in ipport_to_ua:
                    ua = ipport_to_ua[ipport]
                    redacted = strip_ip(line)
                    if redacted not in agents[ua]["logs"]:
                        agents[ua]["logs"].append(redacted)

    for ua, info in agents.items():
        if info["status"] == "🔵 DISCONNECTED":
            continue
        elif info["successes"] > 0:
            info["status"] = "🟢 ACTIVE"
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

    for ua, info in old_agents.items():
        if ua not in new_agents:
            new_agents[ua] = info

    atomic_write_stats(new_agents, args.outfile)
    save_last_processed_time(latest_ts)

    agent_logs_dir = "agent_logs"
    os.makedirs(agent_logs_dir, exist_ok=True)

    for ua, info in new_agents.items():
        fname = info.get("filename", "")
        if not fname:
            continue
        safe_fname = fname.replace("/", "_").replace(" ", "_")
        filepath = os.path.join(agent_logs_dir, safe_fname)
        unique_logs = list(dict.fromkeys(info.get("logs", [])))  # remove duplicates
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("\n".join(unique_logs))

if __name__ == "__main__":
    main()
