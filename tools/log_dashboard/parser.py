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
import json
import re
from collections import defaultdict

LOG_FILE = "miners.log"
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

def strip_ip(line):
    return re.sub(r'\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}', '<redacted>', line)

def parse_logs():
    agents = defaultdict(lambda: {
        "submits": 0,
        "status": "🟡 UNKNOWN",
        "logs": [],
        "filename": "",
    })
    ipport_to_ua = {}
    submitid_to_ua = {}

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()

            # Skip lines without JSON indicators or connections close messages
            if "Some(Ok(" not in line and "Tx" not in line and "Connection closed by client" not in line:
                continue

            # Extract IP:port if present for mapping
            ipp_match = re.search(r'(?:Rx|Tx)\s+([\d\.]+:\d+)', line)
            ipport = ipp_match.group(1) if ipp_match else None

            # Handle connection closed to cleanup tracking
            if "Connection closed by client" in line and ipport:
                print(f"[DEBUG] Connection closed, removing mapping for {ipport}")
                ipport_to_ua.pop(ipport, None)
                to_delete = [key for key in submitid_to_ua if key[0] == ipport]
                for key in to_delete:
                    submitid_to_ua.pop(key, None)
                continue

            # Extract all JSON objects inside quoted strings:
            someok_jsons = re.findall(r'Some\(Ok\("(\{.*?\})"\)\)', line)
            if someok_jsons:
                to_parse_jsons = someok_jsons
            else:
                to_parse_jsons = re.findall(r'\"(\{.*?\})\"', line)

            if not to_parse_jsons:
                # No JSON found, skip
                continue

            for raw_json in to_parse_jsons:
                raw_json = raw_json.replace('\\"', '"')
                try:
                    msg = json.loads(raw_json)
                    method = msg.get("method")
                    is_rx = "Some(Ok(" in line

                    print(f"[DEBUG] Processing msg from line: {line}")
                    print(f"[DEBUG] IP:port: {ipport}")
                    print(f"[DEBUG] Method: {method}")

                    # mining.subscribe: map IP:port -> UA
                    if method == "mining.subscribe":
                        ua = msg["params"][0]
                        agents[ua]["filename"] = ua.replace("/", "_").replace(" ", "_") + ".log"
                        if ipport:
                            ipport_to_ua[ipport] = ua
                            print(f"[DEBUG] Mapping {ipport} to UA {ua}")
                        agents[ua]["logs"].append(strip_ip(line))

                    # mining.submit: track submit id -> UA mapping per connection
                    elif method == "mining.submit":
                        submit_id = msg.get("id")
                        if ipport and ipport in ipport_to_ua:
                            ua = ipport_to_ua[ipport]
                            agents[ua]["submits"] += 1
                            if submit_id is not None:
                                submitid_to_ua[(ipport, submit_id)] = ua
                                print(f"[DEBUG] Added submit id {submit_id} for UA {ua} on {ipport}")
                            agents[ua]["logs"].append(strip_ip(line))
                        else:
                            print(f"[DEBUG] mining.submit without known UA for IP:port {ipport}")

                    # Tx response with result:true: check if matches a submit
                    elif not is_rx and "result" in msg and msg["result"] is True:
                        tx_id = msg.get("id")
                        if ipport and tx_id is not None:
                            ua = submitid_to_ua.get((ipport, tx_id))
                            print(f"[DEBUG] Tx result=true with id={tx_id} associated UA={ua}")
                            if ua:
                                agents[ua]["status"] = "🟢 ACTIVE"
                                agents[ua]["logs"].append(strip_ip(line))
                                submitid_to_ua.pop((ipport, tx_id), None)  # Remove mapping after success
                            else:
                                print(f"[DEBUG] No matching UA found for Tx id={tx_id} at {ipport}")
                        else:
                            print(f"[DEBUG] Tx response missing id or ipport")

                    # Append other lines if UA known
                    else:
                        if ipport and ipport in ipport_to_ua:
                            ua = ipport_to_ua[ipport]
                            agents[ua]["logs"].append(strip_ip(line))

                    print("---")

                except json.JSONDecodeError as e:
                    print(f"[ERROR] JSON parse error: {e} at line: {line}")
                    continue

    except FileNotFoundError:
        print("[ERROR] miners.log not found.")
        return {}

    return agents

def save_agent_logs(agents):
    for ua, info in agents.items():
        if not info["filename"]:
            continue
        filepath = os.path.join(LOG_DIR, info["filename"])
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(info["logs"]))

# Run if executed as main script
if __name__ == "__main__":
    agents = parse_logs()
    save_agent_logs(agents)
    for ua, info in agents.items():
        print(f"User Agent: {ua}, Status: {info['status']}, Submits: {info['submits']}")
