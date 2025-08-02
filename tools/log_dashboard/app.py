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

from flask import Flask, jsonify, Response, abort, render_template, send_from_directory, request
import json
import os
import glob
import gzip

app = Flask(__name__)
STATS_FILE = "stats.json"
LOGS_DIR = "logs"
LOG_GLOB = "p2pool-*.log*"


def load_stats_json():
    try:
        with open(STATS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


@app.route("/api/agent_logs/<path:ua>")
def agent_logs(ua):
    stats = load_stats_json()
    if ua not in stats:
        return jsonify({"error": "User agent not found"}), 404
    return jsonify(stats[ua].get("last_session_logs", []))


@app.route("/api/agent_usernames/<path:ua>")
def agent_usernames(ua):
    stats = load_stats_json()
    if ua not in stats:
        return jsonify({"error": "User agent not found"}), 404
    return jsonify(stats[ua].get("usernames", []))


def read_all_logs():
    pattern = os.path.join(LOGS_DIR, LOG_GLOB)
    files = sorted(glob.glob(pattern))

    lines = []
    for fname in files:
        if fname.endswith(".gz"):
            with gzip.open(fname, 'rt', encoding='utf-8', errors='ignore') as f:
                lines.extend(f.readlines())
        else:
            with open(fname, 'r', encoding='utf-8', errors='ignore') as f:
                lines.extend(f.readlines())
    return "".join(lines)


@app.route("/api/full_raw_logs")
def full_raw_logs():
    full_log_data = read_all_logs()
    return Response(full_log_data, mimetype='text/plain')


@app.route("/logs/<path:filename>")
def serve_log(filename):
    if ".." in filename or filename.startswith("/"):
        abort(400, "Invalid filename")
    return send_from_directory(LOGS_DIR, filename)

@app.route("/logs/download_last_session/<path:ua>")
def download_last_session_log(ua):
    stats = load_stats_json()
    if ua not in stats:
        abort(404, "User agent not found")
    logs = stats[ua].get("last_session_logs", [])
    content = "\n".join(logs)
    filename = f"{ua.replace('/', '_')}_last_session.log"
    return Response(
        content,
        mimetype="text/plain",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )

@app.route("/")
def index():
    stats = load_stats_json()
    query = request.args.get("q", "").strip().lower()
    if query:
        agents = {ua: info for ua, info in stats.items() if query in ua.lower()}
    else:
        agents = stats

    return render_template("index.html", agents=agents, query=query)


if __name__ == "__main__":
    app.run(port=5000, debug=True)
