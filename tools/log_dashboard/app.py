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

from flask import Flask, render_template, send_from_directory, request
import os
import json

app = Flask(__name__)

LOG_DIR = os.environ.get("LOG_DIR", "agent_logs")
STATS_FILE = os.environ.get("STATS_FILE", "stats.json")
BACKUP_STATS_FILE = STATS_FILE + ".backup"


def load_stats():
    try:
        with open(STATS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        try:
            with open(BACKUP_STATS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}


@app.route("/", methods=["GET"])
def dashboard():
    query = request.args.get("q", "").lower()
    agents = load_stats()

    if query:
        agents = {ua: info for ua, info in agents.items() if query in ua.lower()}

    return render_template("index.html", agents=agents, query=query)


@app.route("/logs/<path:filename>")
def serve_log(filename):
    safe_dir = os.path.abspath(LOG_DIR)
    requested_file = os.path.abspath(os.path.join(safe_dir, filename))
    if not requested_file.startswith(safe_dir):
        return "Not allowed", 403
    if os.path.isfile(requested_file):
        return send_from_directory(LOG_DIR, filename)
    return "File not found", 404


if __name__ == "__main__":
    app.run(debug=True)
