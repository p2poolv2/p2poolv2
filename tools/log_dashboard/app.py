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

from flask import Flask, render_template, send_from_directory, request, redirect, url_for
from parser import parse_logs, save_agent_logs
import os

app = Flask(__name__)
LOG_DIR = "logs"

@app.route("/", methods=["GET"])
def dashboard():
    query = request.args.get("q", "").lower()
    agents = parse_logs()
    save_agent_logs(agents)

    if query:
        agents = {ua: info for ua, info in agents.items() if query in ua.lower()}

    return render_template("index.html", agents=agents, query=query)

@app.route("/refresh", methods=["POST"])
def refresh():
    return redirect(url_for('dashboard'))

@app.route("/logs/<path:filename>")
def serve_log(filename):
    return send_from_directory(LOG_DIR, filename)

if __name__ == "__main__":
    app.run(debug=True)
