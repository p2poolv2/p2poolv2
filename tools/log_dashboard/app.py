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
