"""
server.py - SIEM-lite Live Dashboard Server
Flask + Flask-SocketIO backend that runs log analysis on a schedule
and pushes results to connected clients via WebSocket.

Requirements:
    pip install flask flask-socketio

Usage:
    python server.py
    python server.py --config path/to/config.json
    python server.py --interval 30   # scan every 30 seconds
"""

import argparse
import json
import os
import sys
import threading
import time
from datetime import datetime

from flask import Flask, jsonify
from flask_socketio import SocketIO, emit

# ── Import analysis + correlation modules ─────────────────────
sys.path.insert(0, os.path.dirname(__file__))
from analyze import load_config, load_events, summarize, detect_anomalies
from correlate import correlate

# ── App Setup ─────────────────────────────────────────────────
app = Flask(__name__, static_folder="dashboard/static")
app.config["SECRET_KEY"] = "siem-lite-dev-key"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Global State ──────────────────────────────────────────────
_state = {
    "last_scan":  None,
    "summary":    {},
    "anomalies":  [],
    "incidents":  [],   # ← correlated threat incidents
    "scan_count": 0,
    "status":     "idle",
    "error":      None,
}
_state_lock   = threading.Lock()
_config       = {}
_scan_interval = 60


# ── Output Directory Resolution ───────────────────────────────

def get_latest_output_dir(base_dir: str) -> str:
    """
    Return the most recently modified subdirectory inside base_dir.
    Falls back to base_dir itself if no subdirectories exist.
    This handles collect.ps1 creating timestamped subfolders like
    output/2026-03-30_22-25-00/
    """
    if not os.path.exists(base_dir):
        raise FileNotFoundError(
            f"Base output directory not found: '{base_dir}'. "
            "Run collect.ps1 first."
        )
    subdirs = [
        os.path.join(base_dir, d) for d in os.listdir(base_dir)
        if os.path.isdir(os.path.join(base_dir, d))
    ]
    if not subdirs:
        return base_dir
    latest = max(subdirs, key=os.path.getmtime)
    print(f"[*] Using output folder: {latest}")
    return latest


# ── Core Scan Logic ───────────────────────────────────────────

def run_scan() -> dict:
    """
    Run a full log analysis + correlation pass.
    Automatically finds the latest timestamped output subfolder.
    """
    base_dir   = _config.get("output_dir", "output")
    output_dir = get_latest_output_dir(base_dir)
    raw_path   = os.path.join(output_dir, "raw_events.json")

    if not os.path.exists(raw_path):
        raise FileNotFoundError(
            f"raw_events.json not found in '{output_dir}'. "
            "Run collect.ps1 first to generate event data."
        )

    whitelist = _config.get("provider_whitelist", [])
    events    = load_events(raw_path, whitelist)
    summary   = summarize(events)
    anomalies = detect_anomalies(events, _config)
    incidents = correlate(events, _config)          # ← NEW

    return {
        "summary":   summary,
        "anomalies": anomalies,
        "incidents": incidents,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def perform_scan(triggered_by: str = "auto"):
    """
    Execute a scan, update global state, push result to all clients.
    Safe to call from any thread.
    """
    print(f"[*] Scan triggered ({triggered_by}) at {datetime.now().strftime('%H:%M:%S')}")

    with _state_lock:
        _state["status"] = "scanning"
        _state["error"]  = None

    socketio.emit("scan_started", {
        "triggered_by": triggered_by,
        "time": datetime.now().isoformat(),
    })

    try:
        result = run_scan()

        with _state_lock:
            _state["last_scan"]  = result["scan_time"]
            _state["summary"]    = result["summary"]
            _state["anomalies"]  = result["anomalies"]
            _state["incidents"]  = result["incidents"]
            _state["scan_count"] += 1
            _state["status"]     = "idle"

        payload = {
            "scan_time":  result["scan_time"],
            "scan_count": _state["scan_count"],
            "summary":    result["summary"],
            "anomalies":  result["anomalies"],
            "incidents":  result["incidents"],
        }

        socketio.emit("scan_complete", payload)
        print(
            f"[+] Scan complete — {result['summary'].get('total_events', 0)} events, "
            f"{len(result['anomalies'])} anomalies, "
            f"{len(result['incidents'])} incidents"
        )

    except Exception as exc:
        error_msg = str(exc)
        print(f"[!] Scan error: {error_msg}")

        with _state_lock:
            _state["status"] = "error"
            _state["error"]  = error_msg

        socketio.emit("scan_error", {
            "error": error_msg,
            "time":  datetime.now().isoformat(),
        })


def background_scanner():
    """Background thread: scan every _scan_interval seconds."""
    time.sleep(3)
    while True:
        perform_scan(triggered_by="auto")
        time.sleep(_scan_interval)


# ── REST API ──────────────────────────────────────────────────

@app.route("/")
def index():
    dashboard_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    if os.path.exists(dashboard_path):
        with open(dashboard_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h2>dashboard.html not found</h2>", 404


@app.route("/api/status")
def api_status():
    with _state_lock:
        return jsonify({
            "status":                 _state["status"],
            "last_scan":              _state["last_scan"],
            "scan_count":             _state["scan_count"],
            "error":                  _state["error"],
            "scan_interval_seconds":  _scan_interval,
        })


@app.route("/api/summary")
def api_summary():
    with _state_lock:
        return jsonify(_state["summary"])


@app.route("/api/anomalies")
def api_anomalies():
    with _state_lock:
        return jsonify(_state["anomalies"])


@app.route("/api/incidents")
def api_incidents():
    with _state_lock:
        return jsonify(_state["incidents"])


@app.route("/api/scan", methods=["POST"])
def api_scan():
    thread = threading.Thread(
        target=perform_scan, kwargs={"triggered_by": "manual"}, daemon=True
    )
    thread.start()
    return jsonify({"queued": True, "time": datetime.now().isoformat()})


# ── WebSocket Events ──────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    print("[+] Client connected")
    with _state_lock:
        emit("scan_complete", {
            "scan_time":  _state["last_scan"] or "No scan yet",
            "scan_count": _state["scan_count"],
            "summary":    _state["summary"],
            "anomalies":  _state["anomalies"],
            "incidents":  _state["incidents"],
        })
        if _state["status"] == "error":
            emit("scan_error", {"error": _state["error"]})


@socketio.on("disconnect")
def on_disconnect():
    print("[-] Client disconnected")


@socketio.on("request_scan")
def on_request_scan():
    thread = threading.Thread(
        target=perform_scan, kwargs={"triggered_by": "client-request"}, daemon=True
    )
    thread.start()


# ── Entry Point ───────────────────────────────────────────────

def main():
    global _config, _scan_interval

    parser = argparse.ArgumentParser(description="SIEM-lite Dashboard Server")
    parser.add_argument("--config",       default="config.json")
    parser.add_argument("--interval",     type=int, default=60)
    parser.add_argument("--port",         type=int, default=5000)
    parser.add_argument("--no-auto-scan", action="store_true")
    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f"[!] Config not found: {args.config}")
        sys.exit(1)

    _config        = load_config(args.config)
    _scan_interval = args.interval

    print(f"[*] SIEM-lite Dashboard Server")
    print(f"[*] Config:    {os.path.abspath(args.config)}")
    print(f"[*] Interval:  {_scan_interval}s")
    print(f"[*] Dashboard: http://localhost:{args.port}")
    print()

    if not args.no_auto_scan:
        t = threading.Thread(target=background_scanner, daemon=True)
        t.start()
        print("[*] Background scanner started")

    socketio.run(app, host="127.0.0.1", port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()