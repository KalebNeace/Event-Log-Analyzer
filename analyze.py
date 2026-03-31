"""
analyze.py - Log Analysis Engine
Parses raw Windows Event Log data, detects anomalies, and outputs
structured JSON + CSV results.
"""

import argparse
import json
import csv
import os
import sys
from datetime import datetime
from collections import defaultdict, Counter


# ── Anomaly Detection Rules ───────────────────────────────────

# Event IDs commonly associated with security or system issues
FLAGGED_EVENT_IDS = {
    # Security
    4625: "Failed logon attempt",
    4648: "Logon with explicit credentials",
    4672: "Special privileges assigned to new logon",
    4720: "User account created",
    4726: "User account deleted",
    4740: "User account locked out",
    # System
    41:   "Kernel power loss / unexpected shutdown",
    1001: "Windows Error Reporting / crash",
    6008: "Unexpected shutdown",
    7034: "Service crashed unexpectedly",
    7036: "Service state change",
    7045: "New service installed",
}

SEVERITY_ORDER = {"Critical": 0, "Error": 1, "Warning": 2, "Information": 3, "Verbose": 4}


def load_config(config_path: str) -> dict:
    with open(config_path, "r") as f:
        return json.load(f)


def load_events(input_path: str, whitelist: list = None) -> list:
    with open(input_path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)
    # PowerShell may export a single object instead of a list
    if isinstance(data, dict):
        data = [data]
    # Filter out whitelisted providers
    if whitelist:
        before = len(data)
        data = [e for e in data if e.get("ProviderName") not in whitelist]
        filtered = before - len(data)
        if filtered:
            print(f"[*] Whitelist suppressed {filtered} events from noisy providers")
    return data


def classify_severity(level: str) -> str:
    """Normalize various level strings to consistent severity labels."""
    level = (level or "").strip().lower()
    if level in ("critical",):
        return "Critical"
    if level in ("error",):
        return "Error"
    if level in ("warning", "warn"):
        return "Warning"
    if level in ("information", "info", "verbose", "audit success", "audit failure"):
        return "Information"
    return "Information"


def detect_anomalies(events: list, config: dict) -> list:
    """
    Run anomaly detection rules against the event list.
    Returns a list of anomaly dicts.
    """
    anomalies = []
    thresholds = config.get("anomaly_thresholds", {})

    # ── Rule 1: Flagged Event IDs ─────────────────────────────
    for event in events:
        eid = int(event.get("EventId", 0))
        if eid in FLAGGED_EVENT_IDS:
            anomalies.append({
                "type": "Flagged Event ID",
                "severity": "High" if classify_severity(event.get("Level", "")) in ("Critical", "Error") else "Medium",
                "event_id": eid,
                "channel": event.get("Channel"),
                "time": event.get("TimeCreated"),
                "provider": event.get("ProviderName"),
                "description": FLAGGED_EVENT_IDS[eid],
                "message_preview": event.get("Message", "")[:200],
            })

    # ── Rule 2: Repeated failures within timeframe ────────────
    failure_threshold = thresholds.get("repeated_failures", 5)
    failure_counts = Counter()
    for event in events:
        level = classify_severity(event.get("Level", ""))
        if level in ("Critical", "Error"):
            key = (event.get("Channel"), event.get("ProviderName"))
            failure_counts[key] += 1

    for (channel, provider), count in failure_counts.items():
        if count >= failure_threshold:
            anomalies.append({
                "type": "Repeated Failures",
                "severity": "High",
                "event_id": None,
                "channel": channel,
                "time": None,
                "provider": provider,
                "description": f"{count} errors/criticals from '{provider}' in '{channel}'",
                "message_preview": "",
            })

    # ── Rule 3: Failed logon spike (Event ID 4625) ────────────
    # Only count 4625 from the Security channel - Application channel
    # uses this ID for unrelated COM event suppression notifications
    logon_threshold = thresholds.get("failed_logon_spike", 3)
    failed_logons = [e for e in events if int(e.get("EventId", 0)) == 4625
                     and e.get("Channel") == "Security"]
    if len(failed_logons) >= logon_threshold:
        anomalies.append({
            "type": "Failed Logon Spike",
            "severity": "Critical",
            "event_id": 4625,
            "channel": "Security",
            "time": failed_logons[0].get("TimeCreated"),
            "provider": "Microsoft-Windows-Security-Auditing",
            "description": f"{len(failed_logons)} failed logon attempts detected",
            "message_preview": "",
        })

    return anomalies


def summarize(events: list) -> dict:
    """Build a summary dict from the event list."""
    severity_counts = defaultdict(int)
    channel_counts = defaultdict(int)
    provider_counts = defaultdict(int)
    top_event_ids = Counter()

    for event in events:
        severity = classify_severity(event.get("Level", ""))
        severity_counts[severity] += 1
        channel_counts[event.get("Channel", "Unknown")] += 1
        provider_counts[event.get("ProviderName", "Unknown")] += 1
        top_event_ids[int(event.get("EventId", 0))] += 1

    return {
        "total_events": len(events),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severity_breakdown": dict(severity_counts),
        "channel_breakdown": dict(channel_counts),
        "top_providers": dict(Counter(provider_counts).most_common(10)),
        "top_event_ids": [
            {"event_id": eid, "count": count}
            for eid, count in top_event_ids.most_common(10)
        ],
    }


def export_csv(events: list, output_dir: str):
    """Write all events to a CSV file."""
    path = os.path.join(output_dir, "summary.csv")
    fieldnames = ["TimeCreated", "Channel", "Level", "EventId", "ProviderName", "Message"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        # Sort by time descending
        sorted_events = sorted(events, key=lambda e: e.get("TimeCreated", ""), reverse=True)
        writer.writerows(sorted_events)
    print(f"[+] CSV exported: {path}")


def export_json(summary: dict, anomalies: list, output_dir: str):
    """Write results.json with summary + anomalies."""
    path = os.path.join(output_dir, "results.json")
    results = {
        "summary": summary,
        "anomalies": anomalies,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"[+] JSON results exported: {path}")


def main():
    parser = argparse.ArgumentParser(description="Log Analysis Engine")
    parser.add_argument("--input", required=True, help="Path to raw_events.json")
    parser.add_argument("--output", required=True, help="Output directory")
    parser.add_argument("--config", required=True, help="Path to config.json")
    args = parser.parse_args()

    print("[*] Loading configuration...")
    config = load_config(args.config)
    whitelist = config.get("provider_whitelist", [])

    print("[*] Loading raw events...")
    events = load_events(args.input, whitelist)
    print(f"[*] Analyzing {len(events)} events...")

    summary = summarize(events)

    print("[*] Running anomaly detection...")
    anomalies = detect_anomalies(events, config)
    print(f"[+] Detected {len(anomalies)} anomalies")

    # Print severity breakdown to console
    print("\n--- Severity Breakdown ---")
    for sev, count in sorted(summary["severity_breakdown"].items(),
                              key=lambda x: SEVERITY_ORDER.get(x[0], 99)):
        print(f"    {sev:<15} {count}")
    print()

    export_csv(events, args.output)
    export_json(summary, anomalies, args.output)

    print("[+] Analysis complete.")


if __name__ == "__main__":
    main()