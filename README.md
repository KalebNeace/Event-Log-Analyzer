# Windows Log Analyzer - SIEM (Secruity Information and Event Management)-lite

A cross-language log analysis tool that collects Windows Event Logs via PowerShell,
parses and detects anomalies with Python, correlates events into threat incidents,
and serves a live real-time dashboard over WebSocket.

## Requirements

- Windows 10/11
- PowerShell 5.1+
- Python 3.8+
- pip packages: `flask`, `flask-socketio`

Install dependencies:
```bash
pip install flask flask-socketio
```

## Project Structure

```
log-analyzer/
├── collect.ps1       # PowerShell entry point — collects Event Logs
├── analyze.py        # Log parser and anomaly detection engine
├── correlate.py      # Threat correlation engine — chains events into incidents
├── server.py         # Flask + WebSocket live dashboard server
├── dashboard.html    # Live dashboard frontend (served by server.py)
├── report.py         # Static HTML report generator (standalone)
├── config.json       # User configuration
├── output/           # Generated reports (created automatically)
│   └── YYYY-MM-DD_HH-MM-SS/
│       ├── raw_events.json
│       ├── results.json
│       ├── summary.csv
│       └── report.html
└── README.md
```

## Usage

### Live Dashboard (recommended)

**Step 1** — Collect event data. Run in an elevated PowerShell (Run as Administrator):
```powershell
.\collect.ps1
```

**Step 2** — Start the dashboard server:
```bash
python server.py
```

**Step 3** — Open your browser and navigate to:
```
http://localhost:5000
```

The server automatically finds the latest timestamped output folder, runs a full
analysis + correlation pass on startup, and pushes live updates to the dashboard
every 60 seconds via WebSocket. Use the **Scan Now** button to trigger an
immediate scan at any time.

### Server Options

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `config.json` | Path to config file |
| `--interval` | `60` | Seconds between auto-scans |
| `--port` | `5000` | Port to serve the dashboard on |
| `--no-auto-scan` | off | Disable automatic background scanning |

```bash
python server.py --interval 30
python server.py --port 8080 --no-auto-scan
```

### Static Report (no server)

To generate a one-off HTML report without running the server:
```powershell
.\collect.ps1 -OpenReport
```

Or run the pipeline manually:
```bash
python analyze.py --input output\<timestamp>\raw_events.json --output output\<timestamp> --config config.json
python report.py --output output\<timestamp>
```

## Configuration (config.json)

| Key | Default | Description |
|-----|---------|-------------|
| `log_channels` | System, Application, Security | Windows Event Log channels to collect |
| `hours_back` | 24 | How many hours of logs to collect |
| `max_events_per_channel` | 500 | Cap per channel to keep runtime fast |
| `output_dir` | output | Base folder — timestamped subfolders are created inside |
| `auto_open_report` | true | Auto-open static HTML report after collect.ps1 |
| `anomaly_thresholds.repeated_failures` | 5 | Min errors from one provider to flag |
| `anomaly_thresholds.failed_logon_spike` | 3 | Min failed logons (Event 4625) to flag |
| `correlation.window_minutes` | 15 | Time window for linking related events |
| `correlation.thresholds.rule_brute_force_success` | 3 | Failed logons before brute force fires |
| `correlation.thresholds.rule_lateral_movement` | 3 | Explicit credential logons to flag |
| `correlation.thresholds.rule_system_instability` | 3 | Crash events before instability fires |

## Anomaly Detection Rules

These fire on individual events and are visible in the **Anomaly Detection** panel.

1. **Flagged Event IDs** — Known problematic event IDs (crashes, lockouts, unexpected shutdowns, new services, etc.)
2. **Repeated Failures** — A single provider generating repeated errors within the collection window
3. **Failed Logon Spike** — Multiple Event ID 4625 (failed logon) occurrences from the Security channel

## Threat Correlation Rules

These chain multiple related anomalies together into higher-level incidents and are
visible in the **Threat Incidents** panel. Each maps to a MITRE ATT&CK technique.

| Rule | Severity | Pattern | MITRE |
|------|----------|---------|-------|
| CR-001 | Critical | Failed logons (4625) → successful logon (4624) within window | T1110 — Brute Force |
| CR-002 | Critical | Failed logons (4625) → special privileges assigned (4672) | T1068 — Privilege Escalation |
| CR-003 | High | New service (7045) + new account (4720) within window | T1543.003 — Windows Service Persistence |
| CR-004 | High | Repeated explicit-credential logons (4648) | T1021 — Lateral Movement |
| CR-005 | High | Account created (4720) then locked out (4740) within window | T1098 — Account Manipulation |
| CR-006 | High | Multiple crash/unexpected shutdown events (41, 6008, 1001) | T1499 — Endpoint DoS |

Click any incident row in the dashboard to expand it and see the linked events and MITRE tag.

## Output Files

Each run of `collect.ps1` creates a timestamped subfolder inside `output/`.
The server always reads from the most recently created subfolder automatically.

| File | Description |
|------|-------------|
| `raw_events.json` | Raw events exported from PowerShell |
| `results.json` | Summary + anomalies from Python analysis |
| `summary.csv` | All events in spreadsheet format |
| `report.html` | Static styled HTML report — open in any browser |

## Provider Whitelist

Noisy but benign providers can be suppressed in `config.json` under `provider_whitelist`.
Common candidates:

| Provider | Reason |
|----------|--------|
| `Microsoft-Windows-Diagnostics-Performance` | Boot/app performance metrics |
| `Microsoft-Windows-WindowsUpdateClient` | Update check noise |
| `Microsoft-Windows-WLAN-AutoConfig` | WiFi connection events |
| `Microsoft-Windows-TaskScheduler` | Routine scheduled task completions |
| `Microsoft-Windows-DNS-Client` | High-volume DNS resolution events |
| `Microsoft-Windows-DistributedCOM` | Benign DCOM activation errors |

Do **not** whitelist `Microsoft-Windows-Security-Auditing` (logon events),
`Microsoft-Windows-PowerShell` (execution logging), or `Service Control Manager`
(new service installs) — these are critical for security monitoring.

## Notes

- The **Security** log requires Administrator privileges. If not running as admin it will be skipped with a warning.
- The server does **not** pull new Windows events automatically — re-run `collect.ps1` to refresh the data, then click **Scan Now** or wait for the next auto-scan cycle.
- To continuously refresh data, schedule `collect.ps1` in Windows Task Scheduler to run on an interval alongside the server.