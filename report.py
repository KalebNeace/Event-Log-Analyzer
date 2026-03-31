"""
report.py - HTML Report Generator
Reads results.json and summary.csv to produce a styled HTML report.
"""

import argparse
import json
import os
from datetime import datetime


def load_results(output_dir: str) -> dict:
    path = os.path.join(output_dir, "results.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def severity_badge(sev: str) -> str:
    colors = {
        "Critical": ("#ff4444", "#fff"),
        "Error":    ("#ff8c00", "#fff"),
        "Warning":  ("#f0c040", "#333"),
        "Information": ("#4a9eff", "#fff"),
    }
    bg, fg = colors.get(sev, ("#888", "#fff"))
    return f'<span class="badge" style="background:{bg};color:{fg}">{sev}</span>'


def anomaly_severity_badge(sev: str) -> str:
    colors = {
        "Critical": ("#ff4444", "#fff"),
        "High":     ("#ff8c00", "#fff"),
        "Medium":   ("#f0c040", "#333"),
        "Low":      ("#4a9eff", "#fff"),
    }
    bg, fg = colors.get(sev, ("#888", "#fff"))
    return f'<span class="badge" style="background:{bg};color:{fg}">{sev}</span>'


def build_html(results: dict, output_dir: str) -> str:
    summary = results["summary"]
    anomalies = results["anomalies"]

    generated_at = summary.get("generated_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    total = summary.get("total_events", 0)
    severity_breakdown = summary.get("severity_breakdown", {})
    channel_breakdown = summary.get("channel_breakdown", {})
    top_providers = summary.get("top_providers", {})
    top_event_ids = summary.get("top_event_ids", [])

    # ── Severity rows ─────────────────────────────────────────
    sev_order = ["Critical", "Error", "Warning", "Information"]
    severity_rows = ""
    for sev in sev_order:
        count = severity_breakdown.get(sev, 0)
        if count:
            severity_rows += f"""
            <tr>
                <td>{severity_badge(sev)}</td>
                <td class="num">{count}</td>
                <td class="num">{round(count / total * 100, 1) if total else 0}%</td>
            </tr>"""

    # ── Channel rows ──────────────────────────────────────────
    channel_rows = ""
    for ch, count in sorted(channel_breakdown.items(), key=lambda x: -x[1]):
        channel_rows += f"""
            <tr><td>{ch}</td><td class="num">{count}</td></tr>"""

    # ── Top providers rows ────────────────────────────────────
    provider_rows = ""
    for prov, count in list(top_providers.items())[:8]:
        short = prov.replace("Microsoft-Windows-", "MW-")
        provider_rows += f"""
            <tr><td title="{prov}">{short}</td><td class="num">{count}</td></tr>"""

    # ── Top Event ID rows ─────────────────────────────────────
    event_id_rows = ""
    for item in top_event_ids[:8]:
        eid = item["event_id"]
        count = item["count"]
        event_id_rows += f"""
            <tr><td>{eid}</td><td class="num">{count}</td></tr>"""

    # ── Anomaly rows ──────────────────────────────────────────
    anomaly_rows = ""
    if not anomalies:
        anomaly_rows = '<tr><td colspan="6" class="no-anomalies">✓ No anomalies detected</td></tr>'
    else:
        for a in sorted(anomalies, key=lambda x: ["Critical","High","Medium","Low"].index(x.get("severity","Low")) if x.get("severity") in ["Critical","High","Medium","Low"] else 99):
            eid = a.get("event_id") or "—"
            time = a.get("time") or "—"
            preview = (a.get("message_preview") or "")[:120]
            preview = preview.replace("<", "&lt;").replace(">", "&gt;")
            anomaly_rows += f"""
            <tr>
                <td>{anomaly_severity_badge(a.get('severity',''))}</td>
                <td>{a.get('type','')}</td>
                <td>{a.get('channel','')}</td>
                <td>{eid}</td>
                <td>{time}</td>
                <td class="desc">{a.get('description','')}{"<br><small class='preview'>" + preview + "</small>" if preview else ""}</td>
            </tr>"""

    anomaly_count = len(anomalies)
    anomaly_color = "#ff4444" if anomaly_count > 0 else "#2ecc71"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Log Analyzer Report — {generated_at}</title>
<style>
  :root {{
    --bg: #0f1117;
    --surface: #1a1d27;
    --surface2: #22263a;
    --border: #2e3250;
    --accent: #4a9eff;
    --text: #e2e8f0;
    --muted: #8892a4;
    --green: #2ecc71;
    --red: #ff4444;
    --orange: #ff8c00;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 14px;
    line-height: 1.6;
    padding: 2rem;
  }}
  header {{
    border-left: 4px solid var(--accent);
    padding-left: 1.5rem;
    margin-bottom: 2.5rem;
  }}
  header h1 {{
    font-size: 1.8rem;
    letter-spacing: 0.1em;
    color: var(--accent);
    text-transform: uppercase;
  }}
  header p {{ color: var(--muted); font-size: 0.85rem; margin-top: 0.3rem; }}

  .stat-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1rem;
    margin-bottom: 2.5rem;
  }}
  .stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.2rem 1.5rem;
  }}
  .stat-card .label {{ color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em; }}
  .stat-card .value {{ font-size: 2rem; font-weight: bold; margin-top: 0.3rem; }}

  .grid-2 {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5rem;
    margin-bottom: 2.5rem;
  }}
  @media (max-width: 700px) {{ .grid-2 {{ grid-template-columns: 1fr; }} }}

  .panel {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }}
  .panel-header {{
    background: var(--surface2);
    padding: 0.75rem 1.2rem;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--accent);
    border-bottom: 1px solid var(--border);
  }}

  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ padding: 0.6rem 1.2rem; text-align: left; border-bottom: 1px solid var(--border); }}
  th {{ background: var(--surface2); color: var(--muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.1em; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(74,158,255,0.05); }}
  td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}

  .badge {{
    display: inline-block;
    padding: 0.15rem 0.6rem;
    border-radius: 4px;
    font-size: 0.72rem;
    font-weight: bold;
    letter-spacing: 0.05em;
  }}

  .anomaly-section {{ margin-bottom: 2.5rem; }}
  .anomaly-section .panel-header {{ color: {anomaly_color}; }}
  td.desc {{ font-size: 0.82rem; max-width: 320px; }}
  small.preview {{ color: var(--muted); display: block; margin-top: 0.2rem; }}
  td.no-anomalies {{ text-align: center; color: var(--green); padding: 2rem; }}

  footer {{ color: var(--muted); font-size: 0.75rem; text-align: center; margin-top: 3rem; }}

  .pdf-btn {{
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 6px;
    padding: 0.55rem 1.2rem;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 0.8rem;
    font-weight: bold;
    letter-spacing: 0.08em;
    cursor: pointer;
    text-transform: uppercase;
    transition: opacity 0.15s;
  }}
  .pdf-btn:hover {{ opacity: 0.85; }}

  @media print {{
    .pdf-btn {{ display: none; }}
    body {{ background: #fff; color: #000; padding: 1rem; }}
    .panel, .stat-card {{ border: 1px solid #ccc; background: #fff; }}
    .panel-header {{ background: #f0f0f0; color: #333; }}
    th {{ background: #f0f0f0; color: #333; }}
    header h1 {{ color: #1a1a1a; }}
    .badge {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .stat-card .value {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    tr:hover td {{ background: none; }}
    .grid-2 {{ grid-template-columns: 1fr 1fr; }}
    footer {{ margin-top: 1rem; }}
  }}
</style>
</head>
<body>

<header>
  <div style="display:flex; align-items:flex-start; justify-content:space-between; flex-wrap:wrap; gap:1rem;">
    <div>
      <h1>&#9632; Log Analyzer Report</h1>
      <p>Generated: {generated_at} &nbsp;|&nbsp; Output: {os.path.abspath(output_dir)}</p>
    </div>
    <button class="pdf-btn" onclick="exportPDF()">&#128438; Export PDF</button>
  </div>
</header>

<script>
  function exportPDF() {{
    const btn = document.querySelector('.pdf-btn');
    btn.textContent = 'Preparing...';
    setTimeout(() => {{
      window.print();
      btn.innerHTML = '&#128438; Export PDF';
    }}, 100);
  }}
</script>

<!-- Stat Cards -->
<div class="stat-grid">
  <div class="stat-card">
    <div class="label">Total Events</div>
    <div class="value" style="color:var(--accent)">{total:,}</div>
  </div>
  <div class="stat-card">
    <div class="label">Anomalies</div>
    <div class="value" style="color:{anomaly_color}">{anomaly_count}</div>
  </div>
  <div class="stat-card">
    <div class="label">Errors / Criticals</div>
    <div class="value" style="color:var(--red)">{severity_breakdown.get('Error',0) + severity_breakdown.get('Critical',0):,}</div>
  </div>
  <div class="stat-card">
    <div class="label">Warnings</div>
    <div class="value" style="color:var(--orange)">{severity_breakdown.get('Warning',0):,}</div>
  </div>
  <div class="stat-card">
    <div class="label">Channels Scanned</div>
    <div class="value" style="color:var(--green)">{len(channel_breakdown)}</div>
  </div>
</div>

<!-- 2-col tables -->
<div class="grid-2">
  <div class="panel">
    <div class="panel-header">Severity Breakdown</div>
    <table>
      <thead><tr><th>Level</th><th>Count</th><th>%</th></tr></thead>
      <tbody>{severity_rows}</tbody>
    </table>
  </div>
  <div class="panel">
    <div class="panel-header">Events by Channel</div>
    <table>
      <thead><tr><th>Channel</th><th>Count</th></tr></thead>
      <tbody>{channel_rows}</tbody>
    </table>
  </div>
  <div class="panel">
    <div class="panel-header">Top Providers</div>
    <table>
      <thead><tr><th>Provider</th><th>Count</th></tr></thead>
      <tbody>{provider_rows}</tbody>
    </table>
  </div>
  <div class="panel">
    <div class="panel-header">Top Event IDs</div>
    <table>
      <thead><tr><th>Event ID</th><th>Count</th></tr></thead>
      <tbody>{event_id_rows}</tbody>
    </table>
  </div>
</div>

<!-- Anomalies -->
<div class="anomaly-section">
  <div class="panel">
    <div class="panel-header">&#9888; Anomaly Detection Results ({anomaly_count} found)</div>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Type</th>
          <th>Channel</th>
          <th>Event ID</th>
          <th>Time</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>{anomaly_rows}</tbody>
    </table>
  </div>
</div>

<footer>Windows Log Analyzer &mdash; Kaleb Neace &mdash; {generated_at}</footer>
</body>
</html>"""

    return html


def main():
    parser = argparse.ArgumentParser(description="HTML Report Generator")
    parser.add_argument("--output", required=True, help="Output directory containing results.json")
    args = parser.parse_args()

    print("[*] Loading analysis results...")
    results = load_results(args.output)

    print("[*] Building HTML report...")
    html = build_html(results, args.output)

    report_path = os.path.join(args.output, "report.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] HTML report written: {report_path}")


if __name__ == "__main__":
    main()