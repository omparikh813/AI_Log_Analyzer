import json
import os
import time
from typing import Dict

from jinja2 import BaseLoader, Environment

from app.models import AnalysisResult
from app.utils import ensure_output_dir, format_timestamp, setup_logging

logger = setup_logging(__name__)

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#2563eb",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PCAP Threat Analysis Report</title>
<style>
  body{font-family:Arial,sans-serif;margin:0;padding:20px;background:#f5f5f5;color:#333}
  .header{background:#1e293b;color:#fff;padding:20px 30px;border-radius:8px;margin-bottom:24px}
  .header h1{margin:0 0 6px;font-size:1.8em}
  .header p{margin:0;opacity:.7;font-size:.9em}
  .stats{display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap}
  .stat{background:#fff;border-radius:8px;padding:16px 24px;flex:1;min-width:100px;
        box-shadow:0 1px 3px rgba(0,0,0,.1);text-align:center}
  .stat .val{font-size:2em;font-weight:700;color:#1e293b}
  .stat .lbl{font-size:.82em;color:#64748b;margin-top:4px}
  .finding{background:#fff;border-radius:8px;margin-bottom:16px;
           box-shadow:0 1px 3px rgba(0,0,0,.1);overflow:hidden}
  .fh{padding:12px 20px;display:flex;justify-content:space-between;align-items:center}
  .ftitle{font-weight:700;font-size:1.05em}
  .badge{padding:3px 10px;border-radius:12px;font-size:.78em;font-weight:700;color:#fff}
  .fb{padding:16px 20px;border-top:1px solid #f1f5f9}
  .fb table{width:100%;border-collapse:collapse;font-size:.9em}
  .fb td{padding:6px 8px;vertical-align:top}
  .fb td:first-child{width:150px;font-weight:600;color:#475569}
  .fb tr:not(:last-child) td{border-bottom:1px solid #f1f5f9}
  ul{margin:0;padding-left:18px} li{margin:2px 0}
  .mitre{display:inline-block;background:#eff6ff;color:#1d4ed8;border-radius:4px;
         padding:2px 8px;font-size:.78em;margin:2px;font-family:monospace}
  .sec{font-size:1.15em;font-weight:700;color:#1e293b;margin:24px 0 12px}
  .ok{background:#f0fdf4;border:1px solid #86efac;border-radius:8px;
      padding:16px;color:#166534;text-align:center}
  .tl{display:flex;gap:12px;margin-bottom:6px;font-size:.88em}
  .tlt{color:#64748b;white-space:nowrap;width:180px;flex-shrink:0}
</style>
</head>
<body>
<div class="header">
  <h1>PCAP Threat Analysis Report</h1>
  <p>File: {{ result.pcap_file }} &bull; Generated: {{ generated_at }} &bull;
     Duration: {{ "%.2f"|format(result.analysis_end - result.analysis_start) }}s</p>
</div>

<div class="stats">
  <div class="stat"><div class="val">{{ result.total_packets }}</div><div class="lbl">Packets</div></div>
  <div class="stat"><div class="val">{{ result.total_flows }}</div><div class="lbl">Flows</div></div>
  <div class="stat"><div class="val">{{ result.findings|length }}</div><div class="lbl">Findings</div></div>
  <div class="stat"><div class="val" style="color:#dc2626">{{ counts.CRITICAL }}</div><div class="lbl">Critical</div></div>
  <div class="stat"><div class="val" style="color:#ea580c">{{ counts.HIGH }}</div><div class="lbl">High</div></div>
  <div class="stat"><div class="val" style="color:#ca8a04">{{ counts.MEDIUM }}</div><div class="lbl">Medium</div></div>
  <div class="stat"><div class="val" style="color:#2563eb">{{ counts.LOW }}</div><div class="lbl">Low</div></div>
</div>

{% if result.findings %}
<div class="sec">Findings ({{ result.findings|length }})</div>
{% for f in sorted_findings %}
<div class="finding">
  <div class="fh" style="background:{{ colors[f.severity.value] }}12;border-left:4px solid {{ colors[f.severity.value] }}">
    <div class="ftitle">{{ f.title }}</div>
    <div>
      <span class="badge" style="background:{{ colors[f.severity.value] }}">{{ f.severity.value }}</span>
      &nbsp;<span style="font-size:.8em;color:#64748b">{{ f.confidence.value }} confidence &bull; {{ f.category }}</span>
    </div>
  </div>
  <div class="fb">
    <table>
      <tr>
        <td>MITRE ATT&amp;CK</td>
        <td>{% for m in f.mitre_attacks %}<span class="mitre">{{ m.technique_id }} – {{ m.technique_name }}</span>{% endfor %}</td>
      </tr>
      <tr><td>Description</td><td>{{ f.description }}</td></tr>
      <tr><td>Evidence</td><td><ul>{% for e in f.evidence %}<li>{{ e }}</li>{% endfor %}</ul></td></tr>
      <tr><td>Remediation</td><td><ul>{% for r in f.remediation %}<li>{{ r }}</li>{% endfor %}</ul></td></tr>
      <tr><td>First Seen</td><td>{{ f.timestamp | fmt_ts }}</td></tr>
      {% if f.source_ips %}<tr><td>Source IP(s)</td><td>{{ f.source_ips[:5]|join(", ") }}</td></tr>{% endif %}
      {% if f.destination_ips %}<tr><td>Dest IP(s)</td><td>{{ f.destination_ips[:5]|join(", ") }}</td></tr>{% endif %}
    </table>
  </div>
</div>
{% endfor %}
{% else %}
<div class="ok">No threats detected in this PCAP capture.</div>
{% endif %}

{% if result.timeline %}
<div class="sec">Event Timeline</div>
{% for ev in result.timeline %}
<div class="tl">
  <span class="tlt">{{ ev.timestamp | fmt_ts }}</span>
  <span><strong>{{ ev.event }}</strong>{% if ev.detail %} &mdash; {{ ev.detail }}{% endif %}</span>
</div>
{% endfor %}
{% endif %}

{% if result.statistics %}
<div class="sec">Capture Statistics</div>
<div style="background:#fff;border-radius:8px;padding:16px 20px;box-shadow:0 1px 3px rgba(0,0,0,.1);font-size:.9em">
  <table style="width:100%;border-collapse:collapse">
  {% for k, v in result.statistics.items() %}
  <tr style="border-bottom:1px solid #f1f5f9">
    <td style="padding:6px 8px;font-weight:600;color:#475569;width:220px">{{ k.replace("_"," ").title() }}</td>
    <td style="padding:6px 8px">{{ v }}</td>
  </tr>
  {% endfor %}
  </table>
</div>
{% endif %}

</body>
</html>
"""


def generate_reports(result: AnalysisResult) -> Dict[str, str]:
    from config import REPORT_OUTPUT_DIR

    ensure_output_dir(REPORT_OUTPUT_DIR)
    base_name = os.path.splitext(os.path.basename(result.pcap_file))[0]
    ts = time.strftime("%Y%m%d_%H%M%S")

    json_path = os.path.join(REPORT_OUTPUT_DIR, f"{base_name}_{ts}.json")
    html_path = os.path.join(REPORT_OUTPUT_DIR, f"{base_name}_{ts}.html")

    _write_json(result, json_path)
    _write_html(result, html_path)

    return {"json": json_path, "html": html_path}


def _write_json(result: AnalysisResult, path: str):
    data = {
        "pcap_file": result.pcap_file,
        "analysis_start": format_timestamp(result.analysis_start),
        "analysis_end": format_timestamp(result.analysis_end),
        "total_packets": result.total_packets,
        "total_flows": result.total_flows,
        "statistics": result.statistics,
        "findings": [
            {
                "id": f.finding_id,
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "category": f.category,
                "mitre_attacks": [
                    {"id": m.technique_id, "name": m.technique_name}
                    for m in f.mitre_attacks
                ],
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "timestamp": format_timestamp(f.timestamp),
                "source_ips": f.source_ips,
                "destination_ips": f.destination_ips,
            }
            for f in result.findings
        ],
        "timeline": [
            {
                "timestamp": format_timestamp(e["timestamp"]),
                "event": e["event"],
                "detail": e.get("detail", ""),
            }
            for e in result.timeline
        ],
    }

    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    logger.info(f"JSON report: {path}")


def _write_html(result: AnalysisResult, path: str):
    sorted_findings = sorted(
        result.findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity.value, 99),
    )
    counts = {sev: sum(1 for f in result.findings if f.severity.value == sev)
              for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}

    env = Environment(loader=BaseLoader())
    env.filters["fmt_ts"] = lambda ts: format_timestamp(float(ts))

    html = env.from_string(HTML_TEMPLATE).render(
        result=result,
        sorted_findings=sorted_findings,
        generated_at=format_timestamp(time.time()),
        colors=SEVERITY_COLORS,
        counts=counts,
    )

    with open(path, "w") as fh:
        fh.write(html)
    logger.info(f"HTML report: {path}")
