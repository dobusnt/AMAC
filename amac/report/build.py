from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from .._json import loads
from ..diffing import analyze_summary


def _read_json(path: Path) -> Dict[str, Any]:
    return loads(path.read_bytes())


def _fmt_dt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _h(s: Any) -> str:
    return html.escape(str(s), quote=True)


def _build_findings_table(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "<p><em>No findings under current heuristics.</em></p>"

    rows = []
    for f in findings:
        rows.append(
            "<tr>"
            f"<td>{_h(f.get('severity','').upper())}</td>"
            f"<td>{_h(f.get('type',''))}</td>"
            f"<td>{_h(f.get('method',''))}</td>"
            f"<td class='url'>{_h(f.get('url',''))}</td>"
            f"<td>{_h(f.get('noauth_status'))} → {_h(f.get('auth_status'))}</td>"
            f"<td>{_h(f.get('delta_size'))}</td>"
            f"<td>{_h(f.get('notes',''))}</td>"
            "</tr>"
        )
    return (
        "<table class='zebra'>"
        "<thead><tr>"
        "<th>Severity</th><th>Type</th><th>Method</th><th>URL</th>"
        "<th>no→auth</th><th>Δsize</th><th>Notes</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )


def _build_summary_table(summary: Dict[str, Any]) -> str:
    rows_html = []
    rows = summary.get("rows", [])
    for r in rows:
        req_auth = r.get("requires_auth")
        req_auth_str = "yes" if req_auth is True else "no" if req_auth is False else "unknown"
        rows_html.append(
            "<tr>"
            f"<td>{_h(r.get('index'))}</td>"
            f"<td>{_h(r.get('method'))}</td>"
            f"<td class='url'>{_h(r.get('url'))}</td>"
            f"<td>{_h(req_auth_str)}</td>"
            f"<td>{_h(r.get('noauth_status'))}</td>"
            f"<td>{_h(r.get('auth_name'))}</td>"
            f"<td>{_h(r.get('auth_status'))}</td>"
            f"<td>{_h(r.get('noauth_size'))}</td>"
            f"<td>{_h(r.get('auth_size'))}</td>"
            "</tr>"
        )
    return (
        "<table class='zebra'>"
        "<thead><tr>"
        "<th>#</th><th>Method</th><th>URL</th><th>Req. Auth?</th>"
        "<th>No-Auth</th><th>Auth</th><th>Auth Status</th><th>No Size</th><th>Auth Size</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows_html)}</tbody>"
        "</table>"
    )


def render_report(run_dir: Path, out_html: Path | None = None) -> Path:
    """
    Build a standalone HTML report for a probe run directory.
    - Reads {run_dir}/summary.json
    - If {run_dir}/findings.json exists, uses it; else computes from summary
    - Writes HTML to out_html (default: {run_dir}/report.html)
    Returns the path to the HTML file.
    """
    run_dir = Path(run_dir)
    if out_html is None:
        out_html = run_dir / "report.html"

    summary_path = run_dir / "summary.json"
    if not summary_path.exists():
        raise FileNotFoundError(f"summary.json not found in {run_dir}")

    summary = _read_json(summary_path)

    findings_json_path = run_dir / "findings.json"
    if findings_json_path.exists():
        findings = _read_json(findings_json_path)
    else:
        findings = analyze_summary(summary)

    counts = findings.get("counts", {})
    total_eps = counts.get("total_endpoints", len(summary.get("rows", [])))
    total_findings = counts.get("total_findings", 0)
    by_sev = findings.get("counts", {}).get("by_severity", {})
    by_type = findings.get("counts", {}).get("by_type", {})

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AMAC Report — {_h(run_dir)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {{
    --bg: #0f1115;
    --card: #161a22;
    --text: #e6e6e6;
    --muted: #a0a4ad;
    --accent: #6ea8fe;
    --ok: #49d36d;
    --warn: #ffd166;
    --bad: #ff6b6b;
    --border: #2a2f3a;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  }}
  html, body {{ background: var(--bg); color: var(--text); margin: 0; padding: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, 'Helvetica Neue', Arial, 'Noto Sans', 'Apple Color Emoji', 'Segoe UI Emoji'; }}
  .wrap {{ max-width: 1100px; margin: 40px auto; padding: 0 16px; }}
  h1, h2, h3 {{ margin: 0 0 12px; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 16px 18px; margin: 16px 0; }}
  .meta {{ color: var(--muted); font-size: 0.95rem; }}
  code, .url {{ font-family: var(--mono); }}
  table {{ width: 100%; border-collapse: collapse; }}
  .zebra thead th {{ text-align: left; border-bottom: 1px solid var(--border); padding: 8px; }}
  .zebra td {{ padding: 8px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  .pill {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 0.8rem; border: 1px solid var(--border); }}
  .sev-HIGH {{ background: rgba(255, 107, 107, .12); border-color: #ff6b6b; color: #ff9a9a; }}
  .sev-MEDIUM {{ background: rgba(255, 209, 102, .12); border-color: #ffd166; color: #ffe1a3; }}
  .sev-LOW {{ background: rgba(110, 168, 254, .12); border-color: #6ea8fe; color: #a6c6ff; }}
  .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }}
  .stat {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 12px; text-align: center; }}
  .stat .num {{ font-size: 1.4rem; font-weight: 700; }}
  .muted {{ color: var(--muted); }}
  footer {{ color: var(--muted); font-size: .9rem; margin: 24px 0; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>AMAC Report</h1>
  <div class="meta">Run dir: <code>{_h(run_dir)}</code> · Generated: {_h(_fmt_dt(datetime.now()))}</div>

  <div class="grid" style="margin:16px 0 8px;">
    <div class="stat"><div class="muted">Endpoints</div><div class="num">{_h(total_eps)}</div></div>
    <div class="stat"><div class="muted">Findings</div><div class="num">{_h(total_findings)}</div></div>
    <div class="stat"><div class="muted">Auth Used</div><div class="num">{_h(summary.get('auth_used') or '-')}</div></div>
  </div>

  <div class="card">
    <h2>Findings</h2>
    <div class="muted" style="margin-bottom:8px">By Severity: {_h(by_sev)} · By Type: {_h(by_type)}</div>
    {_build_findings_table(findings.get('findings', []))}
  </div>

  <div class="card">
    <h2>Endpoint Summary</h2>
    {_build_summary_table(summary)}
  </div>

  <footer>
    <div>AMAC 0.1.0 — Generated HTML report. Evidence snapshots (requests) are in: <code>{_h((run_dir / 'requests').resolve())}</code></div>
  </footer>
</div>
</body>
</html>
"""
    out_html = Path(out_html)
    out_html.parent.mkdir(parents=True, exist_ok=True)
    out_html.write_text(html_doc, encoding="utf-8")
    return out_html
