#!/usr/bin/env python3
"""
html_report.py — shared utility to render scan results as a self-contained
HTML report and/or PDF. Used by individual scripts via --html / --pdf, and by
the pipeline.

Each tool writes its own JSON, then calls generate_html_report() to produce
a matching .html file with no external dependencies. If weasyprint is
installed, generate_pdf_report() converts that HTML into a PDF.
"""
import json
import os
from html import escape
from datetime import datetime, timezone

try:
    from weasyprint import HTML as WeasyHTML
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False


CSS = """\
:root {
  --bg: #0f1117; --panel: #161923; --border: #262b3a;
  --text: #e6e8ef; --muted: #8b92a8; --accent: #6ea8fe;
  --danger: #ff6b6b; --warn: #ffb454; --ok: #4ade80;
}
* { box-sizing: border-box; }
body {
  margin: 0; font-family: -apple-system, Segoe UI, Roboto, sans-serif;
  background: var(--bg); color: var(--text);
}
header { padding: 20px 24px; border-bottom: 1px solid var(--border); }
header h1 { margin: 0 0 4px; font-size: 18px; }
header p { margin: 0; color: var(--muted); font-size: 12px; }
.wrap { padding: 20px 24px; max-width: 1100px; margin: 0 auto; }
.card {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: 8px; padding: 14px 16px; margin-bottom: 14px;
}
.card h2 {
  margin: 0 0 10px; font-size: 14px; color: var(--accent);
  text-transform: uppercase; letter-spacing: 0.05em;
}
table {
  width: 100%; border-collapse: collapse; font-size: 13px;
}
th, td {
  text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border);
}
th { color: var(--muted); font-weight: 600; }
tr:last-child td { border-bottom: none; }
.badge {
  display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: 11px; font-weight: 600;
}
.badge-ok { background: rgba(74,222,128,0.15); color: var(--ok); }
.badge-warn { background: rgba(255,180,84,0.15); color: var(--warn); }
.badge-danger { background: rgba(255,107,107,0.15); color: var(--danger); }
.badge-info { background: rgba(110,168,254,0.15); color: var(--accent); }
pre {
  background: #0a0c10; border: 1px solid var(--border); border-radius: 6px;
  padding: 12px; overflow-x: auto; font-size: 12px; line-height: 1.5;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
"""


def _badge(text, kind="info"):
    return f'<span class="badge badge-{kind}">{escape(str(text))}</span>'


def _render_table(headers, rows):
    th = "".join(f"<th>{escape(h)}</th>" for h in headers)
    trs = []
    for row in rows:
        td = "".join(f"<td>{escape(str(c))}</td>" for c in row)
        trs.append(f"<tr>{td}</tr>")
    return f'<table><thead><tr>{th}</tr></thead><tbody>{"".join(trs)}</tbody></table>'


def _render_list(title, items, empty_msg="No items"):
    if not items:
        return f'<div class="card"><h2>{escape(title)}</h2><p style="color:var(--muted)">{empty_msg}</p></div>'
    rows = [(i + 1, escape(str(x))) for i, x in enumerate(items)]
    return f'<div class="card"><h2>{escape(title)} ({len(items)})</h2>' + _render_table(["#", "Value"], rows) + "</div>"


def _render_kv(title, data, empty_msg="No data"):
    if not data:
        return f'<div class="card"><h2>{escape(title)}</h2><p style="color:var(--muted)">{empty_msg}</p></div>'
    rows = [(escape(str(k)), escape(str(v))) for k, v in data.items()]
    return f'<div class="card"><h2>{escape(title)}</h2>' + _render_table(["Field", "Value"], rows) + "</div>"


def _auto_render(key, value):
    if isinstance(value, list):
        if value and isinstance(value[0], dict):
            headers = list(value[0].keys())
            rows = [[escape(str(item.get(h, ""))) for h in headers] for item in value]
            return _render_table(headers, rows)
        return _render_list(key, value)
    if isinstance(value, dict):
        return _render_kv(key, value)
    return f'<div class="card"><h2>{escape(key)}</h2><pre>{escape(json.dumps(value, indent=2, default=str))}</pre></div>'


def generate_html_report(
    tool_name: str,
    target: str,
    data: dict,
    out_path: str,
    summary: str = "",
) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    body_parts = []

    if summary:
        body_parts.append(f'<div class="card"><h2>Summary</h2><p>{escape(summary)}</p></div>')

    skip = {"tool", "target", "timestamp", "summary"}
    for key, value in data.items():
        if key in skip:
            continue
        body_parts.append(_auto_render(key, value))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{escape(tool_name)} — {escape(target)}</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>{escape(tool_name)}</h1>
  <p>Target: {escape(target)} &nbsp;|&nbsp; {ts} &nbsp;|&nbsp; Attack Surface Toolkit</p>
</header>
<div class="wrap">
{''.join(body_parts)}
</div>
</body>
</html>"""

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w") as f:
        f.write(html)
    return out_path


def generate_pdf_report(
    tool_name: str,
    target: str,
    data: dict,
    out_path: str,
    summary: str = "",
) -> str:
    if not HAS_WEASYPRINT:
        print("[!] weasyprint not installed — skipping PDF report. "
              "Install it with: pip install weasyprint")
        return ""

    html_path = out_path.replace(".pdf", ".tmp.html")
    generate_html_report(tool_name, target, data, html_path, summary)

    try:
        WeasyHTML(filename=html_path).write_pdf(out_path)
    except Exception as e:
        print(f"[!] PDF generation failed: {e}")
        return ""
    finally:
        if os.path.exists(html_path):
            os.remove(html_path)

    return out_path
