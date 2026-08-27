#!/usr/bin/env python3
"""
generate_dashboard.py — renders the merged inventory as a single, self-contained
HTML dashboard. No external dependencies; safe to open offline.

Usage:
    python3 generate_dashboard.py reports/inventory.json
    python3 generate_dashboard.py reports/inventory.json --out dashboard.html
"""
import argparse
import json
import os
from collections import Counter
from datetime import datetime, timezone
from html import escape

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
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-bottom: 16px; }
.card {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: 8px; padding: 14px 16px; text-align: center;
}
.card .num { font-size: 24px; font-weight: 700; color: var(--accent); }
.card .lbl { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); }
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


def main():
    parser = argparse.ArgumentParser(description="Render inventory dashboard HTML")
    parser.add_argument("inventory", help="Path to inventory.json")
    parser.add_argument("--out", default="dashboard.html", help="Output HTML path")
    args = parser.parse_args()

    with open(args.inventory) as f:
        inventory = json.load(f)

    assets = inventory.get("assets", [])
    asset_count = inventory.get("asset_count", len(assets))
    target = inventory.get("target", "unknown")
    generated_at = inventory.get("generated_at", datetime.now(timezone.utc).isoformat())

    type_counts = Counter(a.get("type", "unknown") for a in assets)
    source_counts = Counter(a.get("source", "unknown") for a in assets)

    top_types = type_counts.most_common(10)
    top_sources = source_counts.most_common(10)

    type_rows = "".join(
        f"<tr><td>{escape(t)}</td><td>{c}</td></tr>" for t, c in top_types
    )
    source_rows = "".join(
        f"<tr><td>{escape(s)}</td><td>{c}</td></tr>" for s, c in top_sources
    )

    asset_rows = []
    for a in assets[:500]:
        detail = a.get("detail", {})
        if isinstance(detail, dict):
            detail_str = ", ".join(f"{k}={v}" for k, v in list(detail.items())[:3])
        else:
            detail_str = escape(str(detail))[:120]
        asset_rows.append(
            f"<tr><td>{escape(a.get('type',''))}</td><td>{escape(a.get('value',''))}</td>"
            f"<td>{escape(a.get('source',''))}</td><td>{detail_str}</td></tr>"
        )
    asset_table = "".join(asset_rows)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Dashboard — {escape(target)}</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>Attack Surface Dashboard</h1>
  <p>Target: {escape(target)} &nbsp;|&nbsp; Generated: {escape(generated_at)} &nbsp;|&nbsp; {asset_count} assets</p>
</header>
<div class="wrap">
  <div class="cards">
    <div class="card"><div class="num">{asset_count}</div><div class="lbl">Total Assets</div></div>
    <div class="card"><div class="num">{len(type_counts)}</div><div class="lbl">Types</div></div>
    <div class="card"><div class="num">{len(source_counts)}</div><div class="lbl">Sources</div></div>
  </div>

  <div class="card">
    <h2>Asset Type Breakdown</h2>
    <table><thead><tr><th>Type</th><th>Count</th></tr></thead><tbody>{type_rows}</tbody></table>
  </div>

  <div class="card">
    <h2>Source Breakdown</h2>
    <table><thead><tr><th>Source</th><th>Count</th></tr></thead><tbody>{source_rows}</tbody></table>
  </div>

  <div class="card">
    <h2>Assets</h2>
    <table><thead><tr><th>Type</th><th>Value</th><th>Source</th><th>Detail</th></tr></thead><tbody>{asset_table}</tbody></table>
  </div>
</div>
</body>
</html>"""

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        f.write(html)
    print(f"[+] Dashboard written to {args.out} ({asset_count} assets)")


if __name__ == "__main__":
    main()
