#!/usr/bin/env python3
"""
generate_single_pdf.py — generates a single combined PDF report from all
scan outputs in a run directory. Reads the merged inventory plus all per-tool
JSON files and produces one self-contained PDF.

Usage:
    python3 generate_single_pdf.py reports/
    python3 generate_single_pdf.py reports/ --out reports/full_report.pdf
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from html import escape

try:
    from weasyprint import HTML as WeasyHTML
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False

from html_report import CSS
from json_io import load_json


def render_section(title, body_html):
    return f"""
    <div class="card">
      <h2>{escape(title)}</h2>
      {body_html}
    </div>
    """


def render_kv_section(title, data):
    if not data:
        return render_section(title, '<p style="color:var(--muted)">No data</p>')
    rows = "".join(f"<tr><td>{escape(str(k))}</td><td>{escape(str(v))}</td></tr>" for k, v in data.items())
    return render_section(title, f'<table><tbody>{rows}</tbody></table>')


def render_list_section(title, items, empty="No items"):
    if not items:
        return render_section(title, f'<p style="color:var(--muted)">{empty}</p>')
    rows = "".join(f"<tr><td>{i+1}</td><td>{escape(str(x))}</td></tr>" for i, x in enumerate(items))
    return render_section(title, f'<table><tbody>{rows}</tbody></table>')


def build_report_html(indir: str, inventory: dict) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    target = inventory.get("target", "unknown")
    asset_count = inventory.get("asset_count", 0)

    whois_data = load_json(os.path.join(indir, "data", "whois_dns.json"))
    subdomains_data = load_json(os.path.join(indir, "data", "subdomains.json"))
    wayback_data = load_json(os.path.join(indir, "data", "wayback.json"))
    asn_data = load_json(os.path.join(indir, "data", "asn.json"))
    tech_data = load_json(os.path.join(indir, "data", "tech.json"))
    buckets_data = load_json(os.path.join(indir, "data", "buckets.json"))
    certs_data = load_json(os.path.join(indir, "data", "certs.json"))
    headers_data = load_json(os.path.join(indir, "data", "headers.json"))
    robots_data = load_json(os.path.join(indir, "data", "robots_sitemap.json"))
    takeover_data = load_json(os.path.join(indir, "data", "takeover.json"))
    handles_data = load_json(os.path.join(indir, "data", "handles.json"))
    emails_data = load_json(os.path.join(indir, "data", "emails.json"))
    github_data = load_json(os.path.join(indir, "data", "github_dorks.json")) if os.path.isfile(os.path.join(indir, "data", "github_dorks.json")) else None

    parts = []

    parts.append(render_section("Summary", f"""
      <p><strong>Target:</strong> {escape(target)}</p>
      <p><strong>Generated:</strong> {ts}</p>
      <p><strong>Total Assets:</strong> {asset_count}</p>
    """))

    if whois_data:
        parts.append(render_kv_section("WHOIS / DNS", whois_data))

    if subdomains_data and isinstance(subdomains_data, list):
        parts.append(render_list_section("Subdomains (Certificate Transparency)", subdomains_data, "No subdomains found"))
    elif subdomains_data and isinstance(subdomains_data, dict):
        parts.append(render_kv_section("Subdomains (Certificate Transparency)", subdomains_data))

    if asn_data:
        parts.append(render_kv_section("ASN / IP Info", asn_data))

    if tech_data:
        parts.append(render_kv_section("Technology Fingerprint", tech_data))

    if headers_data:
        parts.append(render_kv_section("Security Headers", headers_data))

    if certs_data:
        parts.append(render_kv_section("SSL/TLS Certificate", certs_data))

    if wayback_data and isinstance(wayback_data, list):
        parts.append(render_section("Wayback Machine URLs", f'<p style="color:var(--muted)">{len(wayback_data)} archived URL(s)</p>' + render_list_section("Sample URLs", wayback_data[:50], "No URLs")))
    elif wayback_data:
        parts.append(render_kv_section("Wayback Machine", wayback_data))

    if takeover_data:
        if isinstance(takeover_data, list):
            parts.append(render_list_section("Subdomain Takeover Check", takeover_data, "No takeover candidates"))
        else:
            parts.append(render_kv_section("Subdomain Takeover Check", takeover_data))

    if buckets_data:
        parts.append(render_kv_section("Cloud Bucket Enumeration", buckets_data))

    if robots_data:
        parts.append(render_kv_section("Robots.txt / Sitemap", robots_data))

    if handles_data and isinstance(handles_data, list):
        parts.append(render_section("Username Presence", f'<p style="color:var(--muted)">{len(handles_data)} platform(s) checked</p>' + render_list_section("Platforms", handles_data)))
    elif handles_data:
        parts.append(render_kv_section("Username Presence", handles_data))

    if emails_data:
        parts.append(render_kv_section("Email Pattern Candidates", emails_data))

    if github_data:
        parts.append(render_kv_section("GitHub Code Search Dorks", github_data))

    body = "".join(parts)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Full Report — {escape(target)}</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>Full Recon Report</h1>
  <p>Target: {escape(target)} &nbsp;|&nbsp; {ts} &nbsp;|&nbsp; Attack Surface Toolkit</p>
</header>
<div class="wrap">
{body}
</div>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description="Generate single combined PDF report")
    parser.add_argument("indir", help="Run directory containing data/ and reports/")
    parser.add_argument("--out", help="Output PDF path (default: <indir>/reports/report.pdf)")
    parser.add_argument("--inventory", default="inventory.json", help="Inventory filename (default: inventory.json)")
    args = parser.parse_args()

    if not HAS_WEASYPRINT:
        print("[!] weasyprint not installed. Install it with: pip install weasyprint")
        sys.exit(1)

    inventory_path = os.path.join(args.indir, "reports", args.inventory)
    if not os.path.isfile(inventory_path):
        print(f"[!] Inventory not found at {inventory_path}")
        sys.exit(1)

    with open(inventory_path) as f:
        inventory = json.load(f)

    out_path = args.out or os.path.join(args.indir, "reports", "report.pdf")
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    html_content = build_report_html(args.indir, inventory)
    html_path = out_path + ".tmp.html"
    with open(html_path, "w") as f:
        f.write(html_content)

    try:
        WeasyHTML(filename=html_path).write_pdf(out_path)
        print(f"[+] Single PDF report written to {out_path}")
    except Exception as e:
        print(f"[!] PDF generation failed: {e}")
        sys.exit(1)
    finally:
        if os.path.exists(html_path):
            os.remove(html_path)


if __name__ == "__main__":
    main()
