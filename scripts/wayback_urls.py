#!/usr/bin/env python3
"""
wayback_urls.py — passive historical URL discovery via the Internet Archive's
Wayback Machine CDX API. Surfaces old endpoints, forgotten parameters,
backup files, and staging paths that were once crawled but may not appear
in current sitemaps — a real technique used across bug bounty and red-team
recon (equivalent to the popular 'waybackurls' / 'gau' tools).

Purely passive: queries archive.org's public dataset, never contacts the
target's own infrastructure.

Usage:
    python3 wayback_urls.py example.com
    python3 wayback_urls.py example.com --interesting-only
    python3 wayback_urls.py example.com --json out.json
"""
import argparse
import json
import re
import sys
import requests
from html_report import generate_html_report
from json_io import save_json, load_json

CDX_URL = "https://web.archive.org/cdx/search/cdx"

# Extensions/paths that commonly indicate forgotten or sensitive assets.
INTERESTING_PATTERN = re.compile(
    r"\.(sql|bak|old|zip|tar|gz|log|env|config|conf|yml|yaml|json|xml|"
    r"pem|key|pfx|db|backup)$|"
    r"/(admin|debug|test|staging|internal|api/v[0-9]+|swagger|actuator)/",
    re.IGNORECASE,
)


def fetch_urls(domain: str, timeout: int = 20) -> list:
    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "collapse": "urlkey",
        "fl": "original,timestamp,statuscode,mimetype",
    }
    headers = {"User-Agent": "attack-surface-toolkit/1.0 (passive recon)"}
    try:
        resp = requests.get(CDX_URL, params=params, headers=headers, timeout=timeout)
        resp.raise_for_status()
        rows = resp.json()
    except (requests.RequestException, json.JSONDecodeError) as e:
        print(f"[!] Wayback CDX query failed: {e}", file=sys.stderr)
        return []

    if not rows or len(rows) < 2:
        return []

    header, *data = rows
    results = [dict(zip(header, row)) for row in data]
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("domain", help="Root domain, e.g. example.com")
    parser.add_argument("--interesting-only", action="store_true",
                         help="Only show URLs matching sensitive-file/path patterns")
    parser.add_argument("--json", help="Optional path to write results as JSON")
    parser.add_argument("--html", help="Optional path to write HTML report")
    parser.add_argument("--pdf", help="Optional path to write PDF report")
    args = parser.parse_args()

    print(f"[*] Querying Wayback Machine CDX for *.{args.domain}/* ...")
    records = fetch_urls(args.domain)
    print(f"[+] Found {len(records)} archived URLs")

    if args.interesting_only:
        records = [r for r in records if INTERESTING_PATTERN.search(r.get("original", ""))]
        print(f"[+] {len(records)} match interesting file/path patterns")

    for r in records:
        flag = " <-- interesting" if INTERESTING_PATTERN.search(r.get("original", "")) else ""
        print(f"{r.get('timestamp','')}  {r.get('original','')}{flag}")

    if args.json:
        save_json(records, args.json, compress=True)
        print(f"[*] Written to {args.json}.gz")


    if args.html:
        generate_html_report(
            "wayback_urls", args.domain,
            {"domain": args.domain, "urls": records},
            args.html,
            summary=f"Found {len(records)} archived URLs",
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        from html_report import generate_pdf_report
        generate_pdf_report(
            "wayback_urls.py", args.domain,
            {"domain": args.domain, "urls": records},
            args.pdf,
            summary=f"Found {len(records)} archived URLs",
        )

if __name__ == "__main__":
    main()
