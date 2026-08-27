#!/usr/bin/env python3
"""
shodan_search.py — look up previously-scanned, publicly indexed exposed
services for a domain/org using the Shodan API. This queries Shodan's own
prior scan data, not the target directly, so it stays passive from your
side. Requires a Shodan API key (free tier available) in SHODAN_API_KEY.

Usage:
    export SHODAN_API_KEY=your_key_here
    python3 shodan_search.py example.com
    python3 shodan_search.py example.com --limit 50
"""
import argparse
import os
import sys
from html_report import generate_html_report

try:
    import shodan
except ImportError:
    shodan = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("query", help="Domain or search term, e.g. example.com")
    parser.add_argument("--limit", type=int, default=20,
                         help="Max results to display (default: 20)")
    parser.add_argument("--json", help="Optional path to write results as JSON")
    parser.add_argument("--html", help="Optional path to write HTML report")
    parser.add_argument("--pdf", help="Optional path to write PDF report")
    args = parser.parse_args()

    if shodan is None:
        print("[!] shodan package not installed (pip install shodan)",
              file=sys.stderr)
        sys.exit(1)

    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        print("[!] Set SHODAN_API_KEY environment variable first.",
              file=sys.stderr)
        sys.exit(1)

    api = shodan.Shodan(api_key)
    search_query = f'hostname:"{args.query}"'

    print(f"[*] Searching Shodan for: {search_query}")
    try:
        results = api.search(search_query, limit=args.limit)
    except shodan.APIError as e:
        print(f"[!] Shodan API error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] {results['total']} total matches (showing up to {args.limit})\n")
    records = []
    for match in results["matches"]:
        ip = match.get("ip_str")
        port = match.get("port")
        org = match.get("org", "")
        product = match.get("product", "")
        hostnames = match.get("hostnames", [])
        print(f"{ip:16} :{port:<6} {product:20} {org:20} {', '.join(hostnames)}")
        records.append({
            "source": "shodan",
            "ip": ip,
            "port": port,
            "org": org,
            "product": product,
            "hostnames": hostnames,
        })

    if args.json:
        import json
        with open(args.json, "w") as f:
            json.dump(records, f, indent=2)
        print(f"[*] Written to {args.json}")


    if args.html:
        generate_html_report(
            "shodan_search", args.query,
            {"query": search_query, "total": results.get("total", 0), "matches": records},
            args.html,
            summary=f"{results.get('total', 0)} total matches (showing up to {args.limit})",
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        from html_report import generate_pdf_report
        generate_pdf_report(
            "shodan_search.py", args.query,
            {"query": search_query, "total": results.get("total", 0), "matches": records},
            args.pdf,
            summary=f"{results.get('total', 0)} total matches (showing up to {args.limit})",
        )

if __name__ == "__main__":
    main()
