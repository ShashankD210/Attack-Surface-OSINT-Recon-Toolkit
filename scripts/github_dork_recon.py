#!/usr/bin/env python3
"""
github_dork_recon.py — generates a set of targeted GitHub code-search URLs
for an org/keyword, to help a human analyst manually review results for
accidental leakage (config files, internal hostnames, API references, etc).

This script does NOT scrape GitHub or automate secret extraction — it only
builds search URLs for you to open and review yourself, in line with
GitHub's terms of service around automated querying.

Usage:
    python3 github_dork_recon.py "Acme Corp" acme.com
"""
import argparse
import urllib.parse
from html_report import generate_html_report

# Generic, non-exploitative search themes: config/leak awareness, not
# targeted secret harvesting or exploitation.
DORK_TEMPLATES = [
    '"{org}" password',
    '"{org}" api_key',
    '"{org}" secret',
    '"{domain}" filename:.env',
    '"{domain}" filename:config',
    '"{domain}" extension:pem',
    '"{domain}" extension:yml internal',
    'org:"{org}" filename:.git-credentials',
]


def build_urls(org: str, domain: str):
    urls = []
    for template in DORK_TEMPLATES:
        query = template.format(org=org, domain=domain)
        encoded = urllib.parse.quote(query)
        urls.append((query, f"https://github.com/search?q={encoded}&type=code"))
    return urls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("org", help='Organization name, e.g. "Acme Corp"')
    parser.add_argument("domain", help="Primary domain, e.g. acme.com")
    parser.add_argument("--html", help="Optional path to write HTML report")
    parser.add_argument("--pdf", help="Optional path to write PDF report")
    args = parser.parse_args()

    print(f"[*] GitHub review queries for org='{args.org}', domain='{args.domain}'\n")
    for query, url in build_urls(args.org, args.domain):
        print(f"{query}\n  -> {url}\n")

    print("[i] Open these manually and review results by hand — GitHub rate-limits")
    print("    and restricts automated scraping of search results.")


    if args.html:
        urls = build_urls(args.org, args.domain)
        generate_html_report(
            "github_dork_recon", args.domain,
            {"org": args.org, "domain": args.domain, "queries": [(q, u) for q, u in urls]},
            args.html,
            summary=f"{len(urls)} GitHub code-search review queries generated",
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        from html_report import generate_pdf_report
        generate_pdf_report(
            "github_dork_recon.py", args.domain,
            {"org": args.org, "domain": args.domain, "queries": [(q, u) for q, u in build_urls(args.org, args.domain)]},
            args.pdf,
            summary=f"{len(build_urls(args.org, args.domain))} GitHub code-search review queries generated",
        )

if __name__ == "__main__":
    main()
