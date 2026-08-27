#!/usr/bin/env python3
"""
crtsh_subdomains.py — passive subdomain discovery via Certificate
Transparency logs (crt.sh public API). Purely passive: queries a public
third-party dataset, never contacts the target's own infrastructure.

Usage:
    python3 crtsh_subdomains.py example.com
    python3 crtsh_subdomains.py example.com --json out.json
"""
import argparse
import json
import sys
import time
import requests
from html_report import generate_html_report

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


def fetch_subdomains(domain: str, retries: int = 3, timeout: int = 30) -> set:
    url = CRTSH_URL.format(domain=domain)
    headers = {"User-Agent": "attack-surface-toolkit/1.0 (passive recon)"}

    last_err = None
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            names = set()
            for entry in data:
                for line in entry.get("name_value", "").splitlines():
                    line = line.strip().lower().lstrip("*.")
                    if line.endswith(domain):
                        names.add(line)
            return names
        except (requests.RequestException, json.JSONDecodeError) as e:
            last_err = e
            time.sleep(2 * attempt)  # backoff, be polite to the free service

    print(f"[!] Failed to query crt.sh after {retries} attempts: {last_err}",
          file=sys.stderr)
    return set()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("domain", help="Root domain, e.g. example.com")
    parser.add_argument("--json", help="Optional path to write results as JSON")
    parser.add_argument("--html", help="Optional path to write HTML report")
    parser.add_argument("--pdf", help="Optional path to write PDF report")
    parser.add_argument("--txt", help="Optional path to write results as plain text (one per line)")
    args = parser.parse_args()

    print(f"[*] Querying crt.sh for *.{args.domain} ...")
    subdomains = fetch_subdomains(args.domain)

    print(f"[+] Found {len(subdomains)} unique hostnames")
    for name in sorted(subdomains):
        print(name)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(sorted(subdomains), f, indent=2)
        print(f"[*] Written to {args.json}")

    if args.txt:
        with open(args.txt, "w") as f:
            for name in sorted(subdomains):
                f.write(name + "\n")
        print(f"[*] Written to {args.txt}")


    if args.html:
        generate_html_report(
            "crtsh_subdomains", args.domain,
            {"domain": args.domain, "subdomains": sorted(subdomains)},
            args.html,
            summary=f"Found {len(subdomains)} unique hostnames",
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        from html_report import generate_pdf_report
        generate_pdf_report(
            "crtsh_subdomains.py", args.domain,
            {"domain": args.domain, "subdomains": sorted(subdomains)},
            args.pdf,
            summary=f"Found {len(subdomains)} unique hostnames",
        )

if __name__ == "__main__":
    main()
