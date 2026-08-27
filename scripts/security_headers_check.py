#!/usr/bin/env python3
"""
security_headers_check.py — checks a URL for the presence of standard
HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy) and gives a simple pass/fail grade per
header. This is the same check performed by securityheaders.com, done
locally against an authorized target.

ACTIVE (low-impact): a single normal HTTP GET request.

Usage:
    python3 security_headers_check.py https://example.com
    python3 security_headers_check.py https://example.com --json out.json
"""
import argparse
import json
import requests
from html_report import generate_html_report

CHECKS = [
    ("Strict-Transport-Security", "HSTS — enforces HTTPS on future visits"),
    ("Content-Security-Policy", "CSP — mitigates XSS/data-injection attacks"),
    ("X-Frame-Options", "Clickjacking protection (or use CSP frame-ancestors)"),
    ("X-Content-Type-Options", "Prevents MIME-sniffing (expect: nosniff)"),
    ("Referrer-Policy", "Controls referrer leakage to third parties"),
    ("Permissions-Policy", "Restricts browser feature access (camera, geo, etc.)"),
]


def check(url: str, timeout: int = 15) -> dict:
    resp = requests.get(
        url, timeout=timeout, allow_redirects=True,
        headers={"User-Agent": "attack-surface-toolkit/1.0"},
    )
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    results = []
    present_count = 0
    for header, description in CHECKS:
        value = headers_lower.get(header.lower())
        present = value is not None
        if present:
            present_count += 1
        results.append({
            "header": header,
            "present": present,
            "value": value,
            "description": description,
        })

    return {
        "url": url,
        "final_url": resp.url,
        "status_code": resp.status_code,
        "checks": results,
        "score": f"{present_count}/{len(CHECKS)}",
        "server_header": resp.headers.get("Server"),
        "cookies_missing_secure_flag": [
            c.name for c in resp.cookies if not c.secure
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="Full URL to check, e.g. https://example.com")
    parser.add_argument("--json", help="Optional path to write results as JSON")
    parser.add_argument("--html", help="Optional path to write HTML report")
    parser.add_argument("--pdf", help="Optional path to write PDF report")
    args = parser.parse_args()

    print(f"[*] Checking security headers for {args.url} ...")
    try:
        result = check(args.url)
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}")
        return

    print(f"\nStatus: {result['status_code']}  (final URL: {result['final_url']})")
    print(f"Score: {result['score']} headers present\n")
    for c in result["checks"]:
        tag = "PRESENT" if c["present"] else "MISSING"
        print(f"[{tag:7}] {c['header']:26} {c['description']}")
        if c["present"] and c["value"]:
            shown = c["value"] if len(c["value"]) < 80 else c["value"][:77] + "..."
            print(f"           -> {shown}")

    if result["cookies_missing_secure_flag"]:
        print(f"\n[!] Cookies without Secure flag: "
              f"{', '.join(result['cookies_missing_secure_flag'])}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n[*] Written to {args.json}")


    if args.html:
        generate_html_report(
            "security_headers_check", args.url,
            result,
            args.html,
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        from html_report import generate_pdf_report
        generate_pdf_report(
            "security_headers_check.py", args.url,
            result,
            args.pdf,
            summary=None,
        )

if __name__ == "__main__":
    main()
