#!/usr/bin/env python3
"""
username_presence_check.py — checks whether a given username/handle exists
on a curated list of public platforms, by requesting each platform's
profile URL and checking the response. This is the same technique used by
tools like Sherlock/WhatsMyName/Maigret.

Legitimate uses in this toolkit's scope: confirming which platforms an
organization's official brand accounts exist on (so fake/impersonation
accounts can be identified), or checking your own organization's exposure
footprint. This script is a discovery aid only — it does not access
private data, does not authenticate, and does not scrape profile content
beyond the HTTP status of the profile URL.

Do not use this to stalk, harass, or build dossiers on private individuals
without their consent — that's outside this toolkit's intended scope.

Usage:
    python3 username_presence_check.py acmecorp
    python3 username_presence_check.py acmecorp --json out.json
"""
import argparse
import json
import time
import requests
from html_report import generate_html_report

# name -> profile URL template. Deliberately a small, well-known set of
# mainstream platforms (not an exhaustive stalkerware-style list).
PLATFORMS = {
    "GitHub": "https://github.com/{u}",
    "GitLab": "https://gitlab.com/{u}",
    "Twitter/X": "https://x.com/{u}",
    "Instagram": "https://www.instagram.com/{u}/",
    "LinkedIn (company)": "https://www.linkedin.com/company/{u}/",
    "Facebook": "https://www.facebook.com/{u}",
    "YouTube": "https://www.youtube.com/@{u}",
    "Reddit": "https://www.reddit.com/user/{u}",
    "TikTok": "https://www.tiktok.com/@{u}",
    "Medium": "https://medium.com/@{u}",
    "PyPI": "https://pypi.org/user/{u}/",
    "npm": "https://www.npmjs.com/~{u}",
    "Docker Hub": "https://hub.docker.com/u/{u}",
}

NOT_FOUND_HINTS = ["page not found", "user not found", "doesn't exist",
                    "sorry, this page"]


def check_platform(name: str, url_template: str, username: str, timeout: int = 10):
    url = url_template.format(u=username)
    try:
        resp = requests.get(
            url, timeout=timeout, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (attack-surface-toolkit/1.0)"},
        )
    except requests.RequestException as e:
        return {"platform": name, "url": url, "status": "error", "detail": str(e)}

    body_lower = resp.text.lower()[:20000] if resp.text else ""
    looks_missing = any(hint in body_lower for hint in NOT_FOUND_HINTS)

    if resp.status_code == 404 or looks_missing:
        exists = False
    elif resp.status_code in (200, 301, 302):
        exists = True
    else:
        exists = None  # ambiguous (rate-limited, blocked, etc.)

    return {
        "platform": name,
        "url": url,
        "status_code": resp.status_code,
        "exists": exists,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username", help="Username/handle to check")
    parser.add_argument("--delay", type=float, default=0.5,
                         help="Delay between requests in seconds (default 0.5)")
    parser.add_argument("--json", help="Optional path to write results as JSON")
    parser.add_argument("--html", help="Optional path to write HTML report")
    parser.add_argument("--pdf", help="Optional path to write PDF report")
    args = parser.parse_args()

    print(f"[*] Checking '{args.username}' across {len(PLATFORMS)} platforms ...")
    print("[!] Active checks against third-party sites — respect each "
          "platform's Terms of Service and rate limits.\n")

    results = []
    for name, template in PLATFORMS.items():
        result = check_platform(name, template, args.username)
        results.append(result)
        tag = {"True": "FOUND", "False": "not found", "None": "unclear"}.get(
            str(result.get("exists")), "error")
        print(f"{name:22} {tag:10} {result['url']}")
        time.sleep(args.delay)

    found = [r for r in results if r.get("exists") is True]
    print(f"\n[+] Found on {len(found)}/{len(PLATFORMS)} platforms checked.")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[*] Written to {args.json}")


    if args.html:
        generate_html_report(
            "username_presence_check", args.username,
            {"username": args.username, "results": results},
            args.html,
            summary=f"Found on {len(found)}/{len(PLATFORMS)} platforms checked.",
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        from html_report import generate_pdf_report
        generate_pdf_report(
            "username_presence_check.py", args.username,
            {"username": args.username, "results": results},
            args.pdf,
            summary=f"Found on {len(found)}/{len(PLATFORMS)} platforms checked.",
        )

if __name__ == "__main__":
    main()
