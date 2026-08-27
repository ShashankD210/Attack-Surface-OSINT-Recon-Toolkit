#!/usr/bin/env python3
"""
tech_fingerprint.py — lightweight technology fingerprinting for a web host,
in the spirit of Wappalyzer/whatweb: inspects HTTP response headers, the
HTML <meta> generator tag, and common script/asset URL patterns to guess
the CMS, framework, server software, and analytics/CDN providers in use.

ACTIVE (low-impact): makes a single normal HTTP GET request to the target,
the same as visiting the page in a browser. Requires authorization per
docs/00-legal-and-ethics.md.

Usage:
    python3 tech_fingerprint.py https://example.com
    python3 tech_fingerprint.py https://example.com --json out.json
"""
import argparse
import json
import re
import requests
from html_report import generate_html_report

# (label, where to look, pattern)
SIGNATURES = [
    ("WordPress", "body", r"wp-content|wp-includes"),
    ("Drupal", "body", r"Drupal\.settings|sites/default/files"),
    ("Joomla", "body", r"/components/com_|Joomla!"),
    ("Shopify", "body", r"cdn\.shopify\.com|Shopify\.theme"),
    ("Magento", "body", r"Mage\.Cookies|/static/version"),
    ("React", "body", r"__REACT_DEVTOOLS|data-reactroot|react-dom"),
    ("Next.js", "body", r"__NEXT_DATA__|_next/static"),
    ("Vue.js", "body", r"data-v-app|__VUE__|vue\.js"),
    ("Angular", "body", r"ng-version|angular\.js"),
    ("jQuery", "body", r"jquery(\.min)?\.js"),
    ("Bootstrap", "body", r"bootstrap(\.min)?\.css"),
    ("Cloudflare", "headers", r"cloudflare"),
    ("Amazon CloudFront", "headers", r"cloudfront"),
    ("Fastly", "headers", r"fastly"),
    ("Akamai", "headers", r"akamai"),
    ("Nginx", "headers", r"nginx"),
    ("Apache", "headers", r"apache"),
    ("Microsoft IIS", "headers", r"microsoft-iis"),
    ("Google Analytics", "body", r"www\.google-analytics\.com|gtag\("),
    ("Google Tag Manager", "body", r"googletagmanager\.com"),
    ("Hotjar", "body", r"static\.hotjar\.com"),
    ("Intercom", "body", r"widget\.intercom\.io"),
    ("HubSpot", "body", r"js\.hs-scripts\.com|hubspot"),
    ("Segment", "body", r"cdn\.segment\.com"),
    ("PHP", "headers", r"php/"),
    ("ASP.NET", "headers", r"asp\.net|x-aspnet-version"),
]


def fingerprint(url: str, timeout: int = 15) -> dict:
    resp = requests.get(
        url, timeout=timeout, allow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (attack-surface-toolkit/1.0)"},
    )
    header_blob = " ".join(f"{k}:{v}" for k, v in resp.headers.items()).lower()
    body_blob = (resp.text or "")[:200000]  # cap for performance

    meta_generator = None
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                  body_blob, re.IGNORECASE)
    if m:
        meta_generator = m.group(1)

    matches = []
    for label, where, pattern in SIGNATURES:
        haystack = header_blob if where == "headers" else body_blob
        if re.search(pattern, haystack, re.IGNORECASE):
            matches.append(label)

    return {
        "url": url,
        "final_url": resp.url,
        "status_code": resp.status_code,
        "server_header": resp.headers.get("Server"),
        "x_powered_by": resp.headers.get("X-Powered-By"),
        "meta_generator": meta_generator,
        "detected": sorted(set(matches)),
        "notable_headers": {
            k: v for k, v in resp.headers.items()
            if k.lower() in ("server", "x-powered-by", "via", "x-cache",
                              "x-generator", "x-drupal-cache")
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="Full URL to fingerprint, e.g. https://example.com")
    parser.add_argument("--json", help="Optional path to write results as JSON")
    parser.add_argument("--html", help="Optional path to write HTML report")
    parser.add_argument("--pdf", help="Optional path to write PDF report")
    args = parser.parse_args()

    print(f"[*] Fetching {args.url} ...")
    try:
        result = fingerprint(args.url)
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}")
        return

    print(f"\nStatus: {result['status_code']}  (final URL: {result['final_url']})")
    if result["server_header"]:
        print(f"Server: {result['server_header']}")
    if result["x_powered_by"]:
        print(f"X-Powered-By: {result['x_powered_by']}")
    if result["meta_generator"]:
        print(f"Meta generator: {result['meta_generator']}")

    print(f"\nDetected technologies ({len(result['detected'])}):")
    for tech in result["detected"]:
        print(f"  - {tech}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n[*] Written to {args.json}")


    if args.html:
        generate_html_report(
            "tech_fingerprint", args.url,
            result,
            args.html,
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        from html_report import generate_pdf_report
        generate_pdf_report(
            "tech_fingerprint.py", args.url,
            result,
            args.pdf,
            summary=None,
        )

if __name__ == "__main__":
    main()
