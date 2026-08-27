#!/usr/bin/env python3
"""
subdomain_takeover_check.py — checks a list of subdomains for dangling
CNAME records pointing at third-party services (GitHub Pages, Heroku, AWS
S3/CloudFront, Azure, Shopify, WordPress.com, etc.) where the referenced
resource no longer exists — a classic, still-common real-world finding
that lets an attacker claim the subdomain on the third-party service and
serve content under the target's own domain name.

This is the same technique as "Can I Take Over XYZ" fingerprint lists —
resolve CNAME, fetch the page, and match known "not claimed" response
signatures.

ACTIVE (low-impact): a normal DNS lookup + a normal HTTP GET per candidate
subdomain. Requires authorization per docs/00-legal-and-ethics.md.

Usage:
    python3 subdomain_takeover_check.py subdomains.txt
    echo -e "blog.example.com\\nold.example.com" | python3 subdomain_takeover_check.py -
    python3 subdomain_takeover_check.py subdomains.txt --json out.json
"""
import argparse
import json
import sys
import requests
from html_report import generate_html_report

try:
    import dns.resolver
except ImportError:
    dns = None

# service label -> (cname substring, response-body fingerprint substring(s))
FINGERPRINTS = {
    "GitHub Pages": ("github.io", ["There isn't a GitHub Pages site here"]),
    "Heroku": ("herokuapp.com", ["No such app", "herokucdn.com/error-pages/no-such-app.html"]),
    "AWS S3": ("s3.amazonaws.com", ["NoSuchBucket", "The specified bucket does not exist"]),
    "AWS CloudFront": ("cloudfront.net", ["Bad request", "ERROR: The request could not be satisfied"]),
    "Azure": ("azurewebsites.net", ["404 Web Site not found"]),
    "Shopify": ("myshopify.com", ["Sorry, this shop is currently unavailable"]),
    "WordPress.com": ("wordpress.com", ["Do you want to register"]),
    "Fastly": ("fastly.net", ["Fastly error: unknown domain"]),
    "Ghost(Pro)": ("ghost.io", ["The thing you were looking for is no longer here"]),
    "Surge.sh": ("surge.sh", ["project not found"]),
    "Bitbucket": ("bitbucket.io", ["Repository not found"]),
    "Unbounce": ("unbounce.com", ["The requested URL was not found on this server"]),
    "WPEngine": ("wpengine.com", ["The site you're looking for could not be found"]),
    "Zendesk": ("zendesk.com", ["Help Center Closed"]),
}


def get_cname(hostname: str) -> str:
    if dns is None:
        return ""
    try:
        answers = dns.resolver.Resolver().resolve(hostname, "CNAME")
        return str(answers[0].target).rstrip(".")
    except Exception:
        return ""


def check_takeover(hostname: str, timeout: int = 10) -> dict:
    cname = get_cname(hostname)
    if not cname:
        return {"hostname": hostname, "cname": None, "service": None,
                 "likely_takeover": False, "note": "no CNAME record"}

    matched_service = None
    for service, (needle, _fingerprints) in FINGERPRINTS.items():
        if needle in cname:
            matched_service = service
            break

    if not matched_service:
        return {"hostname": hostname, "cname": cname, "service": None,
                 "likely_takeover": False, "note": "CNAME target not in known-service list"}

    body = ""
    try:
        resp = requests.get(f"http://{hostname}/", timeout=timeout,
                             headers={"User-Agent": "attack-surface-toolkit/1.0"})
        body = resp.text or ""
    except requests.RequestException as e:
        return {"hostname": hostname, "cname": cname, "service": matched_service,
                 "likely_takeover": None, "note": f"request failed: {e}"}

    _needle, fingerprints = FINGERPRINTS[matched_service]
    hit = any(fp.lower() in body.lower() for fp in fingerprints)

    return {
        "hostname": hostname,
        "cname": cname,
        "service": matched_service,
        "likely_takeover": hit,
        "note": "fingerprint matched — resource appears unclaimed" if hit
                else "CNAME points at known service but fingerprint not matched "
                     "(resource likely still claimed, or check manually)",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="File of subdomains (one per line), or '-' for stdin")
    parser.add_argument("--json", help="Optional path to write results as JSON")
    parser.add_argument("--html", help="Optional path to write HTML report")
    parser.add_argument("--pdf", help="Optional path to write PDF report")
    args = parser.parse_args()

    if dns is None:
        print("[!] dnspython not installed (pip install dnspython)", file=sys.stderr)
        sys.exit(1)

    if args.input == "-":
        hosts = [line.strip() for line in sys.stdin if line.strip()]
    else:
        with open(args.input) as f:
            hosts = [line.strip() for line in f if line.strip()]

    print(f"[*] Checking {len(hosts)} hostnames for dangling CNAME takeover risk ...")
    print("[!] Active checks (DNS + HTTP GET) — confirm authorization before running.\n")

    results = []
    flagged = []
    for host in hosts:
        result = check_takeover(host)
        results.append(result)
        if result["likely_takeover"]:
            flagged.append(result)
            print(f"[!!!] {host} -> {result['cname']} ({result['service']}) — LIKELY TAKEOVER RISK")
        elif result["cname"]:
            print(f"[+] {host} -> {result['cname']} ({result['service'] or 'unrecognized service'})")
        else:
            print(f"    {host} — no CNAME")

    print(f"\n[+] {len(flagged)} likely takeover candidate(s) out of {len(hosts)} checked.")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[*] Written to {args.json}")


    if args.html:
        generate_html_report(
            "subdomain_takeover_check", args.input,
            {"input": args.input, "results": results, "flagged": flagged},
            args.html,
            summary=f"{len(flagged)} likely takeover candidate(s) out of {len(hosts)} checked.",
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        from html_report import generate_pdf_report
        generate_pdf_report(
            "subdomain_takeover_check.py", args.input,
            {"input": args.input, "results": results, "flagged": flagged},
            args.pdf,
            summary=f"{len(flagged)} likely takeover candidate(s) out of {len(hosts)} checked.",
        )

if __name__ == "__main__":
    main()
