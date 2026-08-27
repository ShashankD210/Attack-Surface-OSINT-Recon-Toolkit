#!/usr/bin/env python3
"""
ipinfo_asn_lookup.py — resolves a hostname (or accepts an IP directly) and
looks up its ASN, owning organization, and rough geolocation using public,
no-auth-required data sources (ipinfo.io's free endpoint and RDAP via
rdap.org). Useful for mapping which network blocks/providers an org's
infrastructure sits in — standard groundwork before deciding what's
actually in-scope for an engagement.

Passive: only queries third-party lookup services, never contacts the
target directly beyond a normal DNS resolution.

Usage:
    python3 ipinfo_asn_lookup.py example.com
    python3 ipinfo_asn_lookup.py 93.184.216.34
    python3 ipinfo_asn_lookup.py example.com --json out.json
"""
import argparse
import json
import socket
import sys
import requests
from html_report import generate_html_report

IPINFO_URL = "https://ipinfo.io/{ip}/json"
RDAP_URL = "https://rdap.org/ip/{ip}"


def resolve_to_ip(target: str) -> str:
    try:
        socket.inet_aton(target)
        return target  # already an IPv4 address
    except OSError:
        pass
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as e:
        print(f"[!] Could not resolve {target}: {e}", file=sys.stderr)
        sys.exit(1)


def lookup_ipinfo(ip: str, timeout: int = 15) -> dict:
    try:
        resp = requests.get(IPINFO_URL.format(ip=ip), timeout=timeout,
                             headers={"User-Agent": "attack-surface-toolkit/1.0"})
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        print(f"[!] ipinfo.io lookup failed: {e}", file=sys.stderr)
        return {}


def lookup_rdap(ip: str, timeout: int = 15) -> dict:
    try:
        resp = requests.get(RDAP_URL.format(ip=ip), timeout=timeout,
                             headers={"User-Agent": "attack-surface-toolkit/1.0"})
        resp.raise_for_status()
        data = resp.json()
        return {
            "handle": data.get("handle"),
            "name": data.get("name"),
            "country": data.get("country"),
            "startAddress": data.get("startAddress"),
            "endAddress": data.get("endAddress"),
        }
    except (requests.RequestException, json.JSONDecodeError) as e:
        print(f"[!] RDAP lookup failed: {e}", file=sys.stderr)
        return {}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="Hostname or IPv4 address")
    parser.add_argument("--json", help="Optional path to write results as JSON")
    parser.add_argument("--html", help="Optional path to write HTML report")
    parser.add_argument("--pdf", help="Optional path to write PDF report")
    args = parser.parse_args()

    ip = resolve_to_ip(args.target)
    print(f"[*] Target: {args.target} -> {ip}")

    ipinfo = lookup_ipinfo(ip)
    rdap = lookup_rdap(ip)

    print("\n=== ipinfo.io ===")
    for field in ["ip", "hostname", "city", "region", "country", "loc",
                  "org", "postal", "timezone"]:
        if ipinfo.get(field):
            print(f"{field:10}: {ipinfo[field]}")

    print("\n=== RDAP (network block) ===")
    for field, label in [("handle", "handle"), ("name", "net name"),
                          ("country", "country"), ("startAddress", "range start"),
                          ("endAddress", "range end")]:
        if rdap.get(field):
            print(f"{label:12}: {rdap[field]}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"target": args.target, "ip": ip, "ipinfo": ipinfo,
                        "rdap": rdap}, f, indent=2)
        print(f"\n[*] Written to {args.json}")


    if args.html:
        generate_html_report(
            "ipinfo_asn_lookup", args.target,
            {"target": args.target, "ip": ip, "ipinfo": ipinfo, "rdap": rdap},
            args.html,
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        from html_report import generate_pdf_report
        generate_pdf_report(
            "ipinfo_asn_lookup.py", args.target,
            {"target": args.target, "ip": ip, "ipinfo": ipinfo, "rdap": rdap},
            args.pdf,
            summary=None,
        )

if __name__ == "__main__":
    main()
