#!/usr/bin/env python3
"""
whois_dns_recon.py — passive WHOIS + DNS record enumeration for a domain.
Queries public WHOIS registries and public DNS resolvers only.

Usage:
    python3 whois_dns_recon.py example.com
"""
import argparse
import json
import sys
from html_report import generate_html_report

try:
    import whois as pywhois
except ImportError:
    pywhois = None

try:
    import dns.resolver
except ImportError:
    dns = None

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]


def do_whois(domain: str) -> dict:
    print(f"\n=== WHOIS: {domain} ===")
    result = {}
    if pywhois is None:
        print("[!] python-whois not installed (pip install python-whois)")
        return result
    try:
        w = pywhois.whois(domain)
        for field in ["domain_name", "registrar", "creation_date",
                      "expiration_date", "updated_date", "name_servers",
                      "emails", "org", "country"]:
            value = w.get(field) if hasattr(w, "get") else getattr(w, field, None)
            if value:
                print(f"{field:16}: {value}")
                result[field] = str(value)
    except Exception as e:
        print(f"[!] WHOIS lookup failed: {e}")
    return result


def do_dns(domain: str) -> dict:
    print(f"\n=== DNS records: {domain} ===")
    records = {}
    if dns is None:
        print("[!] dnspython not installed (pip install dnspython)")
        return records
    resolver = dns.resolver.Resolver()
    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            values = [rdata.to_text() for rdata in answers]
            for v in values:
                print(f"{rtype:6} {v}")
            records[rtype] = values
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            print(f"[!] {domain} does not exist (NXDOMAIN)")
            return records
        except Exception as e:
            print(f"[!] {rtype} lookup failed: {e}")
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("domain", help="Domain to look up, e.g. example.com")
    parser.add_argument("--json", help="Optional path to write results as JSON")
    parser.add_argument("--html", help="Optional path to write HTML report")
    parser.add_argument("--pdf", help="Optional path to write PDF report")
    args = parser.parse_args()

    whois_data = do_whois(args.domain)
    dns_data = do_dns(args.domain)

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"domain": args.domain, "whois": whois_data,
                        "dns": dns_data}, f, indent=2)
        print(f"\n[*] Written to {args.json}")


    if args.html:
        generate_html_report(
            "whois_dns_recon", args.domain,
            {"domain": args.domain, "whois": whois_data, "dns": dns_data},
            args.html,
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        from html_report import generate_pdf_report
        generate_pdf_report(
            "whois_dns_recon.py", args.domain,
            {"domain": args.domain, "whois": whois_data, "dns": dns_data},
            args.pdf,
            summary=None,
        )

if __name__ == "__main__":
    main()
