#!/usr/bin/env python3
"""
dns_zone_transfer_check.py — tests whether any of a domain's authoritative
nameservers allow an unauthenticated AXFR zone transfer. A misconfigured
DNS server that allows this leaks the entire zone (every subdomain record)
to anyone who asks — a classic, still-common finding in real external
assessments (this is what `dig axfr @ns1.target.com target.com` checks
manually).

This is an ACTIVE check: it sends a real query to the target's own
nameservers. Low-impact (a single AXFR attempt, almost always refused by
correctly configured servers) but still requires authorization — see
docs/00-legal-and-ethics.md.

Usage:
    python3 dns_zone_transfer_check.py example.com
"""
import argparse
import sys
from html_report import generate_html_report

try:
    import dns.resolver
    import dns.query
    import dns.zone
except ImportError:
    dns = None


def get_nameservers(domain: str):
    resolver = dns.resolver.Resolver()
    try:
        answers = resolver.resolve(domain, "NS")
        return [str(r.target).rstrip(".") for r in answers]
    except Exception as e:
        print(f"[!] Could not fetch NS records for {domain}: {e}", file=sys.stderr)
        return []


def try_axfr(domain: str, nameserver: str, timeout: int = 10):
    try:
        ns_ip = dns.resolver.Resolver().resolve(nameserver, "A")[0].to_text()
    except Exception as e:
        print(f"[!] Could not resolve nameserver {nameserver}: {e}")
        return None

    try:
        z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=timeout))
        names = sorted(z.nodes.keys(), key=str)
        return [str(n) for n in names]
    except Exception:
        return None  # transfer refused — expected/correct behavior


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("domain", help="Domain to test, e.g. example.com")
    parser.add_argument("--html", help="Optional path to write HTML report")
    parser.add_argument("--pdf", help="Optional path to write PDF report")
    args = parser.parse_args()

    if dns is None:
        print("[!] dnspython not installed (pip install dnspython)", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Enumerating nameservers for {args.domain} ...")
    nameservers = get_nameservers(args.domain)
    if not nameservers:
        print("[!] No nameservers found — aborting.")
        return

    print(f"[+] Nameservers: {', '.join(nameservers)}\n")
    print("[!] Sending AXFR zone-transfer requests — active DNS query against "
          "the target's own nameservers. Confirm authorization before running.\n")

    vulnerable = []
    for ns in nameservers:
        print(f"[*] Trying AXFR against {ns} ...")
        records = try_axfr(args.domain, ns)
        if records:
            print(f"[!!!] {ns} ALLOWS zone transfer — {len(records)} records leaked")
            vulnerable.append(ns)
        else:
            print(f"[+] {ns} refused zone transfer (expected/correct)")

    print()
    if vulnerable:
        print(f"[!] FINDING: {len(vulnerable)} nameserver(s) allow unauthenticated "
              f"AXFR: {', '.join(vulnerable)}. This leaks the full DNS zone and "
              "should be reported and remediated (restrict AXFR to authorized "
              "secondary nameservers only).")
    else:
        print("[+] No nameservers allowed zone transfer.")


    if args.html:
        generate_html_report(
            "dns_zone_transfer_check", args.domain,
            {"domain": args.domain, "nameservers": nameservers, "vulnerable": vulnerable},
            args.html,
            summary=f"{len(vulnerable)} nameserver(s) allow unauthenticated AXFR" if vulnerable else "No nameservers allowed zone transfer.",
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        from html_report import generate_pdf_report
        generate_pdf_report(
            "dns_zone_transfer_check.py", args.domain,
            {"domain": args.domain, "nameservers": nameservers, "vulnerable": vulnerable},
            args.pdf,
            summary=f"{len(vulnerable)} nameserver(s) allow unauthenticated AXFR" if vulnerable else "No nameservers allowed zone transfer.",
        )

if __name__ == "__main__":
    main()
