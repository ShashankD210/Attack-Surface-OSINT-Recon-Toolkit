#!/usr/bin/env python3
"""
ssl_cert_inspector.py — connects to a host on port 443, retrieves its TLS
certificate, and reports issuer, validity window, and all Subject
Alternative Names (SANs). SANs frequently reveal additional subdomains not
found via certificate-transparency logs (e.g. internal-only certs that
were never logged to CT, or wildcard certs). Also flags certificates
expiring soon.

ACTIVE (low-impact): a normal TLS handshake, the same as visiting the site
in a browser. Requires authorization per docs/00-legal-and-ethics.md.

Usage:
    python3 ssl_cert_inspector.py example.com
    python3 ssl_cert_inspector.py example.com --port 8443
    python3 ssl_cert_inspector.py example.com --json out.json
"""
import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from html_report import generate_html_report

DATE_FMT = "%b %d %H:%M:%S %Y %Z"


def parse_cert(hostname: str, port: int, timeout: int = 10) -> dict:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # inspect even self-signed/expired certs

    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            cert_bin = ssock.getpeercert(binary_form=False)
            cipher = ssock.cipher()
            tls_version = ssock.version()

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")
    days_remaining = None
    if not_after:
        try:
            expiry = datetime.strptime(not_after, DATE_FMT).replace(tzinfo=timezone.utc)
            days_remaining = (expiry - datetime.now(timezone.utc)).days
        except ValueError:
            pass

    return {
        "hostname": hostname,
        "port": port,
        "subject_cn": subject.get("commonName"),
        "issuer_cn": issuer.get("commonName"),
        "issuer_org": issuer.get("organizationName"),
        "not_before": not_before,
        "not_after": not_after,
        "days_remaining": days_remaining,
        "san_dns_names": sorted(set(sans)),
        "tls_version": tls_version,
        "cipher": cipher[0] if cipher else None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hostname", help="Hostname to inspect, e.g. example.com")
    parser.add_argument("--port", type=int, default=443, help="TLS port (default 443)")
    parser.add_argument("--json", help="Optional path to write results as JSON")
    parser.add_argument("--html", help="Optional path to write HTML report")
    parser.add_argument("--pdf", help="Optional path to write PDF report")
    args = parser.parse_args()

    print(f"[*] Connecting to {args.hostname}:{args.port} ...")
    try:
        result = parse_cert(args.hostname, args.port)
    except (socket.error, ssl.SSLError, OSError) as e:
        print(f"[!] Connection/TLS error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\nSubject CN : {result['subject_cn']}")
    print(f"Issuer     : {result['issuer_cn']} ({result['issuer_org']})")
    print(f"Valid      : {result['not_before']}  ->  {result['not_after']}")
    if result["days_remaining"] is not None:
        flag = "  <-- EXPIRING SOON" if result["days_remaining"] < 30 else ""
        print(f"Days left  : {result['days_remaining']}{flag}")
    print(f"TLS version: {result['tls_version']}  Cipher: {result['cipher']}")

    print(f"\nSAN DNS names ({len(result['san_dns_names'])}):")
    for name in result["san_dns_names"]:
        print(f"  - {name}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n[*] Written to {args.json}")


    if args.html:
        generate_html_report(
            "ssl_cert_inspector", args.hostname,
            result,
            args.html,
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        from html_report import generate_pdf_report
        generate_pdf_report(
            "ssl_cert_inspector.py", args.hostname,
            result,
            args.pdf,
            summary=None,
        )

if __name__ == "__main__":
    main()
