#!/usr/bin/env python3
"""
merge_inventory.py — combines the JSON outputs of the other scripts in this
toolkit into a single normalized asset inventory (JSON + CSV), so you have
one file to hand off for reporting or feed into generate_dashboard.py.

Expects a directory containing any of these (all optional — merges whatever
it finds):
    data/subdomains.json         <- crtsh_subdomains.py --json
    data/whois_dns.json          <- whois_dns_recon.py --json
    data/wayback.json             <- wayback_urls.py --json
    data/shodan.json              <- shodan_search.py --json
    data/asn.json                 <- ipinfo_asn_lookup.py --json
    data/tech.json                 <- tech_fingerprint.py --json
    data/buckets.json              <- cloud_bucket_enum.py --json
    data/handles.json              <- username_presence_check.py --json
    data/takeover.json             <- subdomain_takeover_check.py --json
    data/certs.json                 <- ssl_cert_inspector.py --json
    data/headers.json                <- security_headers_check.py --json
    data/robots_sitemap.json          <- robots_sitemap_recon.py --json
    data/emails.json                  <- email_pattern_generator.py --json

Usage:
    python3 crtsh_subdomains.py example.com --json run/subdomains.json
    python3 whois_dns_recon.py example.com --json run/whois_dns.json
    python3 wayback_urls.py example.com --json run/wayback.json
    python3 shodan_search.py example.com --json run/shodan.json
    python3 ipinfo_asn_lookup.py example.com --json run/asn.json
    python3 tech_fingerprint.py https://example.com --json run/tech.json
    python3 cloud_bucket_enum.py acme --json run/buckets.json
    python3 username_presence_check.py acmecorp --json run/handles.json
    python3 subdomain_takeover_check.py subdomains.txt --json run/takeover.json
    python3 ssl_cert_inspector.py example.com --json run/certs.json
    python3 security_headers_check.py https://example.com --json run/headers.json
    python3 robots_sitemap_recon.py https://example.com --json run/robots_sitemap.json
    python3 email_pattern_generator.py acme.com "Jane Doe" --json run/emails.json

    python3 merge_inventory.py run/ --out run/inventory
    # -> writes run/inventory.json and run/inventory.csv
"""
import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone

from json_io import load_json
from html_report import generate_html_report


def build_inventory(indir: str) -> dict:
    assets = []

    # Subdomains from certificate transparency
    subs = load_json(os.path.join(indir, "data", "subdomains.json"))
    if subs:
        for host in subs:
            assets.append({
                "type": "hostname",
                "value": host,
                "source": "crtsh",
                "detail": {},
            })
        print(f"[+] Loaded {len(subs)} hostnames from subdomains.json")

    # WHOIS + DNS
    whois_dns = load_json(os.path.join(indir, "data", "whois_dns.json"))
    if whois_dns:
        domain = whois_dns.get("domain")
        dns_records = whois_dns.get("dns", {})
        for rtype, values in dns_records.items():
            for value in values:
                assets.append({
                    "type": f"dns_{rtype.lower()}",
                    "value": value,
                    "source": "dns",
                    "detail": {"domain": domain, "record_type": rtype},
                })
        if whois_dns.get("whois"):
            assets.append({
                "type": "whois_record",
                "value": domain,
                "source": "whois",
                "detail": whois_dns["whois"],
            })
        print(f"[+] Loaded WHOIS/DNS data for {domain}")

    # Wayback Machine historical URLs
    wayback = load_json(os.path.join(indir, "data", "wayback.json"))
    if wayback:
        for record in wayback:
            url = record.get("original")
            if not url:
                continue
            assets.append({
                "type": "archived_url",
                "value": url,
                "source": "wayback",
                "detail": record,
            })
        print(f"[+] Loaded {len(wayback)} archived URLs from wayback.json")

    # Shodan
    shodan_data = load_json(os.path.join(indir, "data", "shodan.json"))
    if shodan_data:
        matches = shodan_data.get("matches", [])
        for m in matches:
            ip = m.get("ip_str")
            if ip:
                assets.append({
                    "type": "shodan_host",
                    "value": ip,
                    "source": "shodan",
                    "detail": m,
                })
        print(f"[+] Loaded {len(matches)} Shodan matches")

    # ASN / IP
    asn_data = load_json(os.path.join(indir, "data", "asn.json"))
    if asn_data:
        ip = asn_data.get("ip")
        if ip:
            assets.append({
                "type": "ip_address",
                "value": ip,
                "source": "asn",
                "detail": {"asn": asn_data.get("asn"), "org": asn_data.get("org"), "country": asn_data.get("country")},
            })
        print(f"[+] Loaded ASN/org data for {asn_data.get('target', 'unknown')}")

    # Tech fingerprint
    tech_data = load_json(os.path.join(indir, "data", "tech.json"))
    if tech_data:
        for tech in tech_data.get("technologies", []):
            assets.append({
                "type": "technology",
                "value": tech.get("name", ""),
                "source": "tech_fingerprint",
                "detail": tech,
            })
        print(f"[+] Loaded {len(tech_data.get('technologies', []))} technology signatures")

    # Cloud buckets
    buckets = load_json(os.path.join(indir, "data", "buckets.json"))
    if buckets:
        for b in buckets:
            assets.append({
                "type": "cloud_bucket",
                "value": b.get("url", ""),
                "source": "cloud_bucket_enum",
                "detail": b,
            })
        print(f"[+] Loaded {len(buckets)} cloud bucket(s)")

    # Username handles
    handles = load_json(os.path.join(indir, "data", "handles.json"))
    if handles:
        for h in handles:
            assets.append({
                "type": "username_handle",
                "value": h.get("url", ""),
                "source": "username_presence",
                "detail": h,
            })
        print(f"[+] Loaded {len(handles)} username presence result(s)")

    # Subdomain takeover check
    takeover = load_json(os.path.join(indir, "data", "takeover.json"))
    if takeover:
        for t in takeover:
            assets.append({
                "type": "takeover_candidate",
                "value": t.get("host", ""),
                "source": "subdomain_takeover",
                "detail": t,
            })
        print(f"[+] Loaded {len(takeover)} subdomain takeover candidate(s)")

    # SSL certificate
    certs = load_json(os.path.join(indir, "data", "certs.json"))
    if certs:
        assets.append({
            "type": "ssl_certificate",
            "value": certs.get("hostname", ""),
            "source": "ssl_cert",
            "detail": certs,
        })
        print(f"[+] Loaded TLS certificate data for {certs.get('hostname', 'unknown')}")

    # Security headers
    headers_data = load_json(os.path.join(indir, "data", "headers.json"))
    if headers_data:
        assets.append({
            "type": "security_headers",
            "value": headers_data.get("url", ""),
            "source": "security_headers",
            "detail": headers_data,
        })
        print(f"[+] Loaded security header score for {headers_data.get('url', 'unknown')}: {headers_data.get('score', 'N/A')}/{headers_data.get('max_score', 'N/A')}")

    # Robots / Sitemap
    robots_sitemap = load_json(os.path.join(indir, "data", "robots_sitemap.json"))
    if robots_sitemap:
        for path in robots_sitemap.get("disallow_paths", []):
            assets.append({
                "type": "robots_rule",
                "value": path,
                "source": "robots_sitemap",
                "detail": {"base_url": robots_sitemap.get("base_url", "")},
            })
        for url in robots_sitemap.get("sitemap_urls", []):
            assets.append({
                "type": "sitemap_url",
                "value": url,
                "source": "robots_sitemap",
                "detail": {"base_url": robots_sitemap.get("base_url", "")},
            })
        print(f"[+] Loaded {len(robots_sitemap.get('disallow_paths', []))} robots.txt paths and {len(robots_sitemap.get('sitemap_urls', []))} sitemap URLs")

    # Email patterns
    emails = load_json(os.path.join(indir, "data", "emails.json"))
    if emails:
        for e in emails.get("candidates", []):
            assets.append({
                "type": "email_candidate",
                "value": e.get("email", ""),
                "source": "email_pattern",
                "detail": e,
            })
        print(f"[+] Loaded {len(emails.get('candidates', []))} candidate email address(es)")

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "asset_count": len(assets),
        "assets": assets,
        "target": "",
    }


def write_csv(inventory: dict, path: str):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "value", "source", "detail"])
        for asset in inventory["assets"]:
            writer.writerow([
                asset["type"], asset["value"], asset["source"],
                json.dumps(asset["detail"]),
            ])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("indir", help="Directory containing per-tool JSON outputs")
    parser.add_argument("--html", help="Optional path to write HTML report")
    parser.add_argument("--pdf", help="Optional path to write PDF report")
    parser.add_argument("--out", default="inventory",
                         help="Output path prefix (default: inventory -> "
                              "inventory.json / inventory.csv)")
    args = parser.parse_args()

    inventory = build_inventory(args.indir)

    json_path = f"{args.out}.json"
    csv_path = f"{args.out}.csv"

    with open(json_path, "w") as f:
        json.dump(inventory, f, indent=2)
    write_csv(inventory, csv_path)

    print(f"\n[+] Merged {inventory['asset_count']} assets")
    print(f"[*] Written {json_path} and {csv_path}")

    if args.html:
        generate_html_report(
            "merge_inventory", args.indir,
            inventory,
            args.html,
            summary=f"Merged {inventory['asset_count']} assets",
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        from html_report import generate_pdf_report
        generate_pdf_report(
            "merge_inventory", args.indir,
            inventory,
            args.pdf,
            summary=f"Merged {inventory['asset_count']} assets",
        )


if __name__ == "__main__":
    main()
