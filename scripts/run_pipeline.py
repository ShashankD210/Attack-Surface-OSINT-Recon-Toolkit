#!/usr/bin/env python3
"""
run_pipeline.py — single-command full recon pipeline.

Runs the passive + active recon stages, merges outputs into a normalized
inventory, and renders self-contained HTML and PDF reports for each scan
plus a merged dashboard.

Output structure:
    OUTDIR/
    ├── data/            - per-tool JSON outputs
    ├── inventory.json   - merged inventory
    ├── inventory.csv    - merged inventory CSV
    ├── report.html      - single combined HTML report
    └── report.pdf       - single combined PDF report

Usage:
    python3 scripts/run_pipeline.py example.com
    python3 scripts/run_pipeline.py example.com --out ./reports/run1
    python3 scripts/run_pipeline.py example.com --skip cloud_bucket_enum.py username_presence_check.py
    python3 scripts/run_pipeline.py example.com --no-pdf
"""
import argparse
import os
import subprocess
import sys

TOOLS = [
    ("crtsh_subdomains.py",       ["{domain}", "--json", "{out}/data/subdomains.json", "--txt", "{out}/data/subdomains.txt"]),
    ("whois_dns_recon.py",        ["{domain}", "--json", "{out}/data/whois_dns.json"]),
    ("wayback_urls.py",           ["{domain}", "--json", "{out}/data/wayback.json"]),
    ("ipinfo_asn_lookup.py",      ["{domain}", "--json", "{out}/data/asn.json"]),
    ("dns_zone_transfer_check.py",["{domain}"]),
    ("tech_fingerprint.py",       ["https://{domain}", "--json", "{out}/data/tech.json"]),
    ("cloud_bucket_enum.py",      ["{domain}", "--json", "{out}/data/buckets.json"]),
    ("ssl_cert_inspector.py",     ["{domain}", "--json", "{out}/data/certs.json"]),
    ("security_headers_check.py", ["https://{domain}", "--json", "{out}/data/headers.json"]),
    ("robots_sitemap_recon.py",   ["https://{domain}", "--json", "{out}/data/robots_sitemap.json"]),
    ("subdomain_takeover_check.py",["{out}/data/subdomains.txt", "--json", "{out}/data/takeover.json"]),
    ("username_presence_check.py",["{domain}", "--json", "{out}/data/handles.json"]),
    ("email_pattern_generator.py",["{domain}", "User User", "--json", "{out}/data/emails.json"]),
]


def username_for(domain: str) -> str:
    name = domain.split(":")[0] if "://" in domain else domain
    name = name.split("/")[0]
    if name.startswith("www."):
        name = name[4:]
    if "." in name:
        name = name.split(".")[0]
    return name


def run(cmd, cwd=None):
    print(f"[*] $ {' '.join(cmd)}")
    subprocess.run(cmd, cwd=cwd, check=True)


def main():
    parser = argparse.ArgumentParser(description="Run full recon pipeline")
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument("--out", default="reports", help="Output directory (default: reports)")
    parser.add_argument("--skip", nargs="*", default=[], help="Tool filenames to skip")
    parser.add_argument("--venv", default="scripts/venv", help="Venv path")
    parser.add_argument("--no-pdf", action="store_true", help="Skip PDF report generation")
    args = parser.parse_args()

    py = os.path.join(args.venv, "bin", "python")
    if not os.path.isfile(py):
        print(f"[!] Venv not found at {py}. Run 'make setup' first.")
        sys.exit(1)

    os.makedirs(args.out, exist_ok=True)
    os.makedirs(os.path.join(args.out, "data"), exist_ok=True)
    os.makedirs(os.path.join(args.out, "reports"), exist_ok=True)
    skip = set(args.skip)

    for tool, tmpl in TOOLS:
        if tool in skip:
            print(f"[i] Skipping {tool}")
            continue
        cmd = [py, os.path.join("scripts", tool)] + [
            arg.format(domain=args.domain, out=args.out) if tool != "username_presence_check.py"
            else username_for(args.domain) if arg == "{domain}"
            else arg.format(domain=args.domain, out=args.out)
            for arg in tmpl
        ]
        try:
            run(cmd)
        except subprocess.CalledProcessError as e:
            print(f"[!] {tool} failed with exit code {e.returncode}")

    merge = [py, "scripts/merge_inventory.py", f"{args.out}/", "--out", f"{args.out}/reports/inventory"]
    dash = [py, "scripts/generate_dashboard.py", f"{args.out}/reports/inventory.json", "--out", f"{args.out}/reports/report.html"]

    try:
        run(merge)
    except subprocess.CalledProcessError as e:
        print(f"[!] merge_inventory.py failed with exit code {e.returncode}")
        sys.exit(e.returncode)

    try:
        run(dash)
    except subprocess.CalledProcessError as e:
        print(f"[!] generate_dashboard.py failed with exit code {e.returncode}")
        sys.exit(e.returncode)

    if not args.no_pdf:
        single_pdf = [py, "scripts/generate_single_pdf.py", args.out, "--out", f"{args.out}/reports/report.pdf"]
        try:
            run(single_pdf)
        except subprocess.CalledProcessError as e:
            print(f"[!] generate_single_pdf.py failed with exit code {e.returncode}")

    print(f"\n[+] Pipeline complete.")
    print(f"    Data      : {args.out}/data/")
    print(f"    Reports   : {args.out}/reports/")
    print(f"    HTML      : {args.out}/reports/report.html")
    if not args.no_pdf:
        print(f"    PDF       : {args.out}/reports/report.pdf")


if __name__ == "__main__":
    main()
