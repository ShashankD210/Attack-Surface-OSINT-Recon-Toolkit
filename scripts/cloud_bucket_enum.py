#!/usr/bin/env python3
"""
cloud_bucket_enum.py — checks whether permutations of a name resolve to
publicly-accessible cloud storage buckets (AWS S3, Google Cloud Storage,
Azure Blob). Read-only: issues HTTP GET/HEAD requests only, never writes,
deletes, or modifies anything. This is the same class of check used by
tools like S3Scanner and is a standard part of external ASM.

Because this makes live HTTP requests to cloud provider endpoints, treat it
as an ACTIVE recon step — only run it against names/orgs you're authorized
to assess, and be mindful of the cloud providers' own rate limits/ToS.

Usage:
    python3 cloud_bucket_enum.py acme
    python3 cloud_bucket_enum.py acme --words prod,dev,backup,staging
    python3 cloud_bucket_enum.py acme --json out.json
"""
import argparse
import json
import sys
import time
import requests
from html_report import generate_html_report

DEFAULT_SUFFIXES = [
    "", "-prod", "-dev", "-staging", "-test", "-backup", "-backups",
    "-data", "-assets", "-media", "-files", "-uploads", "-logs",
    "-internal", "-private", "-public", "-www", "-static", "-cdn",
]

PROVIDERS = {
    "aws_s3": {
        "url": "https://{bucket}.s3.amazonaws.com/",
        "exists_codes": {200, 403},   # 403 = exists but access denied; 200 = public listing
        "public_codes": {200},
    },
    "gcs": {
        "url": "https://storage.googleapis.com/{bucket}/",
        "exists_codes": {200, 403},
        "public_codes": {200},
    },
    "azure_blob": {
        # Azure requires a known storage account name; this checks the
        # storage account host directly (container listing needs a container
        # name too — left as a documented next step, not automated further).
        "url": "https://{bucket}.blob.core.windows.net/?comp=list",
        "exists_codes": {200, 403, 400},
        "public_codes": {200},
    },
}


def candidate_names(base: str, extra_words):
    names = set()
    for suffix in DEFAULT_SUFFIXES:
        names.add(f"{base}{suffix}")
    for word in extra_words:
        word = word.strip()
        if not word:
            continue
        names.add(f"{base}-{word}")
        names.add(f"{word}-{base}")
    return sorted(names)


def check_bucket(provider: str, bucket: str, timeout: int = 8):
    cfg = PROVIDERS[provider]
    url = cfg["url"].format(bucket=bucket)
    try:
        resp = requests.get(url, timeout=timeout,
                             headers={"User-Agent": "attack-surface-toolkit/1.0"})
    except requests.RequestException:
        return None

    if resp.status_code not in cfg["exists_codes"]:
        return None

    return {
        "provider": provider,
        "bucket": bucket,
        "url": url,
        "status_code": resp.status_code,
        "publicly_listable": resp.status_code in cfg["public_codes"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", help="Base name to permute, e.g. company name")
    parser.add_argument("--words", default="",
                         help="Comma-separated extra words to combine with base")
    parser.add_argument("--providers", default="aws_s3,gcs,azure_blob",
                         help="Comma-separated providers to check "
                              "(aws_s3, gcs, azure_blob)")
    parser.add_argument("--delay", type=float, default=0.3,
                         help="Delay between requests in seconds (default 0.3)")
    parser.add_argument("--json", help="Optional path to write results as JSON")
    parser.add_argument("--html", help="Optional path to write HTML report")
    parser.add_argument("--pdf", help="Optional path to write PDF report")
    args = parser.parse_args()

    extra_words = args.words.split(",") if args.words else []
    providers = [p.strip() for p in args.providers.split(",") if p.strip()]
    names = candidate_names(args.base, extra_words)

    print(f"[*] Checking {len(names)} name permutations across "
          f"{len(providers)} provider(s) ({len(names) * len(providers)} requests)")
    print("[!] Active checks against live cloud endpoints — only run against "
          "names/orgs you're authorized to assess.\n")

    findings = []
    for name in names:
        for provider in providers:
            if provider not in PROVIDERS:
                continue
            result = check_bucket(provider, name)
            if result:
                tag = "PUBLIC" if result["publicly_listable"] else "exists (access denied)"
                print(f"[+] {provider:10} {name:30} -> {tag} ({result['url']})")
                findings.append(result)
            time.sleep(args.delay)

    print(f"\n[+] Done. {len(findings)} bucket(s) found to exist.")
    public_count = sum(1 for f in findings if f["publicly_listable"])
    if public_count:
        print(f"[!] {public_count} appear PUBLICLY LISTABLE — flag for immediate review.")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(findings, f, indent=2)
        print(f"[*] Written to {args.json}")


    if args.html:
        generate_html_report(
            "cloud_bucket_enum", args.base,
            {
                "base": args.base,
                "providers": providers,
                "findings": findings,
                "public_count": public_count,
            },
            args.html,
            summary=f"{len(findings)} bucket(s) found to exist, {public_count} publicly listable",
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        from html_report import generate_pdf_report
        generate_pdf_report(
            "cloud_bucket_enum.py", args.base,
            {"base": args.base, "providers": providers, "findings": findings, "public_count": public_count},
            args.pdf,
            summary=f"{len(findings)} bucket(s) found to exist, {public_count} publicly listable",
        )

if __name__ == "__main__":
    main()
