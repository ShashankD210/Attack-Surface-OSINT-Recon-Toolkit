# Attack Surface & OSINT Recon Toolkit

A structured toolkit for mapping an organization's external attack surface using
open-source intelligence (OSINT) and passive/active reconnaissance techniques.
Built for authorized red-team engagements, bug bounty research, internal
attack surface management (ASM), and hands-on learning.

## ⚠️ Read this first

**Only run active scans (ports, web probing, vuln templates) against assets you
own or have explicit written authorization to test.** Passive OSINT (WHOIS,
certificate transparency, public search, breach-index lookups) is generally
lower-risk but can still violate ToS on some platforms — check before
automating queries at scale. See `docs/00-legal-and-ethics.md`.

## Structure

```
attack-surface-toolkit/
├── ast                       - single CLI entry point (use this)
├── README.md
├── Makefile                  - setup, run, test, clean targets
├── pyproject.toml            - package metadata & dependencies
├── .gitignore
├── docs/
│   ├── 00-legal-and-ethics.md   - scope, authorization, rules of engagement
│   ├── 01-methodology.md        - recon phases & attack surface model
│   ├── 02-tool-catalog.md       - curated tools by category, with notes
│   └── 03-workflow-checklist.md - step-by-step engagement checklist
└── scripts/
    ├── requirements.txt
    ├── run_pipeline.py        - single-command full recon pipeline
    ├── generate_dashboard.py  - renders inventory as a single HTML report
    ├── generate_single_pdf.py - renders inventory as a single PDF report
    ├── merge_inventory.py     - merges all per-tool JSON output into one inventory
    ├── html_report.py         - shared HTML/PDF report generator
    ├── whois_dns_recon.py        - WHOIS + DNS record enumeration
    ├── crtsh_subdomains.py       - subdomain discovery via cert transparency
    ├── wayback_urls.py           - historical URL discovery via Wayback Machine CDX
    ├── shodan_search.py          - exposed-service search via Shodan API
    ├── ipinfo_asn_lookup.py      - ASN / org / geolocation lookup for a host
    ├── dns_zone_transfer_check.py- AXFR zone-transfer misconfiguration test
    ├── subdomain_takeover_check.py- dangling-CNAME subdomain takeover check
    ├── ssl_cert_inspector.py     - TLS certificate SANs, issuer, expiry
    ├── security_headers_check.py - HTTP security header presence/grading
    ├── robots_sitemap_recon.py   - robots.txt / sitemap.xml hidden-path recon
    ├── tech_fingerprint.py       - lightweight web technology fingerprinting
    ├── cloud_bucket_enum.py      - S3/GCS/Azure bucket exposure checks (read-only)
    ├── github_dork_recon.py      - GitHub code-search dork URL generator
    ├── search_dork_generator.py  - Google/Bing/DuckDuckGo + paste-site dork URLs
    ├── username_presence_check.py- brand/handle presence check across platforms
    ├── email_pattern_generator.py- candidate email-address generator (phishing-sim prep)
    └── recon_orchestrator.sh     - chains external CLI recon tools, if installed
```

## Quick start

This toolkit requires a virtual environment on externally-managed Python
installations (e.g. Debian/Ubuntu with PEP 668). The `scripts/venv` created
below isolates dependencies cleanly:

```bash
make setup

# Run full pipeline — produces one report.html + report.pdf
ast run-pipeline example.com

# Or use the Makefile shortcut
make run DOMAIN=example.com
```

> **Note:** `crtsh_subdomains.py` queries crt.sh, which occasionally returns 502s.
> The script retries and exits cleanly with 0 results if the service is unavailable.

## Distribution

The entire toolkit source compresses to a single archive under 25MB:

```bash
make dist
# Creates: /tmp/attack-surface-toolkit-dist.tar.gz (~42KB)
```

Large scan outputs (especially Wayback Machine URLs) are automatically
gzip-compressed to save disk space. The `merge_inventory.py` and
`generate_single_pdf.py` scripts transparently read both plain `.json`
and `.json.gz` files.

The scripts wrap **passive/public data sources** (plus a couple of narrowly-
scoped, read-only active checks) and are meant as a scaffold you extend, not
a finished offensive platform. `recon_orchestrator.sh` shows how to chain
well-known external CLI tools (subfinder, httpx, nuclei, etc.) *if you
already have them installed* — it doesn't bundle or install anything that
performs exploitation.

## CLI entry point

The `ast` command is a single executable wrapper around all tools. It
automatically uses the toolkit's virtual environment, so you don't need to
activate it manually.

If `ast` is not found, add it to your PATH:

```bash
ln -sf /path/to/attack-surface-toolkit/ast ~/.local/bin/ast
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

```bash
# Show help
ast --help

# Pipeline commands
ast run-pipeline example.com --out reports
ast run-quick example.com
ast run-no-pdf example.com

# Individual tools
ast whois example.com
ast crtsh example.com
ast asn example.com
ast ssl example.com
ast headers https://example.com
ast tech https://example.com
ast buckets examplecorp
ast handles dermavilla
ast emails example.com "Jane Doe"
ast merge reports/ --out reports/inventory
ast dashboard reports/inventory.json --out report.html
ast single-pdf reports/ --out report.pdf
```

## Full pipeline: single report output

The pipeline runs all scans, merges the data, and produces **one HTML report**
and **one PDF report** containing every section:

```bash
make run DOMAIN=example.com
```

Output structure:
```
reports/
├── data/                - raw JSON outputs from each scan
├── inventory.json       - merged asset inventory
├── inventory.csv        - merged asset inventory (CSV)
├── report.html          - single combined HTML report
└── report.pdf           - single combined PDF report
```

For a faster run that skips slow active checks:

```bash
make run-quick DOMAIN=example.com
```

To skip PDF generation and only produce the HTML report:

```bash
make run-no-pdf DOMAIN=example.com
```

Or run individual stages manually:

```bash
mkdir -p reports/data

python3 scripts/crtsh_subdomains.py example.com --json reports/data/subdomains.json --txt reports/data/subdomains.txt
python3 scripts/whois_dns_recon.py example.com --json reports/data/whois_dns.json
python3 scripts/wayback_urls.py example.com --json reports/data/wayback.json

export SHODAN_API_KEY=your_key_here
python3 scripts/shodan_search.py example.com --json reports/data/shodan.json

python3 scripts/ipinfo_asn_lookup.py example.com --json reports/data/asn.json
python3 scripts/dns_zone_transfer_check.py example.com
python3 scripts/tech_fingerprint.py https://example.com --json reports/data/tech.json
python3 scripts/cloud_bucket_enum.py examplecorp --json reports/data/buckets.json
python3 scripts/ssl_cert_inspector.py example.com --json reports/data/certs.json
python3 scripts/security_headers_check.py https://example.com --json reports/data/headers.json
python3 scripts/robots_sitemap_recon.py https://example.com --json reports/data/robots_sitemap.json
python3 scripts/subdomain_takeover_check.py reports/data/subdomains.txt --json reports/data/takeover.json

# Manual-review OSINT (open the printed URLs yourself)
python3 scripts/search_dork_generator.py "Example Corp" example.com
python3 scripts/github_dork_recon.py "Example Corp" example.com
python3 scripts/username_presence_check.py examplecorp --json reports/data/handles.json

# Phishing-simulation prep (client-provided employee list only)
python3 scripts/email_pattern_generator.py example.com "Jane Doe" --json reports/data/emails.json

# Merge into one inventory
python3 scripts/merge_inventory.py reports/ --out reports/reports/inventory

# Generate single HTML report
python3 scripts/generate_dashboard.py reports/reports/inventory.json --out reports/reports/report.html

# Generate single PDF report
python3 scripts/generate_single_pdf.py reports --out reports/reports/report.pdf
```

> **Notes:**
> - `cloud_bucket_enum.py` checks 19 name permutations × N providers with a
>   default 0.3s delay. For faster runs, limit providers: `--providers aws_s3`.
> - `merge_inventory.py` `--out` takes a path *prefix*; it appends `.json` and
>   `.csv` automatically. Use `--out reports/inventory`, not `--out reports/inventory.json`.
> - `github_dork_recon.py` requires both an org name and a domain:
>   `python3 github_dork_recon.py "Acme Corp" acme.com`.
> - Every scan resolves the target domain to its IP address where applicable
>   (WHOIS, DNS, SSL, headers, tech fingerprint, etc.), so each command covers
>   both the URL/hostname and its underlying IP.

`merge_inventory.py` picks up whichever of the 13 supported JSON files are
present in the given directory — you don't need to run every source.
`generate_dashboard.py` produces a single self-contained HTML file (no CDN
dependencies) with summary counts, a type/source breakdown, and a
filterable asset table — safe to open offline or attach to a report.
`generate_single_pdf.py` converts that same content into a single PDF.

`run_pipeline.py` automates the full chain above into one command:

```bash
make run DOMAIN=example.com
```

This produces `reports/reports/report.html` and `reports/reports/report.pdf` plus the raw
`reports/data/` JSON files and merged `reports/reports/inventory.json`.

For a faster run that skips slow active checks:

```bash
make run-quick DOMAIN=example.com
```

To run without PDF generation:

```bash
make run-no-pdf DOMAIN=example.com
```

`recon_orchestrator.sh` chains external CLI tools (subfinder, dnsx, httpx)
*if you already have them installed*:

```bash
bash scripts/recon_orchestrator.sh example.com ./recon_output
```

`cloud_bucket_enum.py`, `dns_zone_transfer_check.py`,
`subdomain_takeover_check.py`, `ssl_cert_inspector.py`,
`security_headers_check.py`, and `robots_sitemap_recon.py` all make live,
read-only requests to the target's own infrastructure or cloud provider
endpoints — treat these as **active** recon steps (see
`docs/00-legal-and-ethics.md`) and only run them against names/orgs you're
authorized to assess. `search_dork_generator.py`, `github_dork_recon.py`,
and `email_pattern_generator.py` are OSINT/prep aids that don't contact
the target at all — the first two only build search URLs (no scraping),
and the email generator only produces unverified format guesses from a
client-supplied name list (no sending, no SMTP verification).
`username_presence_check.py` checks a handle's presence via normal
profile-page requests to third-party platforms — respect each platform's
Terms of Service.
