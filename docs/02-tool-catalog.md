# Tool Catalog

Curated by category. "Passive" sources rely on public/third-party data;
"active" tools make direct contact with target infrastructure and require
authorization.

## Subdomain & DNS enumeration (mostly passive)
- **subfinder** (ProjectDiscovery) — aggregates passive sources.
- **amass** (OWASP) — passive + active enumeration, graph-based.
- **crt.sh / Censys / Certificate Transparency** — cert-log based subdomain discovery.
- **dnsx** (ProjectDiscovery) — fast DNS resolution/validation of candidate lists.
- **SecurityTrails, VirusTotal, PassiveTotal** — passive DNS history (API/paid tiers vary).
- **DNSDumpster** — free web-based passive recon, visual domain map.
- **assetfinder, findomain** — additional passive subdomain aggregators.

## Historical & archived content
- **Wayback Machine (web.archive.org)** — `scripts/wayback_urls.py` in this
  toolkit queries the CDX API for every historically-crawled URL under a
  domain and flags likely-sensitive paths (`.env`, `.sql`, `/admin/`,
  `/staging/`, etc.) — the same technique as the popular `waybackurls`/`gau`
  tools.
- **CachedView, Google Cache** — manual spot-checks of specific pages.

## Host & service discovery (active — authorized targets only)
- **nmap / masscan** — port scanning.
- **naabu** (ProjectDiscovery) — fast port scanner, often chained before httpx.
- **httpx** (ProjectDiscovery) — HTTP probing, tech/title/status fingerprinting.
- **Shodan / Censys** — internet-wide scan data lookup (passive from your side —
  you query *their* prior scans rather than scanning the target yourself).

## Network / ASN / geolocation
- **ipinfo.io, RIPEstat, bgp.he.net** — ASN ownership, IP-to-org mapping,
  rough geolocation. `scripts/ipinfo_asn_lookup.py` in this toolkit wraps
  ipinfo.io + RDAP (rdap.org) for a quick per-host lookup.
- **RDAP / WHOIS on IP ranges** — confirms which network block a discovered
  IP actually belongs to (useful for scoping cloud vs. on-prem vs. CDN).

## DNS misconfiguration checks (active, low-impact)
- **AXFR zone transfer test** — `scripts/dns_zone_transfer_check.py` in this
  toolkit tests whether any authoritative nameserver allows an
  unauthenticated zone transfer (equivalent to `dig axfr @ns1.target.com
  target.com`), a classic misconfiguration that leaks the entire DNS zone.
- **dnsrecon, fierce** — broader DNS misconfiguration/brute-force tooling.

## Web technology fingerprinting
- **Wappalyzer / whatweb** — identify CMS, frameworks, JS libraries, server software.
- **httpx -tech-detect** — combined probing + fingerprinting.
- `scripts/tech_fingerprint.py` in this toolkit does a lightweight version
  with no external dependency — inspects headers, meta generator tags, and
  script/asset patterns for common CMS/framework/CDN signatures.

## Subdomain takeover risk
- **Can I Take Over XYZ (fingerprint list)** — the reference list of
  dangling-CNAME signatures across dozens of third-party services.
- `scripts/subdomain_takeover_check.py` in this toolkit checks a list of
  subdomains for CNAMEs pointing at known services (GitHub Pages, Heroku,
  S3, Azure, Shopify, WordPress.com, Fastly, Ghost, Surge, Bitbucket,
  Unbounce, WPEngine, Zendesk) and flags likely-unclaimed resources.

## TLS certificate inspection
- `scripts/ssl_cert_inspector.py` in this toolkit connects directly to a
  host and pulls issuer, validity window, and all Subject Alternative
  Names (SANs) — SANs often reveal subdomains that were never logged to
  public CT (internal certs, wildcard certs), complementing crt.sh.
- Also flags certificates expiring within 30 days.

## HTTP security posture
- **securityheaders.com** — the reference online scanner for this check.
- `scripts/security_headers_check.py` in this toolkit does the same check
  locally: HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy, plus a cookie Secure-flag check.

## robots.txt / sitemap.xml recon
- `scripts/robots_sitemap_recon.py` in this toolkit fetches robots.txt and
  any referenced sitemap(s), extracts every Disallow rule and sitemap URL,
  and flags entries matching admin/internal/staging/debug/config patterns
  — site owners routinely reveal sensitive paths this way.

## Cloud & storage exposure
- **cloud_enum, S3Scanner** — bucket name permutation + public-access checks.
- `scripts/cloud_bucket_enum.py` in this toolkit does the same thing for
  S3, GCS, and Azure Blob: permutes a base name against common suffixes,
  issues read-only requests, and flags buckets that exist and/or are
  publicly listable.
- Manual: check DNS CNAMEs pointing at cloud providers for dangling/subdomain
  takeover risk.

## Code & secret leakage OSINT
- **GitHub/GitLab code search** — org name + keyword dorking (see
  `scripts/github_dork_recon.py` and the broader `scripts/search_dork_generator.py`).
- **gitleaks / trufflehog** — run against *your own* repos to find secrets
  before they leak, or against explicitly authorized targets.
- **Public Postman/Swagger/OpenAPI discovery** — search engines + GitHub for
  exposed API documentation.

## Search-engine & paste-site OSINT
- **Google/Bing/DuckDuckGo dorking** — `scripts/search_dork_generator.py`
  builds targeted queries for exposed documents, login portals, directory
  listings, error pages, and config/backup files, across all three engines.
- **Pastebin and similar paste sites** — the same script builds site-scoped
  search queries for organization/domain mentions on paste sites (via
  search engines, not by scraping the paste sites directly).

## Breach & credential exposure awareness
- **Have I Been Pwned (HIBP) API** — check if corporate domains/emails
  appear in known breaches (domain search requires domain verification).
- **DeHashed, Intelligence X** — broader breach/paste-index search (paid/API-key tiers).

## People / org / brand OSINT (only if explicitly in scope)
- LinkedIn org search, company filings, press releases — used to understand
  social engineering risk and org structure, not to target individuals
  without authorization.
- **Username/handle presence checks** (Sherlock/WhatsMyName-style) —
  `scripts/username_presence_check.py` checks a handle against a curated
  set of mainstream platforms, mainly useful for confirming an
  organization's real brand accounts vs. spotting impersonation accounts.
  Not intended for building dossiers on private individuals.
- **Email pattern generation** — `scripts/email_pattern_generator.py` in
  this toolkit generates likely corporate email-address candidates
  (first.last@, flast@, etc.) from a client-provided employee list, for
  the prep phase of an authorized phishing-simulation engagement. It does
  not harvest names or verify mailboxes — the name list must come from an
  explicitly in-scope source (e.g. supplied by the client), and no email
  is sent or SMTP-verified.

## Broader OSINT frameworks (orchestrate many of the above)
- **theHarvester** — aggregates emails, subdomains, hosts, and employee
  names from search engines and public sources in one run.
- **SpiderFoot** — automated OSINT correlation engine with 200+ data-source
  modules; runs locally or as a hosted service.
- **Recon-ng** — modular recon framework, similar workflow philosophy to
  Metasploit but for OSINT collection.
- **Maltego (Community Edition)** — link-analysis graphing of OSINT
  relationships across many data sources.
- **PhoneInfoga** — OSINT on phone numbers (carrier, line type, possible
  associated accounts) — only for numbers explicitly in scope.

## Vulnerability correlation (triage, not exploitation)
- **nuclei** (ProjectDiscovery) — template-based scanning; many templates are
  detection-only (version/banner checks), some are active checks — review
  templates before running and only against authorized scope.
- **CVE/NVD, vendor advisories** — cross-reference fingerprinted versions.

## Reporting, inventory & visualization
- **Maltego** — link-analysis graphing of OSINT relationships.
- Simple alternative: feed discovered assets into a spreadsheet or graph
  (e.g. via `networkx` + `matplotlib`, or Neo4j for larger engagements).
- `scripts/merge_inventory.py` in this toolkit normalizes and merges the
  JSON output of the other scripts into one asset inventory (JSON + CSV).
- `scripts/generate_dashboard.py` renders that inventory as a single
  offline HTML dashboard (summary counts, type/source breakdown, filterable
  table) for quick triage or attaching to a report.

---

### Notes
- Many of the above are CLI tools you install separately (Go-based tools from
  ProjectDiscovery/OWASP are common in this space). This toolkit's scripts
  either call public APIs directly in Python, or show how to orchestrate
  these external tools if you already have them installed — it does not
  bundle scanning/exploitation binaries.
- This list intentionally excludes exploitation frameworks, password
  cracking, and phishing/social-engineering tooling — those require separate,
  even more tightly scoped authorization and are outside what's covered here.
