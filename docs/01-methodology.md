# Attack Surface Mapping Methodology

A phased approach, roughly following how most red teams and ASM platforms
structure external recon.

## Phase 1 — Scoping & seed collection
- Confirm authorized scope (root domains, IP ranges/ASNs, cloud accounts,
  brand names, known subsidiaries/M&A history).
- Pull seed data: WHOIS registrant orgs, ASN ownership, known domains.

## Phase 2 — Asset discovery (passive)
- **Subdomain enumeration**: certificate transparency logs, passive DNS,
  search engines, public datasets.
- **ASN / IP range mapping**: BGP data, WHOIS, cloud provider ranges.
- **Cloud & SaaS footprint**: S3/GCS/Azure blob bucket naming patterns,
  SaaS tenant discovery (e.g. exposed Jira/Confluence/Slack workspaces).
- **Code & document leakage**: GitHub/GitLab search, public Postman
  collections, exposed `.git` directories, paste sites, doc metadata.
- **People OSINT**: LinkedIn/org-chart mapping for social-engineering risk
  assessment (only if in scope — often excluded from bounty programs).
- **Breach & credential exposure**: check whether corporate email domains
  appear in known breach indexes (for awareness, not for credential reuse).

## Phase 3 — Asset discovery (active, authorized only)
- DNS resolution & reverse DNS sweep of discovered ranges.
- HTTP(S) probing of resolved hosts: status codes, titles, tech fingerprints,
  TLS certificate details.
- Port/service scanning of in-scope IPs (respect scope and rate limits).
- Screenshotting web assets for visual triage.

## Phase 4 — Enrichment & prioritization
- Technology fingerprinting (frameworks, CMS, server software, versions).
- Map assets to business units/criticality where possible.
- Flag anomalies: unexpected admin panels, staging/dev environments exposed
  publicly, forgotten legacy hosts, default credentials pages, verbose
  error pages, exposed API docs.

## Phase 5 — Exposure triage (not exploitation)
- Cross-reference fingerprinted software/versions against public CVE/advisory
  data to flag *candidates* for deeper authorized testing.
- Deliberately stop short of exploitation here — this phase produces a
  prioritized list to hand to the authorized testing phase, not a
  weaponized attack.

## Phase 6 — Reporting
- Inventory of assets found, grouped by confidence and source.
- Risk-ranked findings with remediation-oriented recommendations.
- Diagram of the discovered attack surface (org → domains → hosts → services).

## A simple mental model

```
Org identity  →  Domains/Subdomains  →  Hosts/IPs  →  Services/Ports
     │                  │                    │              │
  people/brand      DNS/cert data        ASN/WHOIS      banners/tech
     │                  │                    │              │
   OSINT leaks      leaked repos         cloud storage    exposed panels
```

Each column widens the map; each row is a different data source. Attack
surface management is the discipline of keeping this map current, since
external assets change constantly (new subdomains, expiring certs, shadow IT).
