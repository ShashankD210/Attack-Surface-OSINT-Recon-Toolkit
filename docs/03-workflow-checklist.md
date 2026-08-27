# Engagement Checklist

## Pre-engagement
- [ ] Signed scope / rules of engagement obtained
- [ ] In-scope domains, IP ranges, cloud accounts documented
- [ ] Out-of-scope exclusions documented (third parties, shared infra)
- [ ] Emergency contact for the target org identified
- [ ] Logging plan in place (what you'll run, when, from what source IP)

## Passive recon
- [ ] WHOIS + registrar history pulled
- [ ] Subdomains enumerated via cert transparency / passive DNS
- [ ] ASN / IP ranges mapped
- [ ] GitHub/GitLab org search for leaked secrets or internal references
- [ ] Cloud storage bucket naming patterns checked (read-only public checks)
- [ ] Breach-index domain check (HIBP or similar)

## Active recon (only within authorized scope)
- [ ] DNS resolution of all candidate subdomains
- [ ] HTTP(S) probing + tech fingerprinting of live hosts
- [ ] Port/service scan of in-scope IP ranges
- [ ] Screenshots captured for visual triage
- [ ] TLS certificate inventory pulled

## Enrichment
- [ ] Assets mapped to business unit / criticality where possible
- [ ] Technology stack versions catalogued
- [ ] Anomalies flagged (staging exposed, admin panels, verbose errors)

## Reporting
- [ ] Asset inventory delivered (spreadsheet/graph)
- [ ] Findings risk-ranked with remediation notes
- [ ] Raw tool output archived for reproducibility
- [ ] Retest / follow-up date scheduled if applicable
