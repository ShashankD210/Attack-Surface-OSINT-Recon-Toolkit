# Legal & Ethical Baseline

Attack surface mapping sits on a spectrum from purely passive OSINT to active
scanning. Treat authorization as the line that determines what you're allowed
to do at each step.

## Before you start

- **Get it in writing.** A signed scope document / rules of engagement (RoE)
  should list in-scope domains, IP ranges, cloud accounts, and any explicitly
  out-of-scope systems (third parties, shared hosting, partners).
- **Know your legal exposure.** Unauthorized scanning or access can trigger
  laws like the U.S. CFAA, UK Computer Misuse Act, or local equivalents —
  even "just recon" active probing (port scans, directory brute-forcing)
  against systems you don't own or have permission to test is risky.
- **Bug bounty programs**: read the program's policy carefully. Most restrict
  automated scanning volume, disallow social engineering / physical attacks,
  and require using program-issued identifiers in traffic.
- **Third-party data sources**: services like Shodan, Censys, crt.sh, and
  GitHub have their own ToS and rate limits — respect them even though the
  underlying data is public.

## Passive vs. active recon

| Category | Examples | Typical risk |
|---|---|---|
| Passive (public data, no contact with target infra) | WHOIS, cert transparency, DNS history, search engine dorking, breach-index lookups, social media OSINT | Low — but check ToS of the data source |
| Active, low-impact | DNS resolution, TLS handshake/banner grab, HTTP probing | Medium — leaves logs on target infra, needs authorization |
| Active, higher-impact | Port scanning, directory brute-force, vulnerability scanning, exploitation | High — requires explicit written authorization |

## Rules of thumb

1. If you didn't get permission and it isn't public data, don't touch it.
2. Log what you run, when, and against what scope — you'll need it for the
   report and if anything is questioned.
3. Rate-limit and time-box active scans; don't hammer production infrastructure.
4. Report findings responsibly — coordinate disclosure timelines with the
   asset owner.
