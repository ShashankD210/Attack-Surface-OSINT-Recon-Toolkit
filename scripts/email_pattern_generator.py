#!/usr/bin/env python3
"""
email_pattern_generator.py — given a domain and a list of employee names,
generates the set of likely corporate email address candidates using
common naming conventions (first.last@, flast@, first@, etc.), and checks
whether the domain has MX records (i.e. actually receives mail).

This does NOT send email, verify mailbox existence via SMTP, or scrape
directories for names — it's a candidate-list generator only, meant for
the reconnaissance/prep phase of an AUTHORIZED phishing-simulation or
social-engineering risk assessment, where the employee list itself was
provided in scope (e.g. by the client) rather than harvested. If you need
actual name discovery, that should come from an explicitly authorized,
scoped data source (company directory, LinkedIn export the client
provided, etc.) — this script only handles the pattern-generation step.

Usage:
    python3 email_pattern_generator.py acme.com "Jane Doe" "John A. Smith"
    python3 email_pattern_generator.py acme.com --names-file names.txt --json out.json
"""
import argparse
import json
import re
import sys
from html_report import generate_html_report

try:
    import dns.resolver
except ImportError:
    dns = None

PATTERNS = [
    ("first.last", lambda f, l: f"{f}.{l}"),
    ("firstlast", lambda f, l: f"{f}{l}"),
    ("flast", lambda f, l: f"{f[0]}{l}"),
    ("first_last", lambda f, l: f"{f}_{l}"),
    ("first", lambda f, l: f"{f}"),
    ("last", lambda f, l: f"{l}"),
    ("last.first", lambda f, l: f"{l}.{f}"),
    ("lastf", lambda f, l: f"{l}{f[0]}"),
    ("first.l", lambda f, l: f"{f}.{l[0]}"),
]


def clean_name_part(part: str) -> str:
    return re.sub(r"[^a-z]", "", part.lower())


def split_name(full_name: str):
    parts = [p for p in full_name.strip().split() if p]
    if len(parts) < 2:
        return None, None
    first = clean_name_part(parts[0])
    last = clean_name_part(parts[-1])  # last token, skips middle names/initials
    if not first or not last:
        return None, None
    return first, last


def generate_candidates(domain: str, full_name: str):
    first, last = split_name(full_name)
    if not first or not last:
        return []
    candidates = []
    for pattern_name, fn in PATTERNS:
        local_part = fn(first, last)
        candidates.append({
            "name": full_name,
            "pattern": pattern_name,
            "email": f"{local_part}@{domain}",
        })
    return candidates


def check_mx(domain: str) -> list:
    if dns is None:
        return []
    try:
        answers = dns.resolver.Resolver().resolve(domain, "MX")
        return sorted(str(r.exchange).rstrip(".") for r in answers)
    except Exception:
        return []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("domain", help="Corporate domain, e.g. acme.com")
    parser.add_argument("names", nargs="*", help='Full names, e.g. "Jane Doe"')
    parser.add_argument("--names-file", help="Optional file with one full name per line")
    parser.add_argument("--pattern", help="Only generate this one pattern "
                         "(e.g. 'first.last'); default generates all patterns")
    parser.add_argument("--json", help="Optional path to write results as JSON")
    parser.add_argument("--html", help="Optional path to write HTML report")
    parser.add_argument("--pdf", help="Optional path to write PDF report")
    args = parser.parse_args()

    names = list(args.names)
    if args.names_file:
        with open(args.names_file) as f:
            names.extend(line.strip() for line in f if line.strip())

    if not names:
        print("[!] No names provided (positional args or --names-file)", file=sys.stderr)
        sys.exit(1)

    mx_records = check_mx(args.domain)
    if mx_records:
        print(f"[+] {args.domain} has MX records: {', '.join(mx_records)}")
    else:
        print(f"[!] No MX records found for {args.domain} — domain may not receive mail")

    all_candidates = []
    for name in names:
        candidates = generate_candidates(args.domain, name)
        if not candidates:
            print(f"[!] Skipping '{name}' — need at least a first and last name")
            continue
        if args.pattern:
            candidates = [c for c in candidates if c["pattern"] == args.pattern]
        all_candidates.extend(candidates)
        print(f"\n{name}:")
        for c in candidates:
            print(f"  [{c['pattern']:12}] {c['email']}")

    print(f"\n[+] Generated {len(all_candidates)} candidate address(es) for "
          f"{len(names)} name(s).")
    print("[i] These are unverified format guesses for an authorized "
          "phishing-simulation/OSINT prep step — not confirmed mailboxes.")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"domain": args.domain, "mx_records": mx_records,
                        "candidates": all_candidates}, f, indent=2)
        print(f"[*] Written to {args.json}")


    if args.html:
        generate_html_report(
            "email_pattern_generator", args.domain,
            {"domain": args.domain, "mx_records": mx_records, "candidates": all_candidates},
            args.html,
            summary=f"Generated {len(all_candidates)} candidate address(es) for {len(names)} name(s).",
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        from html_report import generate_pdf_report
        generate_pdf_report(
            "email_pattern_generator.py", args.domain,
            {"domain": args.domain, "mx_records": mx_records, "candidates": all_candidates},
            args.pdf,
            summary=f"Generated {len(all_candidates)} candidate address(es) for {len(names)} name(s).",
        )

if __name__ == "__main__":
    main()
