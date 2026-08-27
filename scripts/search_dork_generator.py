#!/usr/bin/env python3
"""
search_dork_generator.py — generates targeted search-engine and paste-site
"dork" URLs for manual review, covering Google, Bing, DuckDuckGo, and
common paste sites, in addition to GitHub code search. This is a standard
OSINT technique for finding exposed documents, login portals, error pages,
and accidentally-indexed internal content tied to an organization.

This script does NOT scrape search results or automate query submission —
it only builds URLs for a human analyst to open and review, respecting
each search engine's ToS around automated querying.

Usage:
    python3 search_dork_generator.py "Acme Corp" acme.com
"""
import argparse
import urllib.parse
from html_report import generate_html_report

# Generic, non-exploitative themes: exposed docs, login portals, error
# pages, indexed internal tools, accidental public exposure.
DORK_THEMES = [
    ('Exposed documents', 'site:{domain} filetype:pdf OR filetype:xlsx OR filetype:docx'),
    ('Login/admin portals', 'site:{domain} inurl:login OR inurl:admin OR inurl:portal'),
    ('Directory listings', 'site:{domain} intitle:"index of"'),
    ('Error pages / stack traces', 'site:{domain} "internal server error" OR "stack trace" OR "sql syntax"'),
    ('Config/backup files', 'site:{domain} ext:env OR ext:bak OR ext:config OR ext:sql'),
    ('Exposed API docs', 'site:{domain} inurl:swagger OR inurl:api-docs OR inurl:graphql'),
    ('Subdomains indexed', 'site:*.{domain} -www'),
    ('Org mentions off-site', '"{org}" -site:{domain}'),
]

SEARCH_ENGINES = {
    "Google": "https://www.google.com/search?q={q}",
    "Bing": "https://www.bing.com/search?q={q}",
    "DuckDuckGo": "https://duckduckgo.com/?q={q}",
}

PASTE_SITE_QUERIES = [
    ('Pastebin mentions', '"{domain}"', "https://www.google.com/search?q=site:pastebin.com+%22{domain_enc}%22"),
    ('Org name on paste sites', '"{org}"', "https://www.google.com/search?q=(site:pastebin.com+OR+site:ghostbin.com+OR+site:paste.ee)+%22{org_enc}%22"),
]


def build_engine_urls(org: str, domain: str):
    rows = []
    for theme, template in DORK_THEMES:
        query = template.format(org=org, domain=domain)
        encoded = urllib.parse.quote(query)
        for engine, url_template in SEARCH_ENGINES.items():
            rows.append((theme, engine, query, url_template.format(q=encoded)))
    return rows


def build_paste_urls(org: str, domain: str):
    rows = []
    for label, _query_display, url_template in PASTE_SITE_QUERIES:
        url = url_template.format(
            domain=domain, domain_enc=urllib.parse.quote(domain),
            org=org, org_enc=urllib.parse.quote(org),
        )
        rows.append((label, url))
    return rows


def build_github_urls(org: str, domain: str):
    templates = [
        '"{org}" password', '"{org}" api_key', '"{org}" secret',
        '"{domain}" filename:.env', '"{domain}" filename:config',
        '"{domain}" extension:pem',
    ]
    rows = []
    for template in templates:
        query = template.format(org=org, domain=domain)
        encoded = urllib.parse.quote(query)
        rows.append((query, f"https://github.com/search?q={encoded}&type=code"))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("org", help='Organization name, e.g. "Acme Corp"')
    parser.add_argument("domain", help="Primary domain, e.g. acme.com")
    parser.add_argument("--html", help="Optional path to write HTML report")
    parser.add_argument("--pdf", help="Optional path to write PDF report")
    args = parser.parse_args()

    print(f"=== Search-engine dorks for org='{args.org}', domain='{args.domain}' ===\n")
    for theme, engine, query, url in build_engine_urls(args.org, args.domain):
        print(f"[{engine}] {theme}\n  query: {query}\n  -> {url}\n")

    print("=== Paste-site review queries ===\n")
    for label, url in build_paste_urls(args.org, args.domain):
        print(f"{label}\n  -> {url}\n")

    print("=== GitHub code-search review queries ===\n")
    for query, url in build_github_urls(args.org, args.domain):
        print(f"{query}\n  -> {url}\n")

    print("[i] Open these manually and review results by hand — search engines "
          "and paste sites rate-limit and restrict automated scraping.")


    if args.html:
        engine_rows = build_engine_urls(args.org, args.domain)
        paste_rows = build_paste_urls(args.org, args.domain)
        github_rows = build_github_urls(args.org, args.domain)
        generate_html_report(
            "search_dork_generator", args.domain,
            {
                "org": args.org,
                "domain": args.domain,
                "engine_queries": [(t, e, q, u) for t, e, q, u in engine_rows],
                "paste_queries": paste_rows,
                "github_queries": github_rows,
            },
            args.html,
            summary=f"{len(engine_rows)} engine dorks, {len(paste_rows)} paste queries, {len(github_rows)} GitHub queries",
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        from html_report import generate_pdf_report
        generate_pdf_report(
            "search_dork_generator.py", args.domain,
            {"org": args.org, "domain": args.domain, "engine_queries": [(t, e, q, u) for t, e, q, u in build_engine_urls(args.org, args.domain)], "paste_queries": build_paste_urls(args.org, args.domain), "github_queries": build_github_urls(args.org, args.domain)},
            args.pdf,
            summary=f"{len(build_engine_urls(args.org, args.domain))} engine dorks, {len(build_paste_urls(args.org, args.domain))} paste queries, {len(build_github_urls(args.org, args.domain))} GitHub queries",
        )

if __name__ == "__main__":
    main()
