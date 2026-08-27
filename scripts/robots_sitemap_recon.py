#!/usr/bin/env python3
"""
robots_sitemap_recon.py — fetches /robots.txt and /sitemap.xml (recursively
following sitemap indexes into their child sitemaps) and extracts every
disallowed path and listed page URL. Site owners often unintentionally
reveal admin panels, staging areas, or internal tools in robots.txt
Disallow rules — a well-known, still-common real recon technique.

ACTIVE (low-impact): two or a few normal HTTP GET requests, the same as a
browser or search-engine crawler would make.

Usage:
    python3 robots_sitemap_recon.py https://example.com
    python3 robots_sitemap_recon.py https://example.com --json out.json
"""
import argparse
import json
import re
import xml.etree.ElementTree as ET
import requests
from html_report import generate_html_report

INTERESTING_PATTERN = re.compile(
    r"admin|internal|staging|dev|test|backup|private|debug|config|"
    r"\.git|\.env|api/v[0-9]+|swagger",
    re.IGNORECASE,
)


def fetch(url: str, timeout: int = 15):
    try:
        resp = requests.get(url, timeout=timeout,
                             headers={"User-Agent": "attack-surface-toolkit/1.0"})
        if resp.status_code == 200:
            return resp.text
    except requests.RequestException:
        pass
    return None


def parse_robots(text: str):
    disallow = []
    sitemaps = []
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                disallow.append(path)
        elif line.lower().startswith("sitemap:"):
            sitemaps.append(line.split(":", 1)[1].strip())
    return disallow, sitemaps


def parse_sitemap(text: str):
    """Returns (kind, urls) where kind is 'index' (child sitemaps) or
    'urlset' (actual page URLs), based on the root element."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return "urlset", []

    root_tag = root.tag.split("}")[-1]
    urls = []
    for elem in root.iter():
        tag = elem.tag.split("}")[-1]
        if tag == "loc" and elem.text:
            urls.append(elem.text.strip())

    kind = "index" if root_tag == "sitemapindex" else "urlset"
    return kind, urls


def collect_sitemap_entries(sitemap_urls, max_child_sitemaps: int = 20):
    """Fetches each sitemap URL; if it's a sitemap INDEX (a sitemap of
    sitemaps, common on larger sites), recursively fetches the child
    sitemaps too so the real page URLs are actually collected, not just
    the list of child sitemap filenames."""
    all_entries = []
    checked = []
    queue = list(sitemap_urls)
    seen = set()

    while queue and len(checked) < max_child_sitemaps:
        sm_url = queue.pop(0)
        if sm_url in seen:
            continue
        seen.add(sm_url)
        checked.append(sm_url)

        print(f"[*] Fetching {sm_url} ...")
        sm_text = fetch(sm_url)
        if not sm_text:
            print(f"[!] Could not fetch {sm_url}")
            continue

        kind, entries = parse_sitemap(sm_text)
        if kind == "index":
            print(f"[+] {sm_url} is a sitemap INDEX referencing {len(entries)} "
                  f"child sitemap(s) — fetching those too")
            queue.extend(entries)
        else:
            print(f"[+] {len(entries)} URL(s) in {sm_url}")
            all_entries.extend(entries)

    if queue:
        print(f"[!] Stopped after {max_child_sitemaps} child sitemaps — "
              f"{len(queue)} more were queued but not fetched")

    return all_entries, checked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url", help="Base URL, e.g. https://example.com")
    parser.add_argument("--json", help="Optional path to write results as JSON")
    parser.add_argument("--html", help="Optional path to write HTML report")
    parser.add_argument("--pdf", help="Optional path to write PDF report")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    print(f"[*] Fetching {base}/robots.txt ...")
    robots_text = fetch(f"{base}/robots.txt")

    disallow_paths = []
    sitemap_urls = []
    if robots_text:
        disallow_paths, sitemap_urls = parse_robots(robots_text)
        print(f"[+] Found {len(disallow_paths)} Disallow rule(s), "
              f"{len(sitemap_urls)} sitemap reference(s)")
    else:
        print("[!] No robots.txt found (or fetch failed)")

    if not sitemap_urls:
        sitemap_urls = [f"{base}/sitemap.xml"]

    all_sitemap_entries, sitemaps_checked = collect_sitemap_entries(sitemap_urls)

    print(f"\n=== Disallowed paths (from robots.txt) ===")
    for path in disallow_paths:
        flag = " <-- interesting" if INTERESTING_PATTERN.search(path) else ""
        print(f"{path}{flag}")

    print(f"\n=== Sitemap URLs ({len(all_sitemap_entries)} total) ===")
    interesting_sitemap = [u for u in all_sitemap_entries if INTERESTING_PATTERN.search(u)]
    for url in interesting_sitemap[:50]:
        print(url)
    if len(interesting_sitemap) > 50:
        print(f"... and {len(interesting_sitemap) - 50} more interesting URLs")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({
                "base_url": base,
                "disallow_paths": disallow_paths,
                "sitemap_urls_checked": sitemaps_checked,
                "sitemap_entries": all_sitemap_entries,
            }, f, indent=2)
        print(f"\n[*] Written to {args.json}")


    if args.html:
        generate_html_report(
            "robots_sitemap_recon", base,
            {
                "base_url": base,
                "disallow_paths": disallow_paths,
                "sitemap_urls_checked": sitemaps_checked,
                "sitemap_entries": all_sitemap_entries,
            },
            args.html,
            summary=f"{len(disallow_paths)} Disallow rules, {len(all_sitemap_entries)} sitemap entries",
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        from html_report import generate_pdf_report
        generate_pdf_report(
            "robots_sitemap_recon.py", base,
            {"base_url": base, "disallow_paths": disallow_paths, "sitemap_urls_checked": sitemaps_checked, "sitemap_entries": all_sitemap_entries},
            args.pdf,
            summary=f"{len(disallow_paths)} Disallow rules, {len(all_sitemap_entries)} sitemap entries",
        )

if __name__ == "__main__":
    main()
