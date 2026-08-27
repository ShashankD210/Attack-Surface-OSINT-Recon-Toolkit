#!/usr/bin/env python3
"""
attack_surface_toolkit.py — single-file attack surface reconnaissance toolkit.

Merged from the attack-surface-toolkit scripts/ directory.
"""

import argparse
import csv
import gzip
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from html import escape

import requests

try:
    import shodan
except ImportError:
    shodan = None

try:
    import whois as pywhois
except ImportError:
    pywhois = None

try:
    import dns.resolver
    import dns.query
    import dns.zone
except ImportError:
    dns = None

try:
    from weasyprint import HTML as WeasyHTML
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False

# =============================================================
# json_io.py
# =============================================================

#!/usr/bin/env python3
"""
json_io.py — shared helpers for reading/writing JSON with optional gzip compression.
"""
import gzip
import json
import os


def load_json(path: str):
    """Load JSON from a plain or .json.gz file."""
    if not os.path.isfile(path):
        gz_path = path + ".gz"
        if os.path.isfile(gz_path):
            path = gz_path
        else:
            return None
    if path.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return json.load(f)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(data, path: str, compress: bool = False):
    """Save data as JSON, optionally gzip-compressed."""
    if compress:
        path = path + ".gz"
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if compress:
        with gzip.open(path, "wt", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    else:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    return path

# =============================================================
# html_report.py
# =============================================================

#!/usr/bin/env python3
"""
html_report.py — shared utility to render scan results as a self-contained
HTML report and/or PDF. Used by individual scripts via --html / --pdf, and by
the pipeline.

Each tool writes its own JSON, then calls generate_html_report() to produce
a matching .html file with no external dependencies. If weasyprint is
installed, generate_pdf_report() converts that HTML into a PDF.
"""
import json
import os
from html import escape
from datetime import datetime, timezone

try:
    from weasyprint import HTML as WeasyHTML
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False


CSS = """\
:root {
  --bg: #0f1117; --panel: #161923; --border: #262b3a;
  --text: #e6e8ef; --muted: #8b92a8; --accent: #6ea8fe;
  --danger: #ff6b6b; --warn: #ffb454; --ok: #4ade80;
}
* { box-sizing: border-box; }
body {
  margin: 0; font-family: -apple-system, Segoe UI, Roboto, sans-serif;
  background: var(--bg); color: var(--text);
}
header { padding: 20px 24px; border-bottom: 1px solid var(--border); }
header h1 { margin: 0 0 4px; font-size: 18px; }
header p { margin: 0; color: var(--muted); font-size: 12px; }
.wrap { padding: 20px 24px; max-width: 1100px; margin: 0 auto; }
.card {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: 8px; padding: 14px 16px; margin-bottom: 14px;
}
.card h2 {
  margin: 0 0 10px; font-size: 14px; color: var(--accent);
  text-transform: uppercase; letter-spacing: 0.05em;
}
table {
  width: 100%; border-collapse: collapse; font-size: 13px;
}
th, td {
  text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border);
}
th { color: var(--muted); font-weight: 600; }
tr:last-child td { border-bottom: none; }
.badge {
  display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: 11px; font-weight: 600;
}
.badge-ok { background: rgba(74,222,128,0.15); color: var(--ok); }
.badge-warn { background: rgba(255,180,84,0.15); color: var(--warn); }
.badge-danger { background: rgba(255,107,107,0.15); color: var(--danger); }
.badge-info { background: rgba(110,168,254,0.15); color: var(--accent); }
pre {
  background: #0a0c10; border: 1px solid var(--border); border-radius: 6px;
  padding: 12px; overflow-x: auto; font-size: 12px; line-height: 1.5;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
"""


def _badge(text, kind="info"):
    return f'<span class="badge badge-{kind}">{escape(str(text))}</span>'


def _render_table(headers, rows):
    th = "".join(f"<th>{escape(h)}</th>" for h in headers)
    trs = []
    for row in rows:
        td = "".join(f"<td>{escape(str(c))}</td>" for c in row)
        trs.append(f"<tr>{td}</tr>")
    return f'<table><thead><tr>{th}</tr></thead><tbody>{"".join(trs)}</tbody></table>'


def _render_list(title, items, empty_msg="No items"):
    if not items:
        return f'<div class="card"><h2>{escape(title)}</h2><p style="color:var(--muted)">{empty_msg}</p></div>'
    rows = [(i + 1, escape(str(x))) for i, x in enumerate(items)]
    return f'<div class="card"><h2>{escape(title)} ({len(items)})</h2>' + _render_table(["#", "Value"], rows) + "</div>"


def _render_kv(title, data, empty_msg="No data"):
    if not data:
        return f'<div class="card"><h2>{escape(title)}</h2><p style="color:var(--muted)">{empty_msg}</p></div>'
    rows = [(escape(str(k)), escape(str(v))) for k, v in data.items()]
    return f'<div class="card"><h2>{escape(title)}</h2>' + _render_table(["Field", "Value"], rows) + "</div>"


def _auto_render(key, value):
    if isinstance(value, list):
        if value and isinstance(value[0], dict):
            headers = list(value[0].keys())
            rows = [[escape(str(item.get(h, ""))) for h in headers] for item in value]
            return _render_table(headers, rows)
        return _render_list(key, value)
    if isinstance(value, dict):
        return _render_kv(key, value)
    return f'<div class="card"><h2>{escape(key)}</h2><pre>{escape(json.dumps(value, indent=2, default=str))}</pre></div>'


def generate_html_report(
    tool_name: str,
    target: str,
    data: dict,
    out_path: str,
    summary: str = "",
) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    body_parts = []

    if summary:
        body_parts.append(f'<div class="card"><h2>Summary</h2><p>{escape(summary)}</p></div>')

    skip = {"tool", "target", "timestamp", "summary"}
    for key, value in data.items():
        if key in skip:
            continue
        body_parts.append(_auto_render(key, value))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{escape(tool_name)} — {escape(target)}</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>{escape(tool_name)}</h1>
  <p>Target: {escape(target)} &nbsp;|&nbsp; {ts} &nbsp;|&nbsp; Attack Surface Toolkit</p>
</header>
<div class="wrap">
{''.join(body_parts)}
</div>
</body>
</html>"""

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w") as f:
        f.write(html)
    return out_path


def generate_pdf_report(
    tool_name: str,
    target: str,
    data: dict,
    out_path: str,
    summary: str = "",
) -> str:
    if not HAS_WEASYPRINT:
        print("[!] weasyprint not installed — skipping PDF report. "
              "Install it with: pip install weasyprint")
        return ""

    html_path = out_path.replace(".pdf", ".tmp.html")
    generate_html_report(tool_name, target, data, html_path, summary)

    try:
        WeasyHTML(filename=html_path).write_pdf(out_path)
    except Exception as e:
        print(f"[!] PDF generation failed: {e}")
        return ""
    finally:
        if os.path.exists(html_path):
            os.remove(html_path)

    return out_path

# =============================================================
# crtsh_subdomains.py
# =============================================================

#!/usr/bin/env python3
"""
crtsh_subdomains.py — passive subdomain discovery via Certificate
Transparency logs (crt.sh public API). Purely passive: queries a public
third-party dataset, never contacts the target's own infrastructure.

Usage:
    python3 crtsh_subdomains.py example.com
    python3 crtsh_subdomains.py example.com --json out.json
"""
import argparse
import json
import sys
import time
import requests


CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


def fetch_subdomains(domain: str, retries: int = 3, timeout: int = 30) -> set:
    url = CRTSH_URL.format(domain=domain)
    headers = {"User-Agent": "attack-surface-toolkit/1.0 (passive recon)"}

    last_err = None
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            names = set()
            for entry in data:
                for line in entry.get("name_value", "").splitlines():
                    line = line.strip().lower().lstrip("*.")
                    if line.endswith(domain):
                        names.add(line)
            return names
        except (requests.RequestException, json.JSONDecodeError) as e:
            last_err = e
            time.sleep(2 * attempt)  # backoff, be polite to the free service

    print(f"[!] Failed to query crt.sh after {retries} attempts: {last_err}",
          file=sys.stderr)
    return set()


def crtsh_main(args):
    pass  # args provided by unified CLI

    print(f"[*] Querying crt.sh for *.{args.domain} ...")
    subdomains = fetch_subdomains(args.domain)

    print(f"[+] Found {len(subdomains)} unique hostnames")
    for name in sorted(subdomains):
        print(name)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(sorted(subdomains), f, indent=2)
        print(f"[*] Written to {args.json}")

    if args.txt:
        with open(args.txt, "w") as f:
            for name in sorted(subdomains):
                f.write(name + "\n")
        print(f"[*] Written to {args.txt}")


    if args.html:
        generate_html_report(
            "crtsh_subdomains", args.domain,
            {"domain": args.domain, "subdomains": sorted(subdomains)},
            args.html,
            summary=f"Found {len(subdomains)} unique hostnames",
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        
        generate_pdf_report(
            "crtsh_subdomains.py", args.domain,
            {"domain": args.domain, "subdomains": sorted(subdomains)},
            args.pdf,
            summary=f"Found {len(subdomains)} unique hostnames",
        )

# crtsh_main is called by the unified dispatcher

# =============================================================
# whois_dns_recon.py
# =============================================================

#!/usr/bin/env python3
"""
whois_dns_recon.py — passive WHOIS + DNS record enumeration for a domain.
Queries public WHOIS registries and public DNS resolvers only.

Usage:
    python3 whois_dns_recon.py example.com
"""
import argparse
import json
import sys


try:
    import whois as pywhois
except ImportError:
    pywhois = None

try:
    import dns.resolver
except ImportError:
    dns = None

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]


def do_whois(domain: str) -> dict:
    print(f"\n=== WHOIS: {domain} ===")
    result = {}
    if pywhois is None:
        print("[!] python-whois not installed (pip install python-whois)")
        return result
    try:
        w = pywhois.whois(domain)
        for field in ["domain_name", "registrar", "creation_date",
                      "expiration_date", "updated_date", "name_servers",
                      "emails", "org", "country"]:
            value = w.get(field) if hasattr(w, "get") else getattr(w, field, None)
            if value:
                print(f"{field:16}: {value}")
                result[field] = str(value)
    except Exception as e:
        print(f"[!] WHOIS lookup failed: {e}")
    return result


def do_dns(domain: str) -> dict:
    print(f"\n=== DNS records: {domain} ===")
    records = {}
    if dns is None:
        print("[!] dnspython not installed (pip install dnspython)")
        return records
    resolver = dns.resolver.Resolver()
    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            values = [rdata.to_text() for rdata in answers]
            for v in values:
                print(f"{rtype:6} {v}")
            records[rtype] = values
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            print(f"[!] {domain} does not exist (NXDOMAIN)")
            return records
        except Exception as e:
            print(f"[!] {rtype} lookup failed: {e}")
    return records


def whois_main(args):
    pass  # args provided by unified CLI

    whois_data = do_whois(args.domain)
    dns_data = do_dns(args.domain)

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"domain": args.domain, "whois": whois_data,
                        "dns": dns_data}, f, indent=2)
        print(f"\n[*] Written to {args.json}")


    if args.html:
        generate_html_report(
            "whois_dns_recon", args.domain,
            {"domain": args.domain, "whois": whois_data, "dns": dns_data},
            args.html,
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        
        generate_pdf_report(
            "whois_dns_recon.py", args.domain,
            {"domain": args.domain, "whois": whois_data, "dns": dns_data},
            args.pdf,
            summary=None,
        )

# whois_main is called by the unified dispatcher

# =============================================================
# wayback_urls.py
# =============================================================

#!/usr/bin/env python3
"""
wayback_urls.py — passive historical URL discovery via the Internet Archive's
Wayback Machine CDX API. Surfaces old endpoints, forgotten parameters,
backup files, and staging paths that were once crawled but may not appear
in current sitemaps — a real technique used across bug bounty and red-team
recon (equivalent to the popular 'waybackurls' / 'gau' tools).

Purely passive: queries archive.org's public dataset, never contacts the
target's own infrastructure.

Usage:
    python3 wayback_urls.py example.com
    python3 wayback_urls.py example.com --interesting-only
    python3 wayback_urls.py example.com --json out.json
"""
import argparse
import json
import re
import sys
import requests



CDX_URL = "https://web.archive.org/cdx/search/cdx"

# Extensions/paths that commonly indicate forgotten or sensitive assets.
INTERESTING_PATTERN = re.compile(
    r"\.(sql|bak|old|zip|tar|gz|log|env|config|conf|yml|yaml|json|xml|"
    r"pem|key|pfx|db|backup)$|"
    r"/(admin|debug|test|staging|internal|api/v[0-9]+|swagger|actuator)/",
    re.IGNORECASE,
)


def fetch_urls(domain: str, timeout: int = 20) -> list:
    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "collapse": "urlkey",
        "fl": "original,timestamp,statuscode,mimetype",
    }
    headers = {"User-Agent": "attack-surface-toolkit/1.0 (passive recon)"}
    try:
        resp = requests.get(CDX_URL, params=params, headers=headers, timeout=timeout)
        resp.raise_for_status()
        rows = resp.json()
    except (requests.RequestException, json.JSONDecodeError) as e:
        print(f"[!] Wayback CDX query failed: {e}", file=sys.stderr)
        return []

    if not rows or len(rows) < 2:
        return []

    header, *data = rows
    results = [dict(zip(header, row)) for row in data]
    return results


def wayback_main(args):
    pass  # args provided by unified CLI

    print(f"[*] Querying Wayback Machine CDX for *.{args.domain}/* ...")
    records = fetch_urls(args.domain)
    print(f"[+] Found {len(records)} archived URLs")

    if args.interesting_only:
        records = [r for r in records if INTERESTING_PATTERN.search(r.get("original", ""))]
        print(f"[+] {len(records)} match interesting file/path patterns")

    for r in records:
        flag = " <-- interesting" if INTERESTING_PATTERN.search(r.get("original", "")) else ""
        print(f"{r.get('timestamp','')}  {r.get('original','')}{flag}")

    if args.json:
        save_json(records, args.json, compress=True)
        print(f"[*] Written to {args.json}.gz")


    if args.html:
        generate_html_report(
            "wayback_urls", args.domain,
            {"domain": args.domain, "urls": records},
            args.html,
            summary=f"Found {len(records)} archived URLs",
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        
        generate_pdf_report(
            "wayback_urls.py", args.domain,
            {"domain": args.domain, "urls": records},
            args.pdf,
            summary=f"Found {len(records)} archived URLs",
        )

# wayback_main is called by the unified dispatcher

# =============================================================
# ipinfo_asn_lookup.py
# =============================================================

#!/usr/bin/env python3
"""
ipinfo_asn_lookup.py — resolves a hostname (or accepts an IP directly) and
looks up its ASN, owning organization, and rough geolocation using public,
no-auth-required data sources (ipinfo.io's free endpoint and RDAP via
rdap.org). Useful for mapping which network blocks/providers an org's
infrastructure sits in — standard groundwork before deciding what's
actually in-scope for an engagement.

Passive: only queries third-party lookup services, never contacts the
target directly beyond a normal DNS resolution.

Usage:
    python3 ipinfo_asn_lookup.py example.com
    python3 ipinfo_asn_lookup.py 93.184.216.34
    python3 ipinfo_asn_lookup.py example.com --json out.json
"""
import argparse
import json
import socket
import sys
import requests


IPINFO_URL = "https://ipinfo.io/{ip}/json"
RDAP_URL = "https://rdap.org/ip/{ip}"


def resolve_to_ip(target: str) -> str:
    try:
        socket.inet_aton(target)
        return target  # already an IPv4 address
    except OSError:
        pass
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as e:
        print(f"[!] Could not resolve {target}: {e}", file=sys.stderr)
        sys.exit(1)


def lookup_ipinfo(ip: str, timeout: int = 15) -> dict:
    try:
        resp = requests.get(IPINFO_URL.format(ip=ip), timeout=timeout,
                             headers={"User-Agent": "attack-surface-toolkit/1.0"})
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        print(f"[!] ipinfo.io lookup failed: {e}", file=sys.stderr)
        return {}


def lookup_rdap(ip: str, timeout: int = 15) -> dict:
    try:
        resp = requests.get(RDAP_URL.format(ip=ip), timeout=timeout,
                             headers={"User-Agent": "attack-surface-toolkit/1.0"})
        resp.raise_for_status()
        data = resp.json()
        return {
            "handle": data.get("handle"),
            "name": data.get("name"),
            "country": data.get("country"),
            "startAddress": data.get("startAddress"),
            "endAddress": data.get("endAddress"),
        }
    except (requests.RequestException, json.JSONDecodeError) as e:
        print(f"[!] RDAP lookup failed: {e}", file=sys.stderr)
        return {}


def ipinfo_main(args):
    pass  # args provided by unified CLI

    ip = resolve_to_ip(args.target)
    print(f"[*] Target: {args.target} -> {ip}")

    ipinfo = lookup_ipinfo(ip)
    rdap = lookup_rdap(ip)

    print("\n=== ipinfo.io ===")
    for field in ["ip", "hostname", "city", "region", "country", "loc",
                  "org", "postal", "timezone"]:
        if ipinfo.get(field):
            print(f"{field:10}: {ipinfo[field]}")

    print("\n=== RDAP (network block) ===")
    for field, label in [("handle", "handle"), ("name", "net name"),
                          ("country", "country"), ("startAddress", "range start"),
                          ("endAddress", "range end")]:
        if rdap.get(field):
            print(f"{label:12}: {rdap[field]}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"target": args.target, "ip": ip, "ipinfo": ipinfo,
                        "rdap": rdap}, f, indent=2)
        print(f"\n[*] Written to {args.json}")


    if args.html:
        generate_html_report(
            "ipinfo_asn_lookup", args.target,
            {"target": args.target, "ip": ip, "ipinfo": ipinfo, "rdap": rdap},
            args.html,
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        
        generate_pdf_report(
            "ipinfo_asn_lookup.py", args.target,
            {"target": args.target, "ip": ip, "ipinfo": ipinfo, "rdap": rdap},
            args.pdf,
            summary=None,
        )

# ipinfo_main is called by the unified dispatcher

# =============================================================
# tech_fingerprint.py
# =============================================================

#!/usr/bin/env python3
"""
tech_fingerprint.py — lightweight technology fingerprinting for a web host,
in the spirit of Wappalyzer/whatweb: inspects HTTP response headers, the
HTML <meta> generator tag, and common script/asset URL patterns to guess
the CMS, framework, server software, and analytics/CDN providers in use.

ACTIVE (low-impact): makes a single normal HTTP GET request to the target,
the same as visiting the page in a browser. Requires authorization per
docs/00-legal-and-ethics.md.

Usage:
    python3 tech_fingerprint.py https://example.com
    python3 tech_fingerprint.py https://example.com --json out.json
"""
import argparse
import json
import re
import requests


# (label, where to look, pattern)
SIGNATURES = [
    ("WordPress", "body", r"wp-content|wp-includes"),
    ("Drupal", "body", r"Drupal\.settings|sites/default/files"),
    ("Joomla", "body", r"/components/com_|Joomla!"),
    ("Shopify", "body", r"cdn\.shopify\.com|Shopify\.theme"),
    ("Magento", "body", r"Mage\.Cookies|/static/version"),
    ("React", "body", r"__REACT_DEVTOOLS|data-reactroot|react-dom"),
    ("Next.js", "body", r"__NEXT_DATA__|_next/static"),
    ("Vue.js", "body", r"data-v-app|__VUE__|vue\.js"),
    ("Angular", "body", r"ng-version|angular\.js"),
    ("jQuery", "body", r"jquery(\.min)?\.js"),
    ("Bootstrap", "body", r"bootstrap(\.min)?\.css"),
    ("Cloudflare", "headers", r"cloudflare"),
    ("Amazon CloudFront", "headers", r"cloudfront"),
    ("Fastly", "headers", r"fastly"),
    ("Akamai", "headers", r"akamai"),
    ("Nginx", "headers", r"nginx"),
    ("Apache", "headers", r"apache"),
    ("Microsoft IIS", "headers", r"microsoft-iis"),
    ("Google Analytics", "body", r"www\.google-analytics\.com|gtag\("),
    ("Google Tag Manager", "body", r"googletagmanager\.com"),
    ("Hotjar", "body", r"static\.hotjar\.com"),
    ("Intercom", "body", r"widget\.intercom\.io"),
    ("HubSpot", "body", r"js\.hs-scripts\.com|hubspot"),
    ("Segment", "body", r"cdn\.segment\.com"),
    ("PHP", "headers", r"php/"),
    ("ASP.NET", "headers", r"asp\.net|x-aspnet-version"),
]


def fingerprint(url: str, timeout: int = 15) -> dict:
    resp = requests.get(
        url, timeout=timeout, allow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (attack-surface-toolkit/1.0)"},
    )
    header_blob = " ".join(f"{k}:{v}" for k, v in resp.headers.items()).lower()
    body_blob = (resp.text or "")[:200000]  # cap for performance

    meta_generator = None
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                  body_blob, re.IGNORECASE)
    if m:
        meta_generator = m.group(1)

    matches = []
    for label, where, pattern in SIGNATURES:
        haystack = header_blob if where == "headers" else body_blob
        if re.search(pattern, haystack, re.IGNORECASE):
            matches.append(label)

    return {
        "url": url,
        "final_url": resp.url,
        "status_code": resp.status_code,
        "server_header": resp.headers.get("Server"),
        "x_powered_by": resp.headers.get("X-Powered-By"),
        "meta_generator": meta_generator,
        "detected": sorted(set(matches)),
        "notable_headers": {
            k: v for k, v in resp.headers.items()
            if k.lower() in ("server", "x-powered-by", "via", "x-cache",
                              "x-generator", "x-drupal-cache")
        },
    }


def tech_main(args):
    pass  # args provided by unified CLI

    print(f"[*] Fetching {args.url} ...")
    try:
        result = fingerprint(args.url)
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}")
        return

    print(f"\nStatus: {result['status_code']}  (final URL: {result['final_url']})")
    if result["server_header"]:
        print(f"Server: {result['server_header']}")
    if result["x_powered_by"]:
        print(f"X-Powered-By: {result['x_powered_by']}")
    if result["meta_generator"]:
        print(f"Meta generator: {result['meta_generator']}")

    print(f"\nDetected technologies ({len(result['detected'])}):")
    for tech in result["detected"]:
        print(f"  - {tech}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n[*] Written to {args.json}")


    if args.html:
        generate_html_report(
            "tech_fingerprint", args.url,
            result,
            args.html,
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        
        generate_pdf_report(
            "tech_fingerprint.py", args.url,
            result,
            args.pdf,
            summary=None,
        )

# tech_main is called by the unified dispatcher

# =============================================================
# cloud_bucket_enum.py
# =============================================================

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


def buckets_main(args):
    pass  # args provided by unified CLI

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
        
        generate_pdf_report(
            "cloud_bucket_enum.py", args.base,
            {"base": args.base, "providers": providers, "findings": findings, "public_count": public_count},
            args.pdf,
            summary=f"{len(findings)} bucket(s) found to exist, {public_count} publicly listable",
        )

# buckets_main is called by the unified dispatcher

# =============================================================
# ssl_cert_inspector.py
# =============================================================

#!/usr/bin/env python3
"""
ssl_cert_inspector.py — connects to a host on port 443, retrieves its TLS
certificate, and reports issuer, validity window, and all Subject
Alternative Names (SANs). SANs frequently reveal additional subdomains not
found via certificate-transparency logs (e.g. internal-only certs that
were never logged to CT, or wildcard certs). Also flags certificates
expiring soon.

ACTIVE (low-impact): a normal TLS handshake, the same as visiting the site
in a browser. Requires authorization per docs/00-legal-and-ethics.md.

Usage:
    python3 ssl_cert_inspector.py example.com
    python3 ssl_cert_inspector.py example.com --port 8443
    python3 ssl_cert_inspector.py example.com --json out.json
"""
import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone


DATE_FMT = "%b %d %H:%M:%S %Y %Z"


def parse_cert(hostname: str, port: int, timeout: int = 10) -> dict:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # inspect even self-signed/expired certs

    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            cert_bin = ssock.getpeercert(binary_form=False)
            cipher = ssock.cipher()
            tls_version = ssock.version()

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")
    days_remaining = None
    if not_after:
        try:
            expiry = datetime.strptime(not_after, DATE_FMT).replace(tzinfo=timezone.utc)
            days_remaining = (expiry - datetime.now(timezone.utc)).days
        except ValueError:
            pass

    return {
        "hostname": hostname,
        "port": port,
        "subject_cn": subject.get("commonName"),
        "issuer_cn": issuer.get("commonName"),
        "issuer_org": issuer.get("organizationName"),
        "not_before": not_before,
        "not_after": not_after,
        "days_remaining": days_remaining,
        "san_dns_names": sorted(set(sans)),
        "tls_version": tls_version,
        "cipher": cipher[0] if cipher else None,
    }


def ssl_main(args):
    pass  # args provided by unified CLI

    print(f"[*] Connecting to {args.hostname}:{args.port} ...")
    try:
        result = parse_cert(args.hostname, args.port)
    except (socket.error, ssl.SSLError, OSError) as e:
        print(f"[!] Connection/TLS error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\nSubject CN : {result['subject_cn']}")
    print(f"Issuer     : {result['issuer_cn']} ({result['issuer_org']})")
    print(f"Valid      : {result['not_before']}  ->  {result['not_after']}")
    if result["days_remaining"] is not None:
        flag = "  <-- EXPIRING SOON" if result["days_remaining"] < 30 else ""
        print(f"Days left  : {result['days_remaining']}{flag}")
    print(f"TLS version: {result['tls_version']}  Cipher: {result['cipher']}")

    print(f"\nSAN DNS names ({len(result['san_dns_names'])}):")
    for name in result["san_dns_names"]:
        print(f"  - {name}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n[*] Written to {args.json}")


    if args.html:
        generate_html_report(
            "ssl_cert_inspector", args.hostname,
            result,
            args.html,
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        
        generate_pdf_report(
            "ssl_cert_inspector.py", args.hostname,
            result,
            args.pdf,
            summary=None,
        )

# ssl_main is called by the unified dispatcher

# =============================================================
# security_headers_check.py
# =============================================================

#!/usr/bin/env python3
"""
security_headers_check.py — checks a URL for the presence of standard
HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy) and gives a simple pass/fail grade per
header. This is the same check performed by securityheaders.com, done
locally against an authorized target.

ACTIVE (low-impact): a single normal HTTP GET request.

Usage:
    python3 security_headers_check.py https://example.com
    python3 security_headers_check.py https://example.com --json out.json
"""
import argparse
import json
import requests


CHECKS = [
    ("Strict-Transport-Security", "HSTS — enforces HTTPS on future visits"),
    ("Content-Security-Policy", "CSP — mitigates XSS/data-injection attacks"),
    ("X-Frame-Options", "Clickjacking protection (or use CSP frame-ancestors)"),
    ("X-Content-Type-Options", "Prevents MIME-sniffing (expect: nosniff)"),
    ("Referrer-Policy", "Controls referrer leakage to third parties"),
    ("Permissions-Policy", "Restricts browser feature access (camera, geo, etc.)"),
]


def check(url: str, timeout: int = 15) -> dict:
    resp = requests.get(
        url, timeout=timeout, allow_redirects=True,
        headers={"User-Agent": "attack-surface-toolkit/1.0"},
    )
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    results = []
    present_count = 0
    for header, description in CHECKS:
        value = headers_lower.get(header.lower())
        present = value is not None
        if present:
            present_count += 1
        results.append({
            "header": header,
            "present": present,
            "value": value,
            "description": description,
        })

    return {
        "url": url,
        "final_url": resp.url,
        "status_code": resp.status_code,
        "checks": results,
        "score": f"{present_count}/{len(CHECKS)}",
        "server_header": resp.headers.get("Server"),
        "cookies_missing_secure_flag": [
            c.name for c in resp.cookies if not c.secure
        ],
    }


def headers_main(args):
    pass  # args provided by unified CLI

    print(f"[*] Checking security headers for {args.url} ...")
    try:
        result = check(args.url)
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}")
        return

    print(f"\nStatus: {result['status_code']}  (final URL: {result['final_url']})")
    print(f"Score: {result['score']} headers present\n")
    for c in result["checks"]:
        tag = "PRESENT" if c["present"] else "MISSING"
        print(f"[{tag:7}] {c['header']:26} {c['description']}")
        if c["present"] and c["value"]:
            shown = c["value"] if len(c["value"]) < 80 else c["value"][:77] + "..."
            print(f"           -> {shown}")

    if result["cookies_missing_secure_flag"]:
        print(f"\n[!] Cookies without Secure flag: "
              f"{', '.join(result['cookies_missing_secure_flag'])}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n[*] Written to {args.json}")


    if args.html:
        generate_html_report(
            "security_headers_check", args.url,
            result,
            args.html,
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        
        generate_pdf_report(
            "security_headers_check.py", args.url,
            result,
            args.pdf,
            summary=None,
        )

# headers_main is called by the unified dispatcher

# =============================================================
# robots_sitemap_recon.py
# =============================================================

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


def robots_main(args):
    pass  # args provided by unified CLI

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
        
        generate_pdf_report(
            "robots_sitemap_recon.py", base,
            {"base_url": base, "disallow_paths": disallow_paths, "sitemap_urls_checked": sitemaps_checked, "sitemap_entries": all_sitemap_entries},
            args.pdf,
            summary=f"{len(disallow_paths)} Disallow rules, {len(all_sitemap_entries)} sitemap entries",
        )

# robots_main is called by the unified dispatcher

# =============================================================
# subdomain_takeover_check.py
# =============================================================

#!/usr/bin/env python3
"""
subdomain_takeover_check.py — checks a list of subdomains for dangling
CNAME records pointing at third-party services (GitHub Pages, Heroku, AWS
S3/CloudFront, Azure, Shopify, WordPress.com, etc.) where the referenced
resource no longer exists — a classic, still-common real-world finding
that lets an attacker claim the subdomain on the third-party service and
serve content under the target's own domain name.

This is the same technique as "Can I Take Over XYZ" fingerprint lists —
resolve CNAME, fetch the page, and match known "not claimed" response
signatures.

ACTIVE (low-impact): a normal DNS lookup + a normal HTTP GET per candidate
subdomain. Requires authorization per docs/00-legal-and-ethics.md.

Usage:
    python3 subdomain_takeover_check.py subdomains.txt
    echo -e "blog.example.com\\nold.example.com" | python3 subdomain_takeover_check.py -
    python3 subdomain_takeover_check.py subdomains.txt --json out.json
"""
import argparse
import json
import sys
import requests


try:
    import dns.resolver
except ImportError:
    dns = None

# service label -> (cname substring, response-body fingerprint substring(s))
FINGERPRINTS = {
    "GitHub Pages": ("github.io", ["There isn't a GitHub Pages site here"]),
    "Heroku": ("herokuapp.com", ["No such app", "herokucdn.com/error-pages/no-such-app.html"]),
    "AWS S3": ("s3.amazonaws.com", ["NoSuchBucket", "The specified bucket does not exist"]),
    "AWS CloudFront": ("cloudfront.net", ["Bad request", "ERROR: The request could not be satisfied"]),
    "Azure": ("azurewebsites.net", ["404 Web Site not found"]),
    "Shopify": ("myshopify.com", ["Sorry, this shop is currently unavailable"]),
    "WordPress.com": ("wordpress.com", ["Do you want to register"]),
    "Fastly": ("fastly.net", ["Fastly error: unknown domain"]),
    "Ghost(Pro)": ("ghost.io", ["The thing you were looking for is no longer here"]),
    "Surge.sh": ("surge.sh", ["project not found"]),
    "Bitbucket": ("bitbucket.io", ["Repository not found"]),
    "Unbounce": ("unbounce.com", ["The requested URL was not found on this server"]),
    "WPEngine": ("wpengine.com", ["The site you're looking for could not be found"]),
    "Zendesk": ("zendesk.com", ["Help Center Closed"]),
}


def get_cname(hostname: str) -> str:
    if dns is None:
        return ""
    try:
        answers = dns.resolver.Resolver().resolve(hostname, "CNAME")
        return str(answers[0].target).rstrip(".")
    except Exception:
        return ""


def check_takeover(hostname: str, timeout: int = 10) -> dict:
    cname = get_cname(hostname)
    if not cname:
        return {"hostname": hostname, "cname": None, "service": None,
                 "likely_takeover": False, "note": "no CNAME record"}

    matched_service = None
    for service, (needle, _fingerprints) in FINGERPRINTS.items():
        if needle in cname:
            matched_service = service
            break

    if not matched_service:
        return {"hostname": hostname, "cname": cname, "service": None,
                 "likely_takeover": False, "note": "CNAME target not in known-service list"}

    body = ""
    try:
        resp = requests.get(f"http://{hostname}/", timeout=timeout,
                             headers={"User-Agent": "attack-surface-toolkit/1.0"})
        body = resp.text or ""
    except requests.RequestException as e:
        return {"hostname": hostname, "cname": cname, "service": matched_service,
                 "likely_takeover": None, "note": f"request failed: {e}"}

    _needle, fingerprints = FINGERPRINTS[matched_service]
    hit = any(fp.lower() in body.lower() for fp in fingerprints)

    return {
        "hostname": hostname,
        "cname": cname,
        "service": matched_service,
        "likely_takeover": hit,
        "note": "fingerprint matched — resource appears unclaimed" if hit
                else "CNAME points at known service but fingerprint not matched "
                     "(resource likely still claimed, or check manually)",
    }


def takeover_main(args):
    pass  # args provided by unified CLI

    if dns is None:
        print("[!] dnspython not installed (pip install dnspython)", file=sys.stderr)
        sys.exit(1)

    if args.input == "-":
        hosts = [line.strip() for line in sys.stdin if line.strip()]
    else:
        with open(args.input) as f:
            hosts = [line.strip() for line in f if line.strip()]

    print(f"[*] Checking {len(hosts)} hostnames for dangling CNAME takeover risk ...")
    print("[!] Active checks (DNS + HTTP GET) — confirm authorization before running.\n")

    results = []
    flagged = []
    for host in hosts:
        result = check_takeover(host)
        results.append(result)
        if result["likely_takeover"]:
            flagged.append(result)
            print(f"[!!!] {host} -> {result['cname']} ({result['service']}) — LIKELY TAKEOVER RISK")
        elif result["cname"]:
            print(f"[+] {host} -> {result['cname']} ({result['service'] or 'unrecognized service'})")
        else:
            print(f"    {host} — no CNAME")

    print(f"\n[+] {len(flagged)} likely takeover candidate(s) out of {len(hosts)} checked.")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[*] Written to {args.json}")


    if args.html:
        generate_html_report(
            "subdomain_takeover_check", args.input,
            {"input": args.input, "results": results, "flagged": flagged},
            args.html,
            summary=f"{len(flagged)} likely takeover candidate(s) out of {len(hosts)} checked.",
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        
        generate_pdf_report(
            "subdomain_takeover_check.py", args.input,
            {"input": args.input, "results": results, "flagged": flagged},
            args.pdf,
            summary=f"{len(flagged)} likely takeover candidate(s) out of {len(hosts)} checked.",
        )

# takeover_main is called by the unified dispatcher

# =============================================================
# username_presence_check.py
# =============================================================

#!/usr/bin/env python3
"""
username_presence_check.py — checks whether a given username/handle exists
on a curated list of public platforms, by requesting each platform's
profile URL and checking the response. This is the same technique used by
tools like Sherlock/WhatsMyName/Maigret.

Legitimate uses in this toolkit's scope: confirming which platforms an
organization's official brand accounts exist on (so fake/impersonation
accounts can be identified), or checking your own organization's exposure
footprint. This script is a discovery aid only — it does not access
private data, does not authenticate, and does not scrape profile content
beyond the HTTP status of the profile URL.

Do not use this to stalk, harass, or build dossiers on private individuals
without their consent — that's outside this toolkit's intended scope.

Usage:
    python3 username_presence_check.py acmecorp
    python3 username_presence_check.py acmecorp --json out.json
"""
import argparse
import json
import time
import requests


# name -> profile URL template. Deliberately a small, well-known set of
# mainstream platforms (not an exhaustive stalkerware-style list).
PLATFORMS = {
    "GitHub": "https://github.com/{u}",
    "GitLab": "https://gitlab.com/{u}",
    "Twitter/X": "https://x.com/{u}",
    "Instagram": "https://www.instagram.com/{u}/",
    "LinkedIn (company)": "https://www.linkedin.com/company/{u}/",
    "Facebook": "https://www.facebook.com/{u}",
    "YouTube": "https://www.youtube.com/@{u}",
    "Reddit": "https://www.reddit.com/user/{u}",
    "TikTok": "https://www.tiktok.com/@{u}",
    "Medium": "https://medium.com/@{u}",
    "PyPI": "https://pypi.org/user/{u}/",
    "npm": "https://www.npmjs.com/~{u}",
    "Docker Hub": "https://hub.docker.com/u/{u}",
}

NOT_FOUND_HINTS = ["page not found", "user not found", "doesn't exist",
                    "sorry, this page"]


def check_platform(name: str, url_template: str, username: str, timeout: int = 10):
    url = url_template.format(u=username)
    try:
        resp = requests.get(
            url, timeout=timeout, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (attack-surface-toolkit/1.0)"},
        )
    except requests.RequestException as e:
        return {"platform": name, "url": url, "status": "error", "detail": str(e)}

    body_lower = resp.text.lower()[:20000] if resp.text else ""
    looks_missing = any(hint in body_lower for hint in NOT_FOUND_HINTS)

    if resp.status_code == 404 or looks_missing:
        exists = False
    elif resp.status_code in (200, 301, 302):
        exists = True
    else:
        exists = None  # ambiguous (rate-limited, blocked, etc.)

    return {
        "platform": name,
        "url": url,
        "status_code": resp.status_code,
        "exists": exists,
    }


def username_main(args):
    pass  # args provided by unified CLI

    print(f"[*] Checking '{args.username}' across {len(PLATFORMS)} platforms ...")
    print("[!] Active checks against third-party sites — respect each "
          "platform's Terms of Service and rate limits.\n")

    results = []
    for name, template in PLATFORMS.items():
        result = check_platform(name, template, args.username)
        results.append(result)
        tag = {"True": "FOUND", "False": "not found", "None": "unclear"}.get(
            str(result.get("exists")), "error")
        print(f"{name:22} {tag:10} {result['url']}")
        time.sleep(args.delay)

    found = [r for r in results if r.get("exists") is True]
    print(f"\n[+] Found on {len(found)}/{len(PLATFORMS)} platforms checked.")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[*] Written to {args.json}")


    if args.html:
        generate_html_report(
            "username_presence_check", args.username,
            {"username": args.username, "results": results},
            args.html,
            summary=f"Found on {len(found)}/{len(PLATFORMS)} platforms checked.",
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        
        generate_pdf_report(
            "username_presence_check.py", args.username,
            {"username": args.username, "results": results},
            args.pdf,
            summary=f"Found on {len(found)}/{len(PLATFORMS)} platforms checked.",
        )

# username_main is called by the unified dispatcher

# =============================================================
# email_pattern_generator.py
# =============================================================

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


def email_main(args):
    pass  # args provided by unified CLI

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
        
        generate_pdf_report(
            "email_pattern_generator.py", args.domain,
            {"domain": args.domain, "mx_records": mx_records, "candidates": all_candidates},
            args.pdf,
            summary=f"Generated {len(all_candidates)} candidate address(es) for {len(names)} name(s).",
        )

# email_main is called by the unified dispatcher

# =============================================================
# shodan_search.py
# =============================================================

#!/usr/bin/env python3
"""
shodan_search.py — look up previously-scanned, publicly indexed exposed
services for a domain/org using the Shodan API. This queries Shodan's own
prior scan data, not the target directly, so it stays passive from your
side. Requires a Shodan API key (free tier available) in SHODAN_API_KEY.

Usage:
    export SHODAN_API_KEY=your_key_here
    python3 shodan_search.py example.com
    python3 shodan_search.py example.com --limit 50
"""
import argparse
import os
import sys


try:
    import shodan
except ImportError:
    shodan = None


def shodan_main(args):
    pass  # args provided by unified CLI

    if shodan is None:
        print("[!] shodan package not installed (pip install shodan)",
              file=sys.stderr)
        sys.exit(1)

    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        print("[!] Set SHODAN_API_KEY environment variable first.",
              file=sys.stderr)
        sys.exit(1)

    api = shodan.Shodan(api_key)
    search_query = f'hostname:"{args.query}"'

    print(f"[*] Searching Shodan for: {search_query}")
    try:
        results = api.search(search_query, limit=args.limit)
    except shodan.APIError as e:
        print(f"[!] Shodan API error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] {results['total']} total matches (showing up to {args.limit})\n")
    records = []
    for match in results["matches"]:
        ip = match.get("ip_str")
        port = match.get("port")
        org = match.get("org", "")
        product = match.get("product", "")
        hostnames = match.get("hostnames", [])
        print(f"{ip:16} :{port:<6} {product:20} {org:20} {', '.join(hostnames)}")
        records.append({
            "source": "shodan",
            "ip": ip,
            "port": port,
            "org": org,
            "product": product,
            "hostnames": hostnames,
        })

    if args.json:
        import json
        with open(args.json, "w") as f:
            json.dump(records, f, indent=2)
        print(f"[*] Written to {args.json}")


    if args.html:
        generate_html_report(
            "shodan_search", args.query,
            {"query": search_query, "total": results.get("total", 0), "matches": records},
            args.html,
            summary=f"{results.get('total', 0)} total matches (showing up to {args.limit})",
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        
        generate_pdf_report(
            "shodan_search.py", args.query,
            {"query": search_query, "total": results.get("total", 0), "matches": records},
            args.pdf,
            summary=f"{results.get('total', 0)} total matches (showing up to {args.limit})",
        )

# shodan_main is called by the unified dispatcher

# =============================================================
# github_dork_recon.py
# =============================================================

#!/usr/bin/env python3
"""
github_dork_recon.py — generates a set of targeted GitHub code-search URLs
for an org/keyword, to help a human analyst manually review results for
accidental leakage (config files, internal hostnames, API references, etc).

This script does NOT scrape GitHub or automate secret extraction — it only
builds search URLs for you to open and review yourself, in line with
GitHub's terms of service around automated querying.

Usage:
    python3 github_dork_recon.py "Acme Corp" acme.com
"""
import argparse
import urllib.parse


# Generic, non-exploitative search themes: config/leak awareness, not
# targeted secret harvesting or exploitation.
DORK_TEMPLATES = [
    '"{org}" password',
    '"{org}" api_key',
    '"{org}" secret',
    '"{domain}" filename:.env',
    '"{domain}" filename:config',
    '"{domain}" extension:pem',
    '"{domain}" extension:yml internal',
    'org:"{org}" filename:.git-credentials',
]


def build_urls(org: str, domain: str):
    urls = []
    for template in DORK_TEMPLATES:
        query = template.format(org=org, domain=domain)
        encoded = urllib.parse.quote(query)
        urls.append((query, f"https://github.com/search?q={encoded}&type=code"))
    return urls


def github_main(args):
    pass  # args provided by unified CLI

    print(f"[*] GitHub review queries for org='{args.org}', domain='{args.domain}'\n")
    for query, url in build_urls(args.org, args.domain):
        print(f"{query}\n  -> {url}\n")

    print("[i] Open these manually and review results by hand — GitHub rate-limits")
    print("    and restricts automated scraping of search results.")


    if args.html:
        urls = build_urls(args.org, args.domain)
        generate_html_report(
            "github_dork_recon", args.domain,
            {"org": args.org, "domain": args.domain, "queries": [(q, u) for q, u in urls]},
            args.html,
            summary=f"{len(urls)} GitHub code-search review queries generated",
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        
        generate_pdf_report(
            "github_dork_recon.py", args.domain,
            {"org": args.org, "domain": args.domain, "queries": [(q, u) for q, u in build_urls(args.org, args.domain)]},
            args.pdf,
            summary=f"{len(build_urls(args.org, args.domain))} GitHub code-search review queries generated",
        )

# github_main is called by the unified dispatcher

# =============================================================
# search_dork_generator.py
# =============================================================

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


def dorks_main(args):
    pass  # args provided by unified CLI

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
        
        generate_pdf_report(
            "search_dork_generator.py", args.domain,
            {"org": args.org, "domain": args.domain, "engine_queries": [(t, e, q, u) for t, e, q, u in build_engine_urls(args.org, args.domain)], "paste_queries": build_paste_urls(args.org, args.domain), "github_queries": build_github_urls(args.org, args.domain)},
            args.pdf,
            summary=f"{len(build_engine_urls(args.org, args.domain))} engine dorks, {len(build_paste_urls(args.org, args.domain))} paste queries, {len(build_github_urls(args.org, args.domain))} GitHub queries",
        )

# dorks_main is called by the unified dispatcher

# =============================================================
# dns_zone_transfer_check.py
# =============================================================

#!/usr/bin/env python3
"""
dns_zone_transfer_check.py — tests whether any of a domain's authoritative
nameservers allow an unauthenticated AXFR zone transfer. A misconfigured
DNS server that allows this leaks the entire zone (every subdomain record)
to anyone who asks — a classic, still-common finding in real external
assessments (this is what `dig axfr @ns1.target.com target.com` checks
manually).

This is an ACTIVE check: it sends a real query to the target's own
nameservers. Low-impact (a single AXFR attempt, almost always refused by
correctly configured servers) but still requires authorization — see
docs/00-legal-and-ethics.md.

Usage:
    python3 dns_zone_transfer_check.py example.com
"""
import argparse
import sys


try:
    import dns.resolver
    import dns.query
    import dns.zone
except ImportError:
    dns = None


def get_nameservers(domain: str):
    resolver = dns.resolver.Resolver()
    try:
        answers = resolver.resolve(domain, "NS")
        return [str(r.target).rstrip(".") for r in answers]
    except Exception as e:
        print(f"[!] Could not fetch NS records for {domain}: {e}", file=sys.stderr)
        return []


def try_axfr(domain: str, nameserver: str, timeout: int = 10):
    try:
        ns_ip = dns.resolver.Resolver().resolve(nameserver, "A")[0].to_text()
    except Exception as e:
        print(f"[!] Could not resolve nameserver {nameserver}: {e}")
        return None

    try:
        z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=timeout))
        names = sorted(z.nodes.keys(), key=str)
        return [str(n) for n in names]
    except Exception:
        return None  # transfer refused — expected/correct behavior


def axfr_main(args):
    pass  # args provided by unified CLI

    if dns is None:
        print("[!] dnspython not installed (pip install dnspython)", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Enumerating nameservers for {args.domain} ...")
    nameservers = get_nameservers(args.domain)
    if not nameservers:
        print("[!] No nameservers found — aborting.")
        return

    print(f"[+] Nameservers: {', '.join(nameservers)}\n")
    print("[!] Sending AXFR zone-transfer requests — active DNS query against "
          "the target's own nameservers. Confirm authorization before running.\n")

    vulnerable = []
    for ns in nameservers:
        print(f"[*] Trying AXFR against {ns} ...")
        records = try_axfr(args.domain, ns)
        if records:
            print(f"[!!!] {ns} ALLOWS zone transfer — {len(records)} records leaked")
            vulnerable.append(ns)
        else:
            print(f"[+] {ns} refused zone transfer (expected/correct)")

    print()
    if vulnerable:
        print(f"[!] FINDING: {len(vulnerable)} nameserver(s) allow unauthenticated "
              f"AXFR: {', '.join(vulnerable)}. This leaks the full DNS zone and "
              "should be reported and remediated (restrict AXFR to authorized "
              "secondary nameservers only).")
    else:
        print("[+] No nameservers allowed zone transfer.")


    if args.html:
        generate_html_report(
            "dns_zone_transfer_check", args.domain,
            {"domain": args.domain, "nameservers": nameservers, "vulnerable": vulnerable},
            args.html,
            summary=f"{len(vulnerable)} nameserver(s) allow unauthenticated AXFR" if vulnerable else "No nameservers allowed zone transfer.",
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        
        generate_pdf_report(
            "dns_zone_transfer_check.py", args.domain,
            {"domain": args.domain, "nameservers": nameservers, "vulnerable": vulnerable},
            args.pdf,
            summary=f"{len(vulnerable)} nameserver(s) allow unauthenticated AXFR" if vulnerable else "No nameservers allowed zone transfer.",
        )

# axfr_main is called by the unified dispatcher

# =============================================================
# merge_inventory.py
# =============================================================

#!/usr/bin/env python3
"""
merge_inventory.py — combines the JSON outputs of the other scripts in this
toolkit into a single normalized asset inventory (JSON + CSV), so you have
one file to hand off for reporting or feed into generate_dashboard.py.

Expects a directory containing any of these (all optional — merges whatever
it finds):
    data/subdomains.json         <- crtsh_subdomains.py --json
    data/whois_dns.json          <- whois_dns_recon.py --json
    data/wayback.json             <- wayback_urls.py --json
    data/shodan.json              <- shodan_search.py --json
    data/asn.json                 <- ipinfo_asn_lookup.py --json
    data/tech.json                 <- tech_fingerprint.py --json
    data/buckets.json              <- cloud_bucket_enum.py --json
    data/handles.json              <- username_presence_check.py --json
    data/takeover.json             <- subdomain_takeover_check.py --json
    data/certs.json                 <- ssl_cert_inspector.py --json
    data/headers.json                <- security_headers_check.py --json
    data/robots_sitemap.json          <- robots_sitemap_recon.py --json
    data/emails.json                  <- email_pattern_generator.py --json

Usage:
    python3 crtsh_subdomains.py example.com --json run/subdomains.json
    python3 whois_dns_recon.py example.com --json run/whois_dns.json
    python3 wayback_urls.py example.com --json run/wayback.json
    python3 shodan_search.py example.com --json run/shodan.json
    python3 ipinfo_asn_lookup.py example.com --json run/asn.json
    python3 tech_fingerprint.py https://example.com --json run/tech.json
    python3 cloud_bucket_enum.py acme --json run/buckets.json
    python3 username_presence_check.py acmecorp --json run/handles.json
    python3 subdomain_takeover_check.py subdomains.txt --json run/takeover.json
    python3 ssl_cert_inspector.py example.com --json run/certs.json
    python3 security_headers_check.py https://example.com --json run/headers.json
    python3 robots_sitemap_recon.py https://example.com --json run/robots_sitemap.json
    python3 email_pattern_generator.py acme.com "Jane Doe" --json run/emails.json

    python3 merge_inventory.py run/ --out run/inventory
    # -> writes run/inventory.json and run/inventory.csv
"""
import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone





def build_inventory(indir: str) -> dict:
    assets = []

    # Subdomains from certificate transparency
    subs = load_json(os.path.join(indir, "data", "subdomains.json"))
    if subs:
        for host in subs:
            assets.append({
                "type": "hostname",
                "value": host,
                "source": "crtsh",
                "detail": {},
            })
        print(f"[+] Loaded {len(subs)} hostnames from subdomains.json")

    # WHOIS + DNS
    whois_dns = load_json(os.path.join(indir, "data", "whois_dns.json"))
    if whois_dns:
        domain = whois_dns.get("domain")
        dns_records = whois_dns.get("dns", {})
        for rtype, values in dns_records.items():
            for value in values:
                assets.append({
                    "type": f"dns_{rtype.lower()}",
                    "value": value,
                    "source": "dns",
                    "detail": {"domain": domain, "record_type": rtype},
                })
        if whois_dns.get("whois"):
            assets.append({
                "type": "whois_record",
                "value": domain,
                "source": "whois",
                "detail": whois_dns["whois"],
            })
        print(f"[+] Loaded WHOIS/DNS data for {domain}")

    # Wayback Machine historical URLs
    wayback = load_json(os.path.join(indir, "data", "wayback.json"))
    if wayback:
        for record in wayback:
            url = record.get("original")
            if not url:
                continue
            assets.append({
                "type": "archived_url",
                "value": url,
                "source": "wayback",
                "detail": record,
            })
        print(f"[+] Loaded {len(wayback)} archived URLs from wayback.json")

    # Shodan
    shodan_data = load_json(os.path.join(indir, "data", "shodan.json"))
    if shodan_data:
        matches = shodan_data.get("matches", [])
        for m in matches:
            ip = m.get("ip_str")
            if ip:
                assets.append({
                    "type": "shodan_host",
                    "value": ip,
                    "source": "shodan",
                    "detail": m,
                })
        print(f"[+] Loaded {len(matches)} Shodan matches")

    # ASN / IP
    asn_data = load_json(os.path.join(indir, "data", "asn.json"))
    if asn_data:
        ip = asn_data.get("ip")
        if ip:
            assets.append({
                "type": "ip_address",
                "value": ip,
                "source": "asn",
                "detail": {"asn": asn_data.get("asn"), "org": asn_data.get("org"), "country": asn_data.get("country")},
            })
        print(f"[+] Loaded ASN/org data for {asn_data.get('target', 'unknown')}")

    # Tech fingerprint
    tech_data = load_json(os.path.join(indir, "data", "tech.json"))
    if tech_data:
        for tech in tech_data.get("technologies", []):
            assets.append({
                "type": "technology",
                "value": tech.get("name", ""),
                "source": "tech_fingerprint",
                "detail": tech,
            })
        print(f"[+] Loaded {len(tech_data.get('technologies', []))} technology signatures")

    # Cloud buckets
    buckets = load_json(os.path.join(indir, "data", "buckets.json"))
    if buckets:
        for b in buckets:
            assets.append({
                "type": "cloud_bucket",
                "value": b.get("url", ""),
                "source": "cloud_bucket_enum",
                "detail": b,
            })
        print(f"[+] Loaded {len(buckets)} cloud bucket(s)")

    # Username handles
    handles = load_json(os.path.join(indir, "data", "handles.json"))
    if handles:
        for h in handles:
            assets.append({
                "type": "username_handle",
                "value": h.get("url", ""),
                "source": "username_presence",
                "detail": h,
            })
        print(f"[+] Loaded {len(handles)} username presence result(s)")

    # Subdomain takeover check
    takeover = load_json(os.path.join(indir, "data", "takeover.json"))
    if takeover:
        for t in takeover:
            assets.append({
                "type": "takeover_candidate",
                "value": t.get("host", ""),
                "source": "subdomain_takeover",
                "detail": t,
            })
        print(f"[+] Loaded {len(takeover)} subdomain takeover candidate(s)")

    # SSL certificate
    certs = load_json(os.path.join(indir, "data", "certs.json"))
    if certs:
        assets.append({
            "type": "ssl_certificate",
            "value": certs.get("hostname", ""),
            "source": "ssl_cert",
            "detail": certs,
        })
        print(f"[+] Loaded TLS certificate data for {certs.get('hostname', 'unknown')}")

    # Security headers
    headers_data = load_json(os.path.join(indir, "data", "headers.json"))
    if headers_data:
        assets.append({
            "type": "security_headers",
            "value": headers_data.get("url", ""),
            "source": "security_headers",
            "detail": headers_data,
        })
        print(f"[+] Loaded security header score for {headers_data.get('url', 'unknown')}: {headers_data.get('score', 'N/A')}/{headers_data.get('max_score', 'N/A')}")

    # Robots / Sitemap
    robots_sitemap = load_json(os.path.join(indir, "data", "robots_sitemap.json"))
    if robots_sitemap:
        for path in robots_sitemap.get("disallow_paths", []):
            assets.append({
                "type": "robots_rule",
                "value": path,
                "source": "robots_sitemap",
                "detail": {"base_url": robots_sitemap.get("base_url", "")},
            })
        for url in robots_sitemap.get("sitemap_urls", []):
            assets.append({
                "type": "sitemap_url",
                "value": url,
                "source": "robots_sitemap",
                "detail": {"base_url": robots_sitemap.get("base_url", "")},
            })
        print(f"[+] Loaded {len(robots_sitemap.get('disallow_paths', []))} robots.txt paths and {len(robots_sitemap.get('sitemap_urls', []))} sitemap URLs")

    # Email patterns
    emails = load_json(os.path.join(indir, "data", "emails.json"))
    if emails:
        for e in emails.get("candidates", []):
            assets.append({
                "type": "email_candidate",
                "value": e.get("email", ""),
                "source": "email_pattern",
                "detail": e,
            })
        print(f"[+] Loaded {len(emails.get('candidates', []))} candidate email address(es)")

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "asset_count": len(assets),
        "assets": assets,
        "target": "",
    }


def write_csv(inventory: dict, path: str):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "value", "source", "detail"])
        for asset in inventory["assets"]:
            writer.writerow([
                asset["type"], asset["value"], asset["source"],
                json.dumps(asset["detail"]),
            ])


def merge_main(args):
    pass  # args provided by unified CLI

    inventory = build_inventory(args.indir)

    json_path = f"{args.out}.json"
    csv_path = f"{args.out}.csv"

    with open(json_path, "w") as f:
        json.dump(inventory, f, indent=2)
    write_csv(inventory, csv_path)

    print(f"\n[+] Merged {inventory['asset_count']} assets")
    print(f"[*] Written {json_path} and {csv_path}")

    if args.html:
        generate_html_report(
            "merge_inventory", args.indir,
            inventory,
            args.html,
            summary=f"Merged {inventory['asset_count']} assets",
        )
        print(f"[*] HTML report written to {args.html}")

    if args.pdf:
        
        generate_pdf_report(
            "merge_inventory", args.indir,
            inventory,
            args.pdf,
            summary=f"Merged {inventory['asset_count']} assets",
        )


# merge_main is called by the unified dispatcher

# =============================================================
# generate_dashboard.py
# =============================================================

#!/usr/bin/env python3
"""
generate_dashboard.py — renders the merged inventory as a single, self-contained
HTML dashboard. No external dependencies; safe to open offline.

Usage:
    python3 generate_dashboard.py reports/inventory.json
    python3 generate_dashboard.py reports/inventory.json --out dashboard.html
"""
import argparse
import json
import os
from collections import Counter
from datetime import datetime, timezone
from html import escape

CSS = """\
:root {
  --bg: #0f1117; --panel: #161923; --border: #262b3a;
  --text: #e6e8ef; --muted: #8b92a8; --accent: #6ea8fe;
  --danger: #ff6b6b; --warn: #ffb454; --ok: #4ade80;
}
* { box-sizing: border-box; }
body {
  margin: 0; font-family: -apple-system, Segoe UI, Roboto, sans-serif;
  background: var(--bg); color: var(--text);
}
header { padding: 20px 24px; border-bottom: 1px solid var(--border); }
header h1 { margin: 0 0 4px; font-size: 18px; }
header p { margin: 0; color: var(--muted); font-size: 12px; }
.wrap { padding: 20px 24px; max-width: 1100px; margin: 0 auto; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-bottom: 16px; }
.card {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: 8px; padding: 14px 16px; text-align: center;
}
.card .num { font-size: 24px; font-weight: 700; color: var(--accent); }
.card .lbl { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 600; }
tr:last-child td { border-bottom: none; }
.badge {
  display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: 11px; font-weight: 600;
}
.badge-ok { background: rgba(74,222,128,0.15); color: var(--ok); }
.badge-warn { background: rgba(255,180,84,0.15); color: var(--warn); }
.badge-danger { background: rgba(255,107,107,0.15); color: var(--danger); }
.badge-info { background: rgba(110,168,254,0.15); color: var(--accent); }
pre {
  background: #0a0c10; border: 1px solid var(--border); border-radius: 6px;
  padding: 12px; overflow-x: auto; font-size: 12px; line-height: 1.5;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
"""


def _badge(text, kind="info"):
    return f'<span class="badge badge-{kind}">{escape(str(text))}</span>'


def dashboard_main(args):
    pass  # args provided by unified CLI

    with open(args.inventory) as f:
        inventory = json.load(f)

    assets = inventory.get("assets", [])
    asset_count = inventory.get("asset_count", len(assets))
    target = inventory.get("target", "unknown")
    generated_at = inventory.get("generated_at", datetime.now(timezone.utc).isoformat())

    type_counts = Counter(a.get("type", "unknown") for a in assets)
    source_counts = Counter(a.get("source", "unknown") for a in assets)

    top_types = type_counts.most_common(10)
    top_sources = source_counts.most_common(10)

    type_rows = "".join(
        f"<tr><td>{escape(t)}</td><td>{c}</td></tr>" for t, c in top_types
    )
    source_rows = "".join(
        f"<tr><td>{escape(s)}</td><td>{c}</td></tr>" for s, c in top_sources
    )

    asset_rows = []
    for a in assets[:500]:
        detail = a.get("detail", {})
        if isinstance(detail, dict):
            detail_str = ", ".join(f"{k}={v}" for k, v in list(detail.items())[:3])
        else:
            detail_str = escape(str(detail))[:120]
        asset_rows.append(
            f"<tr><td>{escape(a.get('type',''))}</td><td>{escape(a.get('value',''))}</td>"
            f"<td>{escape(a.get('source',''))}</td><td>{detail_str}</td></tr>"
        )
    asset_table = "".join(asset_rows)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Dashboard — {escape(target)}</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>Attack Surface Dashboard</h1>
  <p>Target: {escape(target)} &nbsp;|&nbsp; Generated: {escape(generated_at)} &nbsp;|&nbsp; {asset_count} assets</p>
</header>
<div class="wrap">
  <div class="cards">
    <div class="card"><div class="num">{asset_count}</div><div class="lbl">Total Assets</div></div>
    <div class="card"><div class="num">{len(type_counts)}</div><div class="lbl">Types</div></div>
    <div class="card"><div class="num">{len(source_counts)}</div><div class="lbl">Sources</div></div>
  </div>

  <div class="card">
    <h2>Asset Type Breakdown</h2>
    <table><thead><tr><th>Type</th><th>Count</th></tr></thead><tbody>{type_rows}</tbody></table>
  </div>

  <div class="card">
    <h2>Source Breakdown</h2>
    <table><thead><tr><th>Source</th><th>Count</th></tr></thead><tbody>{source_rows}</tbody></table>
  </div>

  <div class="card">
    <h2>Assets</h2>
    <table><thead><tr><th>Type</th><th>Value</th><th>Source</th><th>Detail</th></tr></thead><tbody>{asset_table}</tbody></table>
  </div>
</div>
</body>
</html>"""

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        f.write(html)
    print(f"[+] Dashboard written to {args.out} ({asset_count} assets)")


# dashboard_main is called by the unified dispatcher

# =============================================================
# generate_single_pdf.py
# =============================================================

#!/usr/bin/env python3
"""
generate_single_pdf.py — generates a single combined PDF report from all
scan outputs in a run directory. Reads the merged inventory plus all per-tool
JSON files and produces one self-contained PDF.

Usage:
    python3 generate_single_pdf.py reports/
    python3 generate_single_pdf.py reports/ --out reports/full_report.pdf
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from html import escape

try:
    from weasyprint import HTML as WeasyHTML
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False





def render_section(title, body_html):
    return f"""
    <div class="card">
      <h2>{escape(title)}</h2>
      {body_html}
    </div>
    """


def render_kv_section(title, data):
    if not data:
        return render_section(title, '<p style="color:var(--muted)">No data</p>')
    rows = "".join(f"<tr><td>{escape(str(k))}</td><td>{escape(str(v))}</td></tr>" for k, v in data.items())
    return render_section(title, f'<table><tbody>{rows}</tbody></table>')


def render_list_section(title, items, empty="No items"):
    if not items:
        return render_section(title, f'<p style="color:var(--muted)">{empty}</p>')
    rows = "".join(f"<tr><td>{i+1}</td><td>{escape(str(x))}</td></tr>" for i, x in enumerate(items))
    return render_section(title, f'<table><tbody>{rows}</tbody></table>')


def build_report_html(indir: str, inventory: dict) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    target = inventory.get("target", "unknown")
    asset_count = inventory.get("asset_count", 0)

    whois_data = load_json(os.path.join(indir, "data", "whois_dns.json"))
    subdomains_data = load_json(os.path.join(indir, "data", "subdomains.json"))
    wayback_data = load_json(os.path.join(indir, "data", "wayback.json"))
    asn_data = load_json(os.path.join(indir, "data", "asn.json"))
    tech_data = load_json(os.path.join(indir, "data", "tech.json"))
    buckets_data = load_json(os.path.join(indir, "data", "buckets.json"))
    certs_data = load_json(os.path.join(indir, "data", "certs.json"))
    headers_data = load_json(os.path.join(indir, "data", "headers.json"))
    robots_data = load_json(os.path.join(indir, "data", "robots_sitemap.json"))
    takeover_data = load_json(os.path.join(indir, "data", "takeover.json"))
    handles_data = load_json(os.path.join(indir, "data", "handles.json"))
    emails_data = load_json(os.path.join(indir, "data", "emails.json"))
    github_data = load_json(os.path.join(indir, "data", "github_dorks.json")) if os.path.isfile(os.path.join(indir, "data", "github_dorks.json")) else None

    parts = []

    parts.append(render_section("Summary", f"""
      <p><strong>Target:</strong> {escape(target)}</p>
      <p><strong>Generated:</strong> {ts}</p>
      <p><strong>Total Assets:</strong> {asset_count}</p>
    """))

    if whois_data:
        parts.append(render_kv_section("WHOIS / DNS", whois_data))

    if subdomains_data and isinstance(subdomains_data, list):
        parts.append(render_list_section("Subdomains (Certificate Transparency)", subdomains_data, "No subdomains found"))
    elif subdomains_data and isinstance(subdomains_data, dict):
        parts.append(render_kv_section("Subdomains (Certificate Transparency)", subdomains_data))

    if asn_data:
        parts.append(render_kv_section("ASN / IP Info", asn_data))

    if tech_data:
        parts.append(render_kv_section("Technology Fingerprint", tech_data))

    if headers_data:
        parts.append(render_kv_section("Security Headers", headers_data))

    if certs_data:
        parts.append(render_kv_section("SSL/TLS Certificate", certs_data))

    if wayback_data and isinstance(wayback_data, list):
        parts.append(render_section("Wayback Machine URLs", f'<p style="color:var(--muted)">{len(wayback_data)} archived URL(s)</p>' + render_list_section("Sample URLs", wayback_data[:50], "No URLs")))
    elif wayback_data:
        parts.append(render_kv_section("Wayback Machine", wayback_data))

    if takeover_data:
        if isinstance(takeover_data, list):
            parts.append(render_list_section("Subdomain Takeover Check", takeover_data, "No takeover candidates"))
        else:
            parts.append(render_kv_section("Subdomain Takeover Check", takeover_data))

    if buckets_data:
        parts.append(render_kv_section("Cloud Bucket Enumeration", buckets_data))

    if robots_data:
        parts.append(render_kv_section("Robots.txt / Sitemap", robots_data))

    if handles_data and isinstance(handles_data, list):
        parts.append(render_section("Username Presence", f'<p style="color:var(--muted)">{len(handles_data)} platform(s) checked</p>' + render_list_section("Platforms", handles_data)))
    elif handles_data:
        parts.append(render_kv_section("Username Presence", handles_data))

    if emails_data:
        parts.append(render_kv_section("Email Pattern Candidates", emails_data))

    if github_data:
        parts.append(render_kv_section("GitHub Code Search Dorks", github_data))

    body = "".join(parts)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Full Report — {escape(target)}</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>Full Recon Report</h1>
  <p>Target: {escape(target)} &nbsp;|&nbsp; {ts} &nbsp;|&nbsp; Attack Surface Toolkit</p>
</header>
<div class="wrap">
{body}
</div>
</body>
</html>"""


def pdf_report_main(args):
    pass  # args provided by unified CLI

    if not HAS_WEASYPRINT:
        print("[!] weasyprint not installed. Install it with: pip install weasyprint")
        sys.exit(1)

    inventory_path = os.path.join(args.indir, "reports", args.inventory)
    if not os.path.isfile(inventory_path):
        print(f"[!] Inventory not found at {inventory_path}")
        sys.exit(1)

    with open(inventory_path) as f:
        inventory = json.load(f)

    out_path = args.out or os.path.join(args.indir, "reports", "report.pdf")
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    html_content = build_report_html(args.indir, inventory)
    html_path = out_path + ".tmp.html"
    with open(html_path, "w") as f:
        f.write(html_content)

    try:
        WeasyHTML(filename=html_path).write_pdf(out_path)
        print(f"[+] Single PDF report written to {out_path}")
    except Exception as e:
        print(f"[!] PDF generation failed: {e}")
        sys.exit(1)
    finally:
        if os.path.exists(html_path):
            os.remove(html_path)


# pdf_report_main is called by the unified dispatcher

# =============================================================
# run_pipeline.py
# =============================================================

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


def run_pipeline_main(args):
    pass  # args provided by unified CLI

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


# run_pipeline_main is called by the unified dispatcher

# ============================================================
# WRAPPER FUNCTIONS (for programmatic use / pipeline)
# ============================================================

def run_crtsh(domain, json_path, html_path, pdf_path, txt_path):
    class Args:
        pass
    args = Args()
    args.domain = domain
    args.json = json
    args.html = html
    args.pdf = pdf
    args.txt = txt
    crtsh_main(args)

def run_whois(domain, json_path, html_path, pdf_path):
    class Args:
        pass
    args = Args()
    args.domain = domain
    args.json = json
    args.html = html
    args.pdf = pdf
    whois_main(args)

def run_wayback(domain, json_path, html_path, pdf_path, interesting_only):
    class Args:
        pass
    args = Args()
    args.domain = domain
    args.json = json
    args.html = html
    args.pdf = pdf
    args.interesting_only = interesting_only
    wayback_main(args)

def run_ipinfo(target, json_path, html_path, pdf_path):
    class Args:
        pass
    args = Args()
    args.target = target
    args.json = json
    args.html = html
    args.pdf = pdf
    ipinfo_main(args)

def run_tech(url, json_path, html_path, pdf_path):
    class Args:
        pass
    args = Args()
    args.url = url
    args.json = json
    args.html = html
    args.pdf = pdf
    tech_main(args)

def run_buckets(base, json_path, html_path, pdf_path, words, providers, delay):
    class Args:
        pass
    args = Args()
    args.base = base
    args.json = json
    args.html = html
    args.pdf = pdf
    args.words = words or ""
    args.providers = providers or "aws_s3,gcs,azure_blob"
    args.delay = delay
    buckets_main(args)

def run_ssl(hostname, json_path, html_path, pdf_path, port):
    class Args:
        pass
    args = Args()
    args.hostname = hostname
    args.json = json
    args.html = html
    args.pdf = pdf
    args.port = port
    ssl_main(args)

def run_headers(url, json_path, html_path, pdf_path):
    class Args:
        pass
    args = Args()
    args.url = url
    args.json = json
    args.html = html
    args.pdf = pdf
    headers_main(args)

def run_robots(base_url, json_path, html_path, pdf_path):
    class Args:
        pass
    args = Args()
    args.base_url = base_url
    args.json = json
    args.html = html
    args.pdf = pdf
    robots_main(args)

def run_takeover(input_path, json_path, html_path, pdf_path):
    class Args:
        pass
    args = Args()
    args.input = input
    args.json = json
    args.html = html
    args.pdf = pdf
    takeover_main(args)

def run_username(username, json_path, html_path, pdf_path, delay):
    class Args:
        pass
    args = Args()
    args.username = username
    args.json = json
    args.html = html
    args.pdf = pdf
    args.delay = delay
    username_main(args)

def run_email(domain, names, json_path, html_path, pdf_path, names_file, pattern):
    class Args:
        pass
    args = Args()
    args.domain = domain
    args.names = names or []
    args.json = json
    args.html = html
    args.pdf = pdf
    args.names_file = names_file
    args.pattern = pattern
    email_main(args)

def run_shodan(query, json_path, html_path, pdf_path, limit):
    class Args:
        pass
    args = Args()
    args.query = query
    args.json = json
    args.html = html
    args.pdf = pdf
    args.limit = limit
    shodan_main(args)

def run_github(org, domain, html_path, pdf_path):
    class Args:
        pass
    args = Args()
    args.org = org
    args.domain = domain
    args.html = html
    args.pdf = pdf
    github_main(args)

def run_dorks(org, domain, html_path, pdf_path):
    class Args:
        pass
    args = Args()
    args.org = org
    args.domain = domain
    args.html = html
    args.pdf = pdf
    dorks_main(args)

def run_axfr(domain, html_path, pdf_path):
    class Args:
        pass
    args = Args()
    args.domain = domain
    args.html = html
    args.pdf = pdf
    axfr_main(args)

def run_merge(indir, html_path, pdf_path, out):
    class Args:
        pass
    args = Args()
    args.indir = indir
    args.html = html
    args.pdf = pdf
    args.out = out
    merge_main(args)

def run_dashboard(inventory, out):
    class Args:
        pass
    args = Args()
    args.inventory = inventory
    args.out = out
    dashboard_main(args)

def run_pdf_report(indir, out, inventory):
    class Args:
        pass
    args = Args()
    args.indir = indir
    args.out = out
    args.inventory = inventory
    pdf_report_main(args)

def run_pipeline(domain, outdir="reports", skip=None, no_pdf=False, venv=None):
    """Run the full recon pipeline programmatically."""
    if skip is None:
        skip = set()
    py = os.path.join(venv or "scripts/venv", "bin", "python")
    if not os.path.isfile(py):
        raise RuntimeError(f"Venv not found at {py}")

    os.makedirs(outdir, exist_ok=True)
    os.makedirs(os.path.join(outdir, "data"), exist_ok=True)
    os.makedirs(os.path.join(outdir, "reports"), exist_ok=True)

    def run_cmd(cmd_list):
        print(f"[*] $ {' '.join(cmd_list)}")
        subprocess.run(cmd_list, check=True)

    tools = [
        ("crtsh", [domain, "--json", f"{outdir}/data/subdomains.json", "--txt", f"{outdir}/data/subdomains.txt"]),
        ("whois", [domain, "--json", f"{outdir}/data/whois_dns.json"]),
        ("wayback", [domain, "--json", f"{outdir}/data/wayback.json"]),
        ("ipinfo", [domain, "--json", f"{outdir}/data/asn.json"]),
        ("axfr", [domain]),
        ("tech", [f"https://{domain}", "--json", f"{outdir}/data/tech.json"]),
        ("buckets", [domain, "--json", f"{outdir}/data/buckets.json"]),
        ("ssl", [domain, "--json", f"{outdir}/data/certs.json"]),
        ("headers", [f"https://{domain}", "--json", f"{outdir}/data/headers.json"]),
        ("robots", [f"https://{domain}", "--json", f"{outdir}/data/robots_sitemap.json"]),
        ("takeover", [f"{outdir}/data/subdomains.txt", "--json", f"{outdir}/data/takeover.json"]),
        ("username", [domain, "--json", f"{outdir}/data/handles.json"]),
        ("email", [domain, "User", "User", "--json", f"{outdir}/data/emails.json"]),
    ]

    for tool_name, tool_args in tools:
        if tool_name in skip:
            print(f"[i] Skipping {tool_name}")
            continue
        cmd = [py, os.path.join("scripts", f"{tool_name}.py")] + tool_args
        try:
            run_cmd(cmd)
        except subprocess.CalledProcessError as e:
            print(f"[!] {tool_name} failed with exit code {e.returncode}")

    merge_cmd = [py, "scripts/merge_inventory.py", f"{outdir}/", "--out", f"{outdir}/reports/inventory"]
    dash_cmd = [py, "scripts/generate_dashboard.py", f"{outdir}/reports/inventory.json", "--out", f"{outdir}/reports/report.html"]

    try:
        run_cmd(merge_cmd)
    except subprocess.CalledProcessError as e:
        print(f"[!] merge_inventory.py failed: {e}")

    try:
        run_cmd(dash_cmd)
    except subprocess.CalledProcessError as e:
        print(f"[!] generate_dashboard.py failed: {e}")

    if not no_pdf:
        pdf_cmd = [py, "scripts/generate_single_pdf.py", outdir, "--out", f"{outdir}/reports/report.pdf"]
        try:
            run_cmd(pdf_cmd)
        except subprocess.CalledProcessError as e:
            print(f"[!] generate_single_pdf.py failed: {e}")

    print(f"\n[+] Pipeline complete.")
    print(f"    Data      : {outdir}/data/")
    print(f"    Reports   : {outdir}/reports/")
    print(f"    HTML      : {outdir}/reports/report.html")
    if not no_pdf:
        print(f"    PDF       : {outdir}/reports/report.pdf")

# ============================================================
# UNIFIED CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Attack Surface Toolkit — single-file recon")
    subparsers = parser.add_subparsers(dest="tool")

    p = subparsers.add_parser("run-pipeline", help="Run full recon pipeline")
    p.add_argument("domain")
    p.add_argument("--out", default="reports")
    p.add_argument("--skip", nargs="*", default=[])
    p.add_argument("--no-pdf", action="store_true")

    p = subparsers.add_parser("run-quick", help="Run fast subset")
    p.add_argument("domain")
    p.add_argument("--out", default="reports")
    p.add_argument("--no-pdf", action="store_true")

    p = subparsers.add_parser("run-no-pdf", help="Run without PDF")
    p.add_argument("domain")
    p.add_argument("--out", default="reports")

    p = subparsers.add_parser("crtsh")
    p.add_argument("domain")
    p.add_argument("--json")
    p.add_argument("--html")
    p.add_argument("--pdf")
    p.add_argument("--txt")

    p = subparsers.add_parser("whois")
    p.add_argument("domain")
    p.add_argument("--json")
    p.add_argument("--html")
    p.add_argument("--pdf")

    p = subparsers.add_parser("wayback")
    p.add_argument("domain")
    p.add_argument("--interesting-only", action="store_true")
    p.add_argument("--json")
    p.add_argument("--html")
    p.add_argument("--pdf")

    p = subparsers.add_parser("ipinfo")
    p.add_argument("target")
    p.add_argument("--json")
    p.add_argument("--html")
    p.add_argument("--pdf")

    p = subparsers.add_parser("tech")
    p.add_argument("url")
    p.add_argument("--json")
    p.add_argument("--html")
    p.add_argument("--pdf")

    p = subparsers.add_parser("buckets")
    p.add_argument("base")
    p.add_argument("--words", default="")
    p.add_argument("--providers", default="aws_s3,gcs,azure_blob")
    p.add_argument("--delay", type=float, default=0.3)
    p.add_argument("--json")
    p.add_argument("--html")
    p.add_argument("--pdf")

    p = subparsers.add_parser("ssl")
    p.add_argument("hostname")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--json")
    p.add_argument("--html")
    p.add_argument("--pdf")

    p = subparsers.add_parser("headers")
    p.add_argument("url")
    p.add_argument("--json")
    p.add_argument("--html")
    p.add_argument("--pdf")

    p = subparsers.add_parser("robots")
    p.add_argument("base_url")
    p.add_argument("--json")
    p.add_argument("--html")
    p.add_argument("--pdf")

    p = subparsers.add_parser("takeover")
    p.add_argument("input")
    p.add_argument("--json")
    p.add_argument("--html")
    p.add_argument("--pdf")

    p = subparsers.add_parser("username")
    p.add_argument("username")
    p.add_argument("--delay", type=float, default=0.5)
    p.add_argument("--json")
    p.add_argument("--html")
    p.add_argument("--pdf")

    p = subparsers.add_parser("email")
    p.add_argument("domain")
    p.add_argument("names", nargs="*")
    p.add_argument("--names-file")
    p.add_argument("--pattern")
    p.add_argument("--json")
    p.add_argument("--html")
    p.add_argument("--pdf")

    p = subparsers.add_parser("shodan")
    p.add_argument("query")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--json")
    p.add_argument("--html")
    p.add_argument("--pdf")

    p = subparsers.add_parser("github")
    p.add_argument("org")
    p.add_argument("domain")
    p.add_argument("--html")
    p.add_argument("--pdf")

    p = subparsers.add_parser("dorks")
    p.add_argument("org")
    p.add_argument("domain")
    p.add_argument("--html")
    p.add_argument("--pdf")

    p = subparsers.add_parser("axfr")
    p.add_argument("domain")
    p.add_argument("--html")
    p.add_argument("--pdf")

    p = subparsers.add_parser("merge")
    p.add_argument("indir")
    p.add_argument("--html")
    p.add_argument("--pdf")
    p.add_argument("--out", default="inventory")

    p = subparsers.add_parser("dashboard")
    p.add_argument("inventory")
    p.add_argument("--out", default="dashboard.html")

    p = subparsers.add_parser("pdf")
    p.add_argument("indir")
    p.add_argument("--out")
    p.add_argument("--inventory", default="inventory.json")

    args = parser.parse_args()

    if not args.tool:
        parser.print_help()
        return

    dispatch = {
        "run-pipeline": run_pipeline_main,
        "run-quick": run_pipeline_main,
        "run-no-pdf": run_pipeline_main,
        "crtsh": crtsh_main,
        "whois": whois_main,
        "wayback": wayback_main,
        "ipinfo": ipinfo_main,
        "tech": tech_main,
        "buckets": buckets_main,
        "ssl": ssl_main,
        "headers": headers_main,
        "robots": robots_main,
        "takeover": takeover_main,
        "username": username_main,
        "email": email_main,
        "shodan": shodan_main,
        "github": github_main,
        "dorks": dorks_main,
        "axfr": axfr_main,
        "merge": merge_main,
        "dashboard": dashboard_main,
        "pdf": pdf_report_main,
    }
    fn = dispatch.get(args.tool)
    if fn:
        fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
