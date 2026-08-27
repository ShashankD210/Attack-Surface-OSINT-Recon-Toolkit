#!/usr/bin/env bash
#
# recon_orchestrator.sh — chains well-known external recon CLI tools if you
# already have them installed. Does not install, download, or bundle any
# scanning/exploitation tooling itself; it's a scaffold to wire your own
# toolchain together against AUTHORIZED targets only.
#
# Expected external tools (install separately, official sources only):
#   subfinder  - https://github.com/projectdiscovery/subfinder
#   dnsx       - https://github.com/projectdiscovery/dnsx
#   httpx      - https://github.com/projectdiscovery/httpx
#
# Usage:
#   ./recon_orchestrator.sh example.com ./output_dir
#
set -euo pipefail

DOMAIN="${1:?Usage: $0 <domain> [output_dir]}"
OUTDIR="${2:-./recon_output}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="${SCRIPT_DIR}/../scripts/venv/bin/python"

mkdir -p "$OUTDIR"

echo "[*] Recon run for: $DOMAIN"
echo "[*] Output directory: $OUTDIR"
echo "[!] Only proceed if you have written authorization to test this target."
read -r -p "Type 'yes' to continue: " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    echo "Aborting."
    exit 1
fi

require_tool() {
    if ! command -v "$1" &>/dev/null; then
        echo "[!] '$1' not found on PATH — skipping this stage."
        return 1
    fi
    return 0
}

# Stage 1: passive subdomain enumeration
if require_tool subfinder; then
    echo "[*] Running subfinder..."
    subfinder -d "$DOMAIN" -silent -o "$OUTDIR/subdomains.txt"
    echo "[+] $(wc -l < "$OUTDIR/subdomains.txt") subdomains found"
fi

# Stage 2: DNS resolution of candidates
if [[ -f "$OUTDIR/subdomains.txt" ]] && require_tool dnsx; then
    echo "[*] Resolving with dnsx..."
    dnsx -l "$OUTDIR/subdomains.txt" -silent -o "$OUTDIR/resolved.txt"
    echo "[+] $(wc -l < "$OUTDIR/resolved.txt") hosts resolved"
fi

# Stage 3: HTTP probing + fingerprinting of resolved hosts
if [[ -f "$OUTDIR/resolved.txt" ]] && require_tool httpx; then
    echo "[*] Probing HTTP(S) with httpx..."
    httpx -l "$OUTDIR/resolved.txt" -silent -title -status-code -tech-detect \
        -o "$OUTDIR/http_probe.txt"
    echo "[+] Results written to $OUTDIR/http_probe.txt"
fi

# Stage 4: merge into toolkit inventory if Python venv exists
if [[ -f "$VENV_PY" && -f "$SCRIPT_DIR/merge_inventory.py" ]]; then
    echo "[*] Merging into toolkit inventory..."
    cp "$OUTDIR"/subdomains.txt "$OUTDIR/../run/subdomains.txt" 2>/dev/null || true
    "$VENV_PY" "$SCRIPT_DIR/merge_inventory.py" "$OUTDIR/" --out "$OUTDIR/inventory" 2>/dev/null || true
fi

echo "[*] Done. Review outputs in $OUTDIR/"
echo "[i] Add authorized port scanning / vuln-template stages here as needed,"
echo "    scoped strictly to the domain/IP ranges covered by your RoE."
