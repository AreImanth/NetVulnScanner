#!/usr/bin/env python3
"""
scanner.py — Network Vulnerability Scanner (Lab 03 reference implementation)
"""

import argparse
import csv
import json
import os
import re
import sys
import time
from datetime import datetime

try:
    import nmap
except ImportError:
    sys.exit("Missing dependency: pip install python-nmap")

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_FILE = "cve_cache.json"
NO_KEY_DELAY = 6.5    # seconds between NVD requests without an API key
WITH_KEY_DELAY = 0.7  # seconds between NVD requests with an API key
REPORT_TITLE = "Network Vulnerability Assessment Report"
ORG_NAME = "Cybersecurity Lab"

# Mapping Nmap product strings to (vendor, product)
CPE_MAP = {
    "apache httpd": ("apache", "http_server"),
    "apache": ("apache", "http_server"),
    "openssh": ("openbsd", "openssh"),
    "nginx": ("nginx", "nginx"),
    "microsoft-ds": ("microsoft", "windows"),
    "smb": ("microsoft", "windows"),
}

REMEDIATION_MAP = {
    "ssh": "Disable password authentication in favor of key-based auth; enforce a strong "
           "password policy; add fail2ban or similar rate-limiting; restrict source IPs via firewall.",
    "http": "Disable directory listing (Options -Indexes); remove sensitive/backup files from "
            "the web root; add standard security headers; keep the web server patched.",
    "apache": "Disable directory listing (Options -Indexes); remove sensitive/backup files from "
              "the web root; add standard security headers; keep Apache patched to the latest "
              "stable release for your distribution.",
    "smb": "Disable SMBv1; require SMB signing; restrict access via firewall/VLAN; patch to the "
           "latest supported build.",
    "microsoft-ds": "Disable SMBv1; require SMB signing; restrict access via firewall/VLAN; "
                    "patch to the latest supported build.",
}
DEFAULT_REMEDIATION = ("Review service configuration against vendor hardening guidance; "
                        "patch to the latest stable version; restrict network exposure.")


def score_to_severity(score):
    """CVSS v3.x band mapping."""
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Informational"


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational", "CWE", "No CVE", "Unknown"]
SEVERITY_COLOR = {
    "Critical": "#b91c1c",
    "High": "#c2410c",
    "Medium": "#a16207",
    "Low": "#15803d",
    "Informational": "#1d4ed8",
    "CWE": "#6d28d9",
    "No CVE": "#475569",
    "Unknown": "#64748b",
}
SEVERITY_BG = {
    "Critical": "#fef2f2",
    "High": "#fff7ed",
    "Medium": "#fefce8",
    "Low": "#f0fdf4",
    "Informational": "#eff6ff",
    "CWE": "#f5f3ff",
    "No CVE": "#f8fafc",
    "Unknown": "#f8fafc",
}


# --------------------------------------------------------------------------
# 5.1 — Host discovery
# --------------------------------------------------------------------------

def load_scope(scope_path):
    if not os.path.exists(scope_path):
        sys.exit(f"Scope file not found: {scope_path}")
    with open(scope_path) as f:
        lines = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
    if not lines:
        sys.exit(f"Scope file {scope_path} is empty — refusing to scan nothing.")
    return lines


def discover_hosts(nm, targets):
    live_hosts = []
    for target in targets:
        print(f"[*] Discovering hosts in {target} ...")
        nm.scan(hosts=target, arguments="-sn")
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                live_hosts.append(host)
                print(f"    [+] Live host: {host}")
    return live_hosts


# --------------------------------------------------------------------------
# 5.2 — Service & version detection
# --------------------------------------------------------------------------

def scan_services(nm, host):
    print(f"[*] Scanning services on {host} ...")
    nm.scan(hosts=host, arguments="-sV")
    entries = []
    if host not in nm.all_hosts():
        return entries
    for proto in nm[host].all_protocols():
        ports = nm[host][proto].keys()
        for port in sorted(ports):
            svc = nm[host][proto][port]
            product = svc.get("product", "")
            raw_version = svc.get("version", "")
            entries.append({
                "host": host,
                "port": port,
                "protocol": proto,
                "service": svc.get("name", "unknown"),
                "product": product,
                "version": raw_version,
                "banner": f"{product} {raw_version}".strip(),
            })
    return entries


# --------------------------------------------------------------------------
# 5.3 — CVE mapping & severity scoring
# --------------------------------------------------------------------------

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE) as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}


def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def _clean_version(raw_version):
    """
    Extracts cleaner base version components.
    Example: '9.6p1 Ubuntu-3ubuntu13.19' -> ('9.6', 'p1') or ('9.6p1', '')
    """
    if not raw_version:
        return "", ""
    
    version = raw_version.strip()
    version = re.sub(r"\(.*?\)", "", version).strip()
    first_chunk = version.split()[0] if version.split() else ""
    
    # Extract patch level if formatted like '9.6p1'
    match = re.match(r"^(\d+\.[\d\.]+)(p\d+)?$", first_chunk, re.IGNORECASE)
    if match:
        base_ver = match.group(1)
        patch = match.group(2) if match.group(2) else "*"
        return base_ver, patch
    
    return first_chunk, "*"


def _cpe_for_product(product):
    key = product.lower().strip()
    for name, vendor_prod in CPE_MAP.items():
        if name in key:
            return vendor_prod
    return None, None


def _fetch_nvd(params, headers):
    resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=15)
    resp.raise_for_status()
    return resp.json()


def _parse_cve_items(data):
    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        descriptions = cve.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        score = None
        metrics = cve.get("metrics", {})
        # Look for CVSS v3.1, v3.0, or v2 base scores
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                score = metrics[key][0]["cvssData"].get("baseScore")
                break

        results.append({
            "cve_id": cve_id,
            "description": description[:220],
            "cvss_score": score,
            "severity": score_to_severity(score),
        })
    return results


def query_nvd(product, raw_version, api_key=None):
    """
    Queries NVD REST API 2.0 with proper CPE string formatting and multi-stage fallbacks.
    """
    if not product:
        return []

    headers = {"apiKey": api_key} if api_key else {}
    base_version, patch = _clean_version(raw_version)
    vendor, cpe_prod = _cpe_for_product(product)

    all_results = {}

    # --- Method 1: CPE Name Lookup (Structured) ---
    if vendor and cpe_prod and base_version:
        # Full 13-part CPE 2.3 URI formulation
        cpe_name = f"cpe:2.3:a:{vendor}:{cpe_prod}:{base_version}:{patch}:*:*:*:*:*:*"
        try:
            data = _fetch_nvd({"cpeName": cpe_name, "resultsPerPage": 20}, headers)
            for r in _parse_cve_items(data):
                all_results[r["cve_id"]] = r
        except requests.RequestException as e:
            print(f"    [!] NVD exact CPE lookup failed for '{cpe_name}': {e}")

    # --- Method 2: Broader Keyword Search Fallback ---
    if not all_results:
        # Formulate search queries that match NVD text formats (e.g., 'OpenSSH 9.6')
        clean_raw = raw_version.split()[0] if raw_version else ""
        keyword_queries = [
            f"{product} {base_version}".strip(),
            f"{product} {clean_raw}".strip()
        ]
        
        for kw in set(keyword_queries):
            if not kw:
                continue
            try:
                time.sleep(0.3 if api_key else 1.0)
                data = _fetch_nvd({"keywordSearch": kw, "resultsPerPage": 20}, headers)
                for r in _parse_cve_items(data):
                    all_results.setdefault(r["cve_id"], r)
                if all_results:
                    break
            except requests.RequestException as e:
                print(f"    [!] NVD keyword lookup failed for '{kw}': {e}")

    merged = sorted(all_results.values(), key=lambda c: (c["cvss_score"] or 0), reverse=True)
    return merged[:10]


def enrich_with_cves(service_entries, api_key=None, skip=False):
    cache = load_cache()
    delay = WITH_KEY_DELAY if api_key else NO_KEY_DELAY

    for entry in service_entries:
        if skip:
            entry["findings"] = [{
                "type": "skipped", "id": "N/A", "severity": "Unknown",
                "note": "CVE lookup skipped (--no-cve-lookup)"
            }]
            continue

        base_ver, patch = _clean_version(entry["version"])
        cache_key = f"{entry['product']}|{base_ver}|{patch}".lower().strip()

        if not entry["product"]:
            entry["findings"] = [{
                "type": "no_cve", "id": "N/A", "severity": "No CVE",
                "note": "No product/version banner returned by Nmap — manual review required"
            }]
            continue

        if cache_key in cache:
            cves = cache[cache_key]
        else:
            cves = query_nvd(entry["product"], entry["version"], api_key=api_key)
            cache[cache_key] = cves
            save_cache(cache)
            time.sleep(delay)

        if cves:
            entry["findings"] = [
                {"type": "cve", "id": c["cve_id"], "severity": c["severity"],
                 "cvss_score": c["cvss_score"], "note": c["description"]}
                for c in cves
            ]
        else:
            entry["findings"] = [{
                "type": "no_cve", "id": "N/A", "severity": "No CVE",
                "note": (f"No known CVEs returned for {entry['product']} {entry['version']}. "
                         f"Verify patch level or check for configuration weaknesses.")
            }]

    return service_entries


def get_remediation(service_name, product):
    text = f"{service_name} {product}".lower()
    for key, advice in REMEDIATION_MAP.items():
        if key in text:
            return advice
    return DEFAULT_REMEDIATION


# --------------------------------------------------------------------------
# 5.4 — Report generation
# --------------------------------------------------------------------------

def build_report_rows(service_entries):
    rows = []
    for entry in service_entries:
        remediation = get_remediation(entry["service"], entry["product"])
        for finding in entry["findings"]:
            rows.append({
                "Host": entry["host"],
                "Port": entry["port"],
                "Protocol": entry.get("protocol", "tcp"),
                "Service": entry["service"],
                "Version": entry["banner"] or "unknown",
                "Finding": finding["id"],
                "CVSS Score": finding.get("cvss_score", "N/A"),
                "Severity": finding["severity"],
                "Remediation": remediation,
                "Notes": finding.get("note", ""),
            })
    return rows


def write_csv(rows, path="vuln_report.csv"):
    if not rows:
        print("[!] No rows to write to CSV.")
        return
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"[+] CSV report written: {path}")


def _severity_sort_key(row):
    sev = row["Severity"]
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


def write_html(rows, live_hosts, scope_targets, scan_start, path="vuln_report.html"):
    scan_end = datetime.now()
    duration = (scan_end - scan_start).total_seconds()

    total_hosts = len(live_hosts)
    total_findings = len(rows)
    severity_counts = {}
    for r in rows:
        severity_counts[r["Severity"]] = severity_counts.get(r["Severity"], 0) + 1

    ordered_counts = [(s, severity_counts.get(s, 0)) for s in SEVERITY_ORDER if severity_counts.get(s, 0) > 0]

    summary_cards = "".join(
        f'''<div class="card" style="border-top-color:{SEVERITY_COLOR.get(sev,"#64748b")}">
              <div class="card-count" style="color:{SEVERITY_COLOR.get(sev,"#64748b")}">{count}</div>
              <div class="card-label">{sev}</div>
            </div>'''
        for sev, count in ordered_counts
    )

    hosts_in_order = list(dict.fromkeys(r["Host"] for r in rows)) or live_hosts
    host_sections = ""
    for host in hosts_in_order:
        host_rows = sorted([r for r in rows if r["Host"] == host], key=_severity_sort_key)
        if not host_rows:
            continue
        ports_summary = sorted({f'{r["Port"]}/{r["Protocol"]}' for r in host_rows})
        table_rows = ""
        for r in host_rows:
            color = SEVERITY_COLOR.get(r["Severity"], "#64748b")
            bg = SEVERITY_BG.get(r["Severity"], "#f8fafc")
            cvss_display = r["CVSS Score"] if r["CVSS Score"] not in (None, "N/A") else "—"
            table_rows += f'''
            <tr>
              <td class="mono">{r["Port"]}/{r["Protocol"]}</td>
              <td>{r["Service"]}</td>
              <td class="mono">{r["Version"]}</td>
              <td class="mono">{r["Finding"]}</td>
              <td class="center">{cvss_display}</td>
              <td><span class="badge" style="background:{bg};color:{color};border:1px solid {color}33">{r["Severity"]}</span></td>
              <td class="notes">{r["Notes"]}</td>
              <td class="remediation">{r["Remediation"]}</td>
            </tr>'''
        host_sections += f'''
        <div class="host-section">
          <div class="host-header">
            <h3>Host: <span class="mono">{host}</span></h3>
            <span class="host-meta">{len(host_rows)} finding(s) &middot; open ports: {", ".join(ports_summary)}</span>
          </div>
          <table>
            <thead>
              <tr>
                <th>Port</th><th>Service</th><th>Version</th><th>Finding</th>
                <th>CVSS</th><th>Severity</th><th>Notes</th><th>Remediation</th>
              </tr>
            </thead>
            <tbody>{table_rows}
            </tbody>
          </table>
        </div>'''

    scope_list = "".join(f"<li class='mono'>{t}</li>" for t in scope_targets)

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{REPORT_TITLE}</title>
<style>
  :root {{
    --ink: #0f172a; --muted: #64748b; --border: #e2e8f0; --bg: #f8fafc;
    --accent: #1e293b;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: 'Segoe UI', -apple-system, Helvetica, Arial, sans-serif;
    margin: 0; color: var(--ink); background: #ffffff; line-height: 1.5;
  }}
  .cover {{
    background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
    color: #fff; padding: 56px 48px 40px;
  }}
  .cover .eyebrow {{
    text-transform: uppercase; letter-spacing: 2px; font-size: 12px;
    color: #93c5fd; font-weight: 600; margin-bottom: 10px;
  }}
  .cover h1 {{ margin: 0 0 8px; font-size: 30px; font-weight: 700; }}
  .cover .org {{ color: #cbd5e1; font-size: 14px; margin-bottom: 28px; }}
  .meta-grid {{
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px;
    border-top: 1px solid rgba(255,255,255,0.15); padding-top: 20px; margin-top: 8px;
  }}
  .meta-grid div .label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #93c5fd; }}
  .meta-grid div .value {{ font-size: 14px; margin-top: 4px; font-weight: 600; }}

  .container {{ max-width: 1180px; margin: 0 auto; padding: 40px 48px 64px; }}

  h2.section-title {{
    font-size: 18px; font-weight: 700; margin: 40px 0 16px;
    padding-bottom: 8px; border-bottom: 2px solid var(--accent);
  }}

  .summary-cards {{ display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 8px; }}
  .card {{
    background: #fff; border: 1px solid var(--border); border-top: 4px solid #64748b;
    border-radius: 6px; padding: 16px 22px; min-width: 120px; text-align: center;
    box-shadow: 0 1px 2px rgba(0,0,0,0.04);
  }}
  .card-count {{ font-size: 28px; font-weight: 800; }}
  .card-label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.6px; color: var(--muted); margin-top: 4px; }}

  .scope-box {{
    background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
    padding: 18px 22px; font-size: 13px;
  }}
  .scope-box ul {{ margin: 8px 0 0 18px; padding: 0; }}

  .host-section {{ margin-bottom: 32px; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  .host-header {{
    background: var(--accent); color: #fff; padding: 12px 18px;
    display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; gap: 8px;
  }}
  .host-header h3 {{ margin: 0; font-size: 15px; }}
  .host-meta {{ font-size: 12px; color: #cbd5e1; }}

  table {{ width: 100%; border-collapse: collapse; font-size: 12.5px; }}
  thead th {{
    background: #f1f5f9; text-align: left; padding: 10px 12px; font-size: 11px;
    text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted);
    border-bottom: 1px solid var(--border);
  }}
  tbody td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tbody tr:last-child td {{ border-bottom: none; }}
  tbody tr:hover {{ background: #fafbfc; }}
  .mono {{ font-family: 'SF Mono', Consolas, Monaco, monospace; font-size: 12px; }}
  .center {{ text-align: center; }}
  .notes {{ max-width: 260px; color: #475569; }}
  .remediation {{ max-width: 260px; color: #1e293b; }}
  .badge {{
    display: inline-block; padding: 3px 10px; border-radius: 20px;
    font-size: 11px; font-weight: 700; white-space: nowrap;
  }}

  footer {{
    border-top: 1px solid var(--border); margin-top: 48px; padding-top: 20px;
    font-size: 11.5px; color: var(--muted); display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px;
  }}

  @media print {{
    .cover {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .host-section {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>

  <div class="cover">
    <div class="eyebrow">Confidential — Internal Training Use Only</div>
    <h1>{REPORT_TITLE}</h1>
    <div class="org">{ORG_NAME} &middot; Lab 03 — Network Vulnerability Scanner</div>
    <div class="meta-grid">
      <div><div class="label">Scan Start</div><div class="value">{scan_start.strftime("%Y-%m-%d %H:%M:%S")}</div></div>
      <div><div class="label">Scan End</div><div class="value">{scan_end.strftime("%Y-%m-%d %H:%M:%S")}</div></div>
      <div><div class="label">Duration</div><div class="value">{duration:.1f}s</div></div>
      <div><div class="label">Hosts Scanned</div><div class="value">{total_hosts}</div></div>
    </div>
  </div>

  <div class="container">

    <h2 class="section-title">Executive Summary</h2>
    <p style="color:#334155; font-size:13.5px;">
      This report summarizes the results of an authorized vulnerability assessment performed
      against {total_hosts} host(s) within the defined lab scope. A total of
      <strong>{total_findings}</strong> finding(s) were identified across all scanned services.
    </p>
    <div class="summary-cards">{summary_cards}</div>

    <h2 class="section-title">Scope of Assessment</h2>
    <div class="scope-box">
      <strong>Authorized targets (scope.txt):</strong>
      <ul>{scope_list}</ul>
    </div>

    <h2 class="section-title">Detailed Findings</h2>
    {host_sections}

    <footer>
      <span>Generated by scanner.py &middot; {ORG_NAME}</span>
      <span>Report generated {scan_end.strftime("%Y-%m-%d %H:%M:%S")}</span>
    </footer>

  </div>
</body></html>"""

    with open(path, "w") as f:
        f.write(html)
    print(f"[+] HTML report written: {path}")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Lab 03 Network Vulnerability Scanner")
    parser.add_argument("--scope", required=True, help="Path to scope.txt")
    parser.add_argument("--nvd-api-key", default=None, help="Optional NVD API key")
    parser.add_argument("--no-cve-lookup", action="store_true", help="Skip NVD queries")
    args = parser.parse_args()

    scan_start = datetime.now()
    targets = load_scope(args.scope)

    nm = nmap.PortScanner()

    live_hosts = discover_hosts(nm, targets)
    if not live_hosts:
        sys.exit("[!] No live hosts found.")

    all_service_entries = []
    for host in live_hosts:
        entries = scan_services(nm, host)
        all_service_entries.extend(entries)

    all_service_entries = enrich_with_cves(
        all_service_entries, api_key=args.nvd_api_key, skip=args.no_cve_lookup
    )

    rows = build_report_rows(all_service_entries)
    write_csv(rows)
    write_html(rows, live_hosts, targets, scan_start)

    print("\n[*] Done. Review vuln_report.csv / vuln_report.html")


if __name__ == "__main__":
    main()