#!/usr/bin/env python3
"""
scanner_core.py — reusable scanning engine for the Lab 03 web app.

Refactored from updated_scanners/updated_scanner.py so it can be imported by the
FastAPI backend (no sys.exit, injectable paths, thread-safe cache, returns data).
"""
import csv
import html as _html
import json
import os
import re
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional

try:
    import nmap
except ImportError as e:
    raise RuntimeError("Missing dependency: pip install python-nmap") from e

try:
    import requests
except ImportError as e:
    raise RuntimeError("Missing dependency: pip install requests") from e


# --------------------------------------------------------------------------
# Config (overridable via env / function args)
# --------------------------------------------------------------------------
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NO_KEY_DELAY = 6.5
WITH_KEY_DELAY = 0.7
REPORT_TITLE = "Network Vulnerability Assessment Report"
ORG_NAME = "Blue Cloud Softech Solutions Ltd."

CPE_MAP = {
    "apache httpd": "apache:http_server",
    "apache": "apache:http_server",
    "openssh": "openbsd:openssh",
    "nginx": "nginx:nginx",
    "microsoft-ds": "microsoft:windows",
    "smb": "microsoft:windows",
    "netbios-ssn": "microsoft:windows",
    "http": "apache:http_server",
}

# When nmap returns a generic service label with no usable version, substitute a
# richer search phrase so NVD actually returns relevant CVEs.
SERVICE_QUERY_OVERRIDES = {
    "microsoft-ds": "microsoft windows smb",
    "netbios-ssn": "microsoft windows smb",
    "http": "apache http server",
    "https": "apache http server",
    "ssh": "openssh",
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

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational", "CWE", "No CVE", "Unknown"]
SEVERITY_COLOR = {
    "Critical": "#b91c1c", "High": "#c2410c", "Medium": "#a16207",
    "Low": "#15803d", "Informational": "#1d4ed8", "CWE": "#6d28d9",
    "No CVE": "#475569", "Unknown": "#64748b",
}
SEVERITY_BG = {
    "Critical": "#fef2f2", "High": "#fff7ed", "Medium": "#fefce8",
    "Low": "#f0fdf4", "Informational": "#eff6ff", "CWE": "#f5f3ff",
    "No CVE": "#f8fafc", "Unknown": "#f8fafc",
}

_cache_lock = threading.Lock()


def score_to_severity(score):
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


def load_scope(scope_lines_or_path):
    """Accept a list of lines or a path; return non-empty target list."""
    if isinstance(scope_lines_or_path, (list, tuple)):
        lines = [ln.strip() for ln in scope_lines_or_path]
    else:
        if not os.path.exists(scope_lines_or_path):
            raise FileNotFoundError(f"Scope file not found: {scope_lines_or_path}")
        with open(scope_lines_or_path) as f:
            lines = [ln.strip() for ln in f]
    targets = [ln for ln in lines if ln and not ln.startswith("#")]
    if not targets:
        raise ValueError("Scope is empty — refusing to scan nothing.")
    return targets


def discover_hosts(nm, targets, log=print):
    live_hosts = []
    for target in targets:
        log(f"[*] Discovering hosts in {target} ...")
        nm.scan(hosts=target, arguments="-sn")
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                live_hosts.append(host)
                log(f"    [+] Live host: {host}")
    return live_hosts


def scan_services(nm, host, log=print):
    log(f"[*] Scanning services on {host} ...")
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


def _clean_version(raw_version):
    if not raw_version:
        return ""
    version = raw_version.strip()
    version = re.sub(r"\(.*?\)", "", version).strip()
    version = version.split()[0] if version.split() else ""
    return version


def _cpe_for_product(product):
    key = (product or "").lower().strip()
    for name, cpe in CPE_MAP.items():
        if name in key:
            return cpe
    return None


def _fetch_nvd(params, headers):
    resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=20)
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
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                score = metrics[key][0]["cvssData"].get("baseScore")
                break
        results.append({
            "cve_id": cve_id,
            "description": description[:260],
            "cvss_score": score,
            "severity": score_to_severity(score),
        })
    return results


def _diverse_pick(cves: List[Dict], max_results: int = 8) -> List[Dict]:
    """Pick a diverse subset: prefer top scores but ensure severity spread."""
    if len(cves) <= max_results:
        return cves
    # sort by score desc
    ordered = sorted(cves, key=lambda c: (c["cvss_score"] or 0), reverse=True)
    chosen = []
    seen_sev = set()
    # first pass: one per severity band
    for c in ordered:
        if c["severity"] not in seen_sev:
            chosen.append(c)
            seen_sev.add(c["severity"])
            if len(chosen) >= max_results:
                break
    # fill remaining by score
    for c in ordered:
        if c not in chosen:
            chosen.append(c)
            if len(chosen) >= max_results:
                break
    # keep sorted by score
    chosen.sort(key=lambda c: (c["cvss_score"] or 0), reverse=True)
    return chosen


def query_nvd(product, raw_version, service_name="", api_key=None, max_results=8, log=print):
    """Diverse NVD lookup: CPE + multiple keyword strategies, merged & deduped."""
    if not product and not service_name:
        return []

    headers = {"apiKey": api_key} if api_key else {}
    clean_version = _clean_version(raw_version)
    cpe_product = _cpe_for_product(product) or _cpe_for_product(service_name)

    all_results: Dict[str, Dict] = {}

    # --- candidate queries (diverse) ---
    queries = []

    # 1. CPE-based, version-precise
    if cpe_product and clean_version:
        queries.append(("cpe", f"cpe:2.3:a:{cpe_product}:{clean_version}"))

    # 2. override phrase for generic labels
    svc_key = (service_name or product or "").lower().strip()
    override = None
    for k, v in SERVICE_QUERY_OVERRIDES.items():
        if k in svc_key:
            override = v
            break
    if override:
        queries.append(("kw", override if not clean_version else f"{override} {clean_version}"))

    # 3. product + version
    if product:
        queries.append(("kw", f"{product} {clean_version}".strip()))
    # 4. service + version
    if service_name and service_name != product:
        queries.append(("kw", f"{service_name} {clean_version}".strip()))
    # 5. product only (broad)
    if product:
        queries.append(("kw", product))
    # 6. service only
    if service_name:
        queries.append(("kw", service_name))

    # de-dup query strings
    seen_q = set()
    uniq_queries = []
    for kind, q in queries:
        qn = q.strip().lower()
        if qn and qn not in seen_q:
            seen_q.add(qn)
            uniq_queries.append((kind, q.strip()))

    for kind, q in uniq_queries:
        try:
            if kind == "cpe":
                data = _fetch_nvd({"virtualMatchString": q, "resultsPerPage": 20}, headers)
            else:
                data = _fetch_nvd({"keywordSearch": q, "resultsPerPage": 20}, headers)
            for r in _parse_cve_items(data):
                all_results.setdefault(r["cve_id"], r)
            # small delay to respect rate limits between distinct calls
            time.sleep(0.2 if api_key else 0.6)
        except requests.RequestException as e:
            log(f"    [!] NVD lookup failed for '{q}': {e}")

    merged = sorted(all_results.values(), key=lambda c: (c["cvss_score"] or 0), reverse=True)
    return _diverse_pick(merged, max_results=max_results)


def load_cache(cache_file):
    if os.path.exists(cache_file):
        with open(cache_file) as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}


def save_cache(cache, cache_file):
    os.makedirs(os.path.dirname(os.path.abspath(cache_file)) or ".", exist_ok=True)
    with open(cache_file, "w") as f:
        json.dump(cache, f, indent=2)


def enrich_with_cves(service_entries, api_key=None, skip=False, cache_file="cve_cache.json",
                     max_results=8, log=print):
    cache = load_cache(cache_file)
    delay = WITH_KEY_DELAY if api_key else NO_KEY_DELAY

    for entry in service_entries:
        if skip:
            entry["findings"] = [{
                "type": "skipped", "id": "N/A", "severity": "Unknown",
                "note": "CVE lookup skipped (--no-cve-lookup)"
            }]
            continue

        clean_version = _clean_version(entry["version"])
        cache_key = f"{entry['product']}|{entry['service']}|{clean_version}".lower().strip()

        if not entry["product"] and not entry["service"]:
            entry["findings"] = [{
                "type": "no_cve", "id": "N/A", "severity": "No CVE",
                "note": "No product/version banner returned by Nmap — manual review required"
            }]
            continue

        with _cache_lock:
            if cache_key in cache:
                cves = cache[cache_key]
            else:
                cves = query_nvd(entry["product"], entry["version"], service_name=entry["service"],
                                 api_key=api_key, max_results=max_results, log=log)
                cache[cache_key] = cves
                save_cache(cache, cache_file)
                time.sleep(delay)
                cves = cache[cache_key]

        if cves:
            entry["findings"] = [
                {"type": "cve", "id": c["cve_id"], "severity": c["severity"],
                 "cvss_score": c["cvss_score"], "note": c["description"]}
                for c in cves
            ]
        else:
            entry["findings"] = [{
                "type": "no_cve", "id": "N/A", "severity": "No CVE",
                "note": (f"No known CVEs found for {entry['product'] or entry['service']} "
                         f"{clean_version or entry['version']}. Software appears current/patched — "
                         f"manually verify for misconfigurations (weak credentials, exposed files, "
                         f"directory listing, missing headers, etc.) and classify as CWE if found.")
            }]

    return service_entries


def get_remediation(service_name, product):
    text = f"{service_name} {product}".lower()
    for key, advice in REMEDIATION_MAP.items():
        if key in text:
            return advice
    return DEFAULT_REMEDIATION


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


def write_csv(rows, path):
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    if not rows:
        with open(path, "w", newline="") as f:
            f.write("")
        return path
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return path


def write_html(rows, live_hosts, scope_targets, scan_start, path=None):
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
        host_rows = sorted([r for r in rows if r["Host"] == host],
                           key=lambda row: SEVERITY_ORDER.index(row["Severity"]) if row["Severity"] in SEVERITY_ORDER else len(SEVERITY_ORDER))
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
              <td>{_html.escape(str(r["Service"]))}</td>
              <td class="mono">{_html.escape(str(r["Version"]))}</td>
              <td class="mono">{_html.escape(str(r["Finding"]))}</td>
              <td class="center">{cvss_display}</td>
              <td><span class="badge" style="background:{bg};color:{color};border:1px solid {color}33">{_html.escape(str(r["Severity"]))}</span></td>
              <td class="notes">{_html.escape(str(r["Notes"]))}</td>
              <td class="remediation">{_html.escape(str(r["Remediation"]))}</td>
            </tr>'''
        host_sections += f'''
        <div class="host-section">
          <div class="host-header">
            <h3>Host: <span class="mono">{_html.escape(str(host))}</span></h3>
            <span class="host-meta">{len(host_rows)} finding(s) &middot; open ports: {", ".join(ports_summary)}</span>
          </div>
          <table>
            <thead><tr><th>Port</th><th>Service</th><th>Version</th><th>Finding</th>
            <th>CVSS</th><th>Severity</th><th>Notes</th><th>Remediation</th></tr></thead>
            <tbody>{table_rows}</tbody>
          </table>
        </div>'''
    scope_list = "".join(f"<li class='mono'>{_html.escape(str(t))}</li>" for t in scope_targets)

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{REPORT_TITLE}</title>
<style>
  :root {{ --ink: #0f172a; --muted: #64748b; --border: #e2e8f0; --bg: #f8fafc; --accent: #1e293b; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', -apple-system, Helvetica, Arial, sans-serif; margin: 0; color: var(--ink); background: #ffffff; line-height: 1.5; }}
  .cover {{ background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%); color: #fff; padding: 56px 48px 40px; }}
  .cover .eyebrow {{ text-transform: uppercase; letter-spacing: 2px; font-size: 12px; color: #93c5fd; font-weight: 600; margin-bottom: 10px; }}
  .cover h1 {{ margin: 0 0 8px; font-size: 30px; font-weight: 700; }}
  .cover .org {{ color: #cbd5e1; font-size: 14px; margin-bottom: 28px; }}
  .logo-img {{ display: inline-block; height: 44px; width: auto; margin-bottom: 16px; border-radius: 6px; background: #fff; padding: 4px 8px; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; border-top: 1px solid rgba(255,255,255,0.15); padding-top: 20px; margin-top: 8px; }}
  .meta-grid div .label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #93c5fd; }}
  .meta-grid div .value {{ font-size: 14px; margin-top: 4px; font-weight: 600; }}
  .container {{ max-width: 1180px; margin: 0 auto; padding: 40px 48px 64px; }}
  h2.section-title {{ font-size: 18px; font-weight: 700; margin: 40px 0 16px; padding-bottom: 8px; border-bottom: 2px solid var(--accent); }}
  .summary-cards {{ display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 8px; }}
  .card {{ background: #fff; border: 1px solid var(--border); border-top: 4px solid #64748b; border-radius: 6px; padding: 16px 22px; min-width: 120px; text-align: center; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }}
  .card-count {{ font-size: 28px; font-weight: 800; }}
  .card-label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.6px; color: var(--muted); margin-top: 4px; }}
  .scope-box {{ background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 18px 22px; font-size: 13px; }}
  .scope-box ul {{ margin: 8px 0 0 18px; padding: 0; }}
  .host-section {{ margin-bottom: 32px; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  .host-header {{ background: var(--accent); color: #fff; padding: 12px 18px; display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; gap: 8px; }}
  .host-header h3 {{ margin: 0; font-size: 15px; }}
  .host-meta {{ font-size: 12px; color: #cbd5e1; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12.5px; }}
  thead th {{ background: #f1f5f9; text-align: left; padding: 10px 12px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); border-bottom: 1px solid var(--border); }}
  tbody td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tbody tr:last-child td {{ border-bottom: none; }}
  tbody tr:hover {{ background: #fafbfc; }}
  .mono {{ font-family: 'SF Mono', Consolas, Monaco, monospace; font-size: 12px; }}
  .center {{ text-align: center; }}
  .notes {{ max-width: 260px; color: #475569; }}
  .remediation {{ max-width: 260px; color: #1e293b; }}
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; white-space: nowrap; }}
  .methodology {{ font-size: 13.5px; color: #334155; }}
  .methodology ol {{ margin: 8px 0 0 18px; padding: 0; }}
  .methodology li {{ margin-bottom: 6px; }}
  footer {{ border-top: 1px solid var(--border); margin-top: 48px; padding-top: 20px; font-size: 11.5px; color: var(--muted); display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px; }}
  .disclaimer {{ background: #fffbeb; border: 1px solid #fde68a; border-radius: 6px; padding: 14px 18px; font-size: 12.5px; color: #78350f; margin-top: 24px; }}
  @media print {{ .cover {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }} .host-section {{ break-inside: avoid; }} }}
</style>
</head>
<body>
  <div class="cover">
    <img class="logo-img" src="/static/bcss.png" alt="BCSS logo">
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
      <strong>{total_findings}</strong> finding(s) were identified across all scanned services,
      broken down by severity below. Findings without an associated CVE indicate current/patched
      software and are flagged for manual configuration review rather than treated as an absence
      of risk.
    </p>
    <div class="summary-cards">{summary_cards}</div>
    <h2 class="section-title">Scope of Assessment</h2>
    <div class="scope-box">
      <strong>Authorized targets (scope.txt):</strong>
      <ul>{scope_list}</ul>
      All scanning was performed strictly within the ranges listed above, per the lab's
      Scope &amp; Ethics Notice. No hosts outside this list were scanned.
    </div>
    <h2 class="section-title">Methodology</h2>
    <div class="methodology">
      <ol>
        <li><strong>Host discovery</strong> — ICMP ping sweep (<span class="mono">nmap -sn</span>) across the authorized scope to identify live hosts.</li>
        <li><strong>Service &amp; version detection</strong> — targeted service/version scan (<span class="mono">nmap -sV</span>) against each live host.</li>
        <li><strong>Vulnerability mapping</strong> — each detected service/version was checked against the National Vulnerability Database (NVD) using both CPE-based and keyword-based lookups (diverse queries), with results merged and de-duplicated.</li>
        <li><strong>Severity scoring</strong> — CVSS base scores were mapped to standard severity bands (Critical / High / Medium / Low).</li>
        <li><strong>Remediation mapping</strong> — each finding was paired with actionable, service-specific remediation guidance.</li>
      </ol>
    </div>
    <h2 class="section-title">Detailed Findings</h2>
    {host_sections}
    <div class="disclaimer">
      <strong>Note on scope of automated detection:</strong> This scan reflects automated
      CVE lookups only. Configuration-level weaknesses (e.g. weak credentials, directory
      listing, exposed files) are not detected by CVE databases and require manual
      verification, as noted in the findings above where applicable.
    </div>
    <footer>
      <span>Generated by scanner_core.py &middot; {ORG_NAME}</span>
      <span>Report generated {scan_end.strftime("%Y-%m-%d %H:%M:%S")}</span>
    </footer>
  </div>
</body></html>"""

    if path:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
    return html


def run_scan(targets, api_key=None, skip_cve=False, output_dir=".", cache_file="cve_cache.json",
             max_results=8, log=print):
    """Run full pipeline. Returns dict with paths + rows + html string."""
    scan_start = datetime.now()
    os.makedirs(output_dir, exist_ok=True)
    cache_file = cache_file or os.path.join(output_dir, "cve_cache.json")

    nm = nmap.PortScanner()
    live_hosts = discover_hosts(nm, targets, log=log)
    if not live_hosts:
        raise RuntimeError("No live hosts found. Check connectivity/scope.")

    all_entries = []
    for host in live_hosts:
        entries = scan_services(nm, host, log=log)
        all_entries.extend(entries)
    log(f"\n[*] {len(all_entries)} service(s) found across {len(live_hosts)} host(s).")

    if not skip_cve:
        log("[*] Querying NVD for CVEs (diverse CPE + keyword)...")
    all_entries = enrich_with_cves(all_entries, api_key=api_key, skip=skip_cve,
                                  cache_file=cache_file, max_results=max_results, log=log)

    rows = build_report_rows(all_entries)

    ts = scan_start.strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(output_dir, f"vuln_report_{ts}.csv")
    html_path = os.path.join(output_dir, f"vuln_report_{ts}.html")
    write_csv(rows, csv_path)
    html = write_html(rows, live_hosts, targets, scan_start, path=html_path)

    # also write "latest" convenience copies
    write_csv(rows, os.path.join(output_dir, "vuln_report.csv"))
    write_html(rows, live_hosts, targets, scan_start, path=os.path.join(output_dir, "vuln_report.html"))

    log("\n[*] Done. Reports written.")
    return {
        "scan_start": scan_start.isoformat(),
        "live_hosts": live_hosts,
        "service_count": len(all_entries),
        "rows": rows,
        "csv_path": csv_path,
        "html_path": html_path,
        "html": html,
    }
