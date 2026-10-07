# Lab 03 — Network Vulnerability Scanner

A network vulnerability scanning lab built as a hands-on cybersecurity learning
project. It demonstrates host discovery, service detection, CVE mapping, and
report generation using Python and Nmap.

---

## Overview

This project scans a defined network scope for live hosts, identifies running
services and versions, queries the National Vulnerability Database (NVD) for
known CVEs, and produces both CSV and HTML reports with severity ratings and
remediation guidance.

**Key concepts covered:**

- Network host discovery (ping sweep)
- Service and version detection
- CVE mapping via NVD REST API
- CVSS severity scoring
- Report generation (CSV + HTML)

---

## Project Structure

```
lab03_complete_setup_docs/
├── scanner.py                          # Main scanner script
├── scope.txt.example                   # Example scope file (edit before use)
├── cve_cache.json                      # Cached NVD query results
├── vuln_report.csv                    # Latest scan results (CSV)
├── vuln_report.html                   # Latest scan results (HTML)
├── updated_scanner_docs/
│   ├── updated_scanner.py             # Enhanced scanner with dual-query CVE lookup
│   ├── cve_cache.json                 # Cache from updated scanner
│   ├── vuln_report.csv                # Report from updated scanner
│   └── vuln_report.html               # Report from updated scanner
├── Lab03_Setup_and_Configuration_windows.docx
├── Lab03_Setup_Documentation.docx
└── lab03_architecture.png              # Architecture diagram
```

---

## Prerequisites

- **Python 3.10+**
- **Nmap** installed system-wide
- **python-nmap** and **requests** Python packages

Install dependencies:
```powershell
pip install python-nmap requests
```

---

## Usage

1. **Edit the scope file** — copy `scope.txt.example` to `scope.txt` and add your target IPs:
   ```powershell
   copy scope.txt.example scope.txt
   notepad scope.txt
   ```

2. **Run the scanner:**
   ```powershell
   python scanner.py --scope scope.txt
   ```

3. **Optional:** Use an NVD API key for higher rate limits:
   ```powershell
   python scanner.py --scope scope.txt --nvd-api-key YOUR_KEY_HERE
   ```

4. **Optional:** Skip CVE lookup for a fast dry run:
   ```powershell
   python scanner.py --scope scope.txt --no-cve-lookup
   ```

5. **View results** — open `vuln_report.html` in a browser or review `vuln_report.csv`.

---

## How It Works

### Pipeline

1. **Host discovery** — ICMP ping sweep (`nmap -sn`) across the authorized scope
2. **Service detection** — service/version scan (`nmap -sV`) on each live host
3. **CVE mapping** — queries NVD REST API v2.0 using both CPE-based and keyword-based lookups
4. **Report generation** — produces CSV and HTML reports with severity ratings and remediation

### Severity Bands

| CVSS Score | Severity |
|------------|----------|
| 9.0+       | Critical |
| 7.0 – 8.9  | High     |
| 4.0 – 6.9  | Medium   |
| 0.1 – 3.9  | Low      |

### CPE Mapping

The scanner maps Nmap product strings to CPE identifiers for precise CVE matching:

| Nmap Product | CPE Vendor:Product |
|--------------|-------------------|
| Apache httpd | apache:http_server |
| OpenSSH      | openbsd:openssh    |
| Nginx        | nginx:nginx        |
| SMB/Windows  | microsoft:windows  |

---

## Safety & Ethics

- **Only scan hosts you have explicit written authorization to test**
- The scope file defines the legal boundary — the scanner refuses to run if it's empty
- No exploitation is performed; this is a detection and reporting tool only
- NVD API rate limits are respected (6.5s delay without key, 0.7s with key)

---

## Learning Outcomes

By studying and running this lab, you will understand:

1. **How network scanners discover hosts and services**
2. **How CVE databases work and how to query them programmatically**
3. **How CVSS scores map to severity bands**
4. **How to build automated security reports**
5. **Why scope definition and authorization are critical in vulnerability scanning**

---

## License

This project is provided for educational purposes. Use it responsibly in
isolated lab environments only.
