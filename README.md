# WEBGUARD-AI

**An automated web vulnerability assessment tool that scans for OWASP Top 10 weaknesses and generates professional, risk-scored HTML reports.**

Built to bring together practical VAPT (Vulnerability Assessment & Penetration Testing) concepts into a working, automated tool — tested against both a deliberately vulnerable lab application and a live production website.

---

## 🔍 What It Does

WEBGUARD-AI automatically scans a target web application for four categories of common web security weaknesses, then compiles the findings into a single, color-coded HTML report with an automatically calculated risk level per category.

| Module | What It Checks |
|---|---|
| **SQL Injection Scanner** | Sends common SQLi payloads and analyzes responses (error signatures, response-length deltas, record leakage) to detect injectable inputs |
| **XSS Scanner** | Tests reflected Cross-Site Scripting by injecting script/event-handler payloads and checking whether they're reflected unescaped |
| **Security Header Checker** | Audits HTTP responses for 7 key security headers (CSP, HSTS, X-Frame-Options, etc.) and explains the risk of each missing one |
| **Directory/File Exposure Scanner** | Probes for commonly exposed sensitive paths (`.env`, `.git/config`, backup files, admin panels, etc.) |

A rule-based risk-scoring layer aggregates results per category into **Low / Medium / High / Critical**, so the report reads like a real assessment deliverable rather than a raw log dump.

---

## 🛠️ Tech Stack

- **Python 3.11** — core scanning logic
- **Requests** — session handling, HTTP automation, login/CSRF-token flows
- **Docker & Docker Compose** — reproducible vulnerable-lab environment (DVWA + MariaDB)
- **HTML/CSS** — generated report styling

---

## 📊 Sample Results

Tested in two environments to validate both detection accuracy and real-world safety:

1. **DVWA (Damn Vulnerable Web App)** — a controlled, intentionally vulnerable lab used to validate detection logic.
   - SQL Injection: 3/4 test payloads correctly flagged as vulnerable
   - XSS: 4/4 test payloads correctly flagged as vulnerable
   - Security Headers: 7/7 flagged missing (expected — DVWA ships with no hardening)

2. **A live production web application** (a healthcare appointment platform) — scanned using only **non-invasive, read-only checks** (headers + path exposure; no injection or data-modifying tests were run against live data).
   - Result: 6/7 security headers present, sensitive config paths correctly returning 403 (blocked), overall risk rated **Medium**

### DVWA Test Lab Report
![DVWA Scan Report](screenshots/dvwa_report.png)

### Production Site Scan
![Production Site Scan](screenshots/clinic_report.png)

---

## 🚀 How It Works

```bash
# 1. Spin up the vulnerable lab
cd dvwa-lab
docker-compose up -d

# 2. Activate the Python environment
cd ..
venv\Scripts\activate      # Windows
pip install -r requirements.txt

# 3. Run the full scan
cd scanner
python main.py
```

This logs into the target automatically, sets the DVWA security level, runs all four scan modules, and writes `webguard_report.html` — open it in any browser.

For scanning a live site with **read-only checks only**, use `safe_scan.py` with the target URL set at the top of the file.

---

## 📁 Project Structure

```
webguard-ai/
├── dvwa-lab/
│   └── docker-compose.yml       # DVWA + MariaDB lab environment
├── scanner/
│   ├── sqli_scanner.py          # SQL Injection module
│   ├── xss_scanner.py           # XSS module
│   ├── header_checker.py        # Security header module
│   ├── dir_scanner.py           # Directory/file exposure module
│   ├── main.py                  # Unified scan + report generator
│   └── safe_scan.py             # Read-only scanner for live/production targets
└── README.md
```

---

## ⚠️ Responsible Use

This tool is built strictly for **authorized security testing** — against systems you own or have explicit written permission to test (e.g. DVWA, OWASP Juice Shop, your own applications, or engagements with signed scope agreements). Scanning systems without authorization is illegal in most jurisdictions, including under India's IT Act, 2000.

---

## 🎯 Why I Built This

I wanted to move beyond checklist-based manual testing and build something that reflects how real VAPT tooling works — automated detection, evidence-backed findings, and a report a client or engineering team could actually act on. This project ties together my CEH coursework and cybercrime-unit internship experience into a working tool rather than just theory.

---

## 🔮 Possible Extensions

- Automated column-count detection for UNION-based SQL injection
- Flask-based web dashboard for running scans without the CLI
- CVE/CWE correlation for discovered issues
- Authenticated crawling to discover additional testable endpoints

---

## 📄 License

Built for educational and authorized-testing purposes only.
