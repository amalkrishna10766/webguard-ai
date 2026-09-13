import requests
from datetime import datetime

BASE_URL = "https://clinic-production-83e1.up.railway.app"

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
    "/.env.local", "/.env.production", "/package.json", "/server.js",
    "/api/", "/.well-known/", "/database.sql", "/test.php", "/debug"
]

results = {"headers": [], "paths": []}


def check_headers(url):
    print(f"\n[*] Checking security headers for: {url}\n")
    try:
        response = requests.get(url, timeout=15)
    except requests.exceptions.RequestException as e:
        print(f"[!] Error connecting: {e}")
        return

    for header, desc in security_headers.items():
        present = header in response.headers
        value = response.headers.get(header, "")
        results["headers"].append({"header": header, "present": present, "desc": desc, "value": value})
        if present:
            print(f"\U0001F7E2 PRESENT   | {header:30} --> {value}")
        else:
            print(f"\U0001F534 MISSING   | {header:30} --> {desc}")


def check_paths(base_url):
    print(f"\n[*] Scanning for exposed files/directories on: {base_url}\n")

    for path in sensitive_paths:
        url = base_url.rstrip("/") + path
        try:
            response = requests.get(url, timeout=10, allow_redirects=False)
            status = response.status_code
        except requests.exceptions.RequestException:
            status = "error"

        results["paths"].append({"path": path, "status": status})

        if status == 200:
            print(f"\U0001F534 EXPOSED   | {path:25} --> Status {status} (accessible!)")
        elif status in (301, 302):
            print(f"\U0001F7E1 REDIRECT  | {path:25} --> Status {status}")
        elif status == 403:
            print(f"\U0001F7E1 FORBIDDEN | {path:25} --> Status {status} (exists but blocked)")
        else:
            print(f"\U0001F7E2 SAFE      | {path:25} --> Status {status}")

    print("\n[*] Scan complete.\n")


def risk_level(count, total):
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
    headers_missing = sum(1 for r in results["headers"] if not r["present"])
    paths_exposed = sum(1 for r in results["paths"] if r["status"] == 200)

    header_risk = risk_level(headers_missing, len(results["headers"]))
    path_risk = risk_level(paths_exposed, len(results["paths"]))

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def row(label, value, risk_class):
        return f"<tr><td>{label}</td><td>{value}</td><td class='{risk_class}'>{risk_class.upper()}</td></tr>"

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
<title>WEBGUARD-AI Security Report - Clinic Website</title>
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
    .note {{ background:#1e293b; border-left:4px solid #38bdf8; padding:10px 15px; margin-top:15px; }}
</style>
</head>
<body>
    <h1>WEBGUARD-AI Security Assessment Report</h1>
    <p>Target: {BASE_URL} &nbsp;|&nbsp; Generated: {timestamp}</p>
    <div class="note">Note: This scan performed read-only checks only (security headers and path exposure). No injection or data-modifying tests were run against this live production site.</div>

    <h2>Risk Summary</h2>
    <table>
        <tr><th>Category</th><th>Findings</th><th>Risk Level</th></tr>
        {row("Missing Security Headers", f"{headers_missing}/{len(results['headers'])} missing", header_risk)}
        {row("Exposed Files/Directories", f"{paths_exposed}/{len(results['paths'])} exposed", path_risk)}
    </table>

    <h2>Security Headers</h2>
    <table><tr><th>Header</th><th>Status</th><th>Purpose</th></tr>{header_rows()}</table>

    <h2>Exposed Files/Directories</h2>
    <table><tr><th>Path</th><th>Status</th></tr>{path_rows()}</table>

</body>
</html>
    """

    with open("clinic_security_report.html", "w", encoding="utf-8") as f:
        f.write(report_html)

    print("\n[+] Report generated: clinic_security_report.html")


if __name__ == "__main__":
    check_headers(BASE_URL)
    check_paths(BASE_URL)
    generate_report()