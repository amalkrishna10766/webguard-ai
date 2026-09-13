import requests

TARGET_URL = "http://localhost"

# Important security headers to check for
security_headers = {
    "Content-Security-Policy": "Helps prevent XSS and data injection attacks",
    "X-Frame-Options": "Prevents clickjacking attacks",
    "X-Content-Type-Options": "Prevents MIME-sniffing attacks",
    "Strict-Transport-Security": "Enforces HTTPS connections",
    "X-XSS-Protection": "Legacy XSS filter (still checked for older browsers)",
    "Referrer-Policy": "Controls how much referrer info is sent",
    "Permissions-Policy": "Controls which browser features the site can use"
}

def check_headers(url):
    print(f"\n[*] Checking security headers for: {url}\n")

    try:
        response = requests.get(url, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"[!] Error connecting to {url}: {e}")
        return

    for header, description in security_headers.items():
        if header in response.headers:
            print(f"\U0001F7E2 PRESENT   | {header:30} --> {response.headers[header]}")
        else:
            print(f"\U0001F534 MISSING   | {header:30} --> {description}")

    print("\n[*] Scan complete.\n")

if __name__ == "__main__":
    check_headers(TARGET_URL)