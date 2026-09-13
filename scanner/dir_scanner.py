import requests

TARGET_URL = "http://localhost"

# Common sensitive paths/files to check for exposure
paths_to_check = [
    "/.git/config",
    "/.env",
    "/config.php",
    "/backup.zip",
    "/admin/",
    "/phpinfo.php",
    "/robots.txt",
    "/.htaccess",
    "/wp-config.php",
    "/config/",
    "/database.sql",
    "/test.php"
]

def check_paths(base_url):
    print(f"\n[*] Scanning for exposed files/directories on: {base_url}\n")

    for path in paths_to_check:
        url = base_url.rstrip("/") + path
        try:
            response = requests.get(url, timeout=5, allow_redirects=False)
            status = response.status_code

            if status == 200:
                print(f"\U0001F534 EXPOSED   | {path:25} --> Status {status} (accessible!)")
            elif status in (301, 302):
                print(f"\U0001F7E1 REDIRECT  | {path:25} --> Status {status}")
            elif status == 403:
                print(f"\U0001F7E1 FORBIDDEN | {path:25} --> Status {status} (exists but blocked)")
            else:
                print(f"\U0001F7E2 SAFE      | {path:25} --> Status {status} (not found)")

        except requests.exceptions.RequestException as e:
            print(f"[!] Error checking {path}: {e}")

    print("\n[*] Scan complete.\n")

if __name__ == "__main__":
    check_paths(TARGET_URL)