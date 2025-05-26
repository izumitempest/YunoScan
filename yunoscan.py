# yunoscan.py
import requests
from urllib.parse import urljoin
import re

def is_wordpress_site(url):
    try:
        r = requests.get(url, timeout=10, headers={'User-Agent': 'YunoScan/1.0'})
        if "wp-content" in r.text or "wp-includes" in r.text:
            return True
        if "X-Pingback" in r.headers and "xmlrpc.php" in r.headers.get("X-Pingback", ""):
            return True
    except Exception as e:
        print(f"[!] Error checking WordPress: {e}")
    return False

def get_wp_version(url):
    try:
        r = requests.get(url, timeout=10)
        version = re.search(r'<meta name="generator" content="WordPress (\d+\.\d+(\.\d+)*)"', r.text)
        if version:
            return version.group(1)
    except:
        pass
    return "Unknown"

def enumerate_users_json_api(url):
    print("\n[*] Attempting user enumeration via wp-json...")
    try:
        api_url = urljoin(url, "/wp-json/wp/v2/users")
        res = requests.get(api_url, timeout=10)
        if res.status_code == 200:
            users = res.json()
            for user in users:
                print(f"[+] ID: {user.get('id')} | Username: {user.get('slug')} | Name: {user.get('name')}")
        else:
            print("[-] wp-json user endpoint not accessible.")
    except Exception as e:
        print(f"[!] Error: {e}")

def enumerate_users_author_id(url, max_users=10):
    print("\n[*] Attempting author ID brute force...")
    for i in range(1, max_users + 1):
        try:
            author_url = f"{url}/?author={i}"
            res = requests.get(author_url, allow_redirects=False, timeout=10)
            if res.status_code in [301, 302] and "Location" in res.headers:
                location = res.headers["Location"]
                match = re.search(r"/author/([^/]+)/", location)
                if match:
                    print(f"[+] Found user: {match.group(1)} (ID: {i})")
        except Exception as e:
            print(f"[!] Error at ID {i}: {e}")


def main():
    target = input("[?] Enter the full target URL (e.g., https://example.com): ").strip().rstrip("/")
    print(f"\n[*] Scanning {target} with YunoScan...\n")
    
    if is_wordpress_site(target):
        print("[+] WordPress detected!")
        version = get_wp_version(target)
        print(f"[+] WordPress version: {version}")
        enumerate_users_json_api(target)
        enumerate_users_author_id(target)
        print("\n[*] User enumeration complete.")
    else:
        print("[-] Target does not appear to be a WordPress site.")

if __name__ == "__main__":
    main()
