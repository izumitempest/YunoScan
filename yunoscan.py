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

def main():
    target = input("[?] Enter the full target URL (e.g., https://example.com): ").strip().rstrip("/")
    print(f"\n[*] Scanning {target} with YunoScan...\n")
    
    if is_wordpress_site(target):
        print("[+] WordPress detected!")
        version = get_wp_version(target)
        print(f"[+] WordPress version: {version}")
    else:
        print("[-] Target does not appear to be a WordPress site.")

if __name__ == "__main__":
    main()
