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

def passive_plugin_theme_detection(url):
    print("\n[*] Performing passive detection of plugins/themes...")
    try:
        res = requests.get(url, timeout=10)
        plugins = set(re.findall(r'/wp-content/plugins/([^/]+)/', res.text))
        themes = set(re.findall(r'/wp-content/themes/([^/]+)/', res.text))

        if plugins:
            print("[+] Detected plugins (passive):")
            for plugin in plugins:
                print(f"    - {plugin}")
        else:
            print("[-] No plugins found passively.")

        if themes:
            print("[+] Detected themes (passive):")
            for theme in themes:
                print(f"    - {theme}")
        else:
            print("[-] No themes found passively.")
        return plugins, themes
    except Exception as e:
        print(f"[!] Error during passive detection: {e}")
        return set(), set()

plugin_wordlist = ['contact-form-7', 'woocommerce', 'wordfence', 'elementor']
theme_wordlist = ['astra', 'twentytwentyone', 'hello-elementor', 'generatepress']

def aggressive_plugin_theme_detection(url):
    print("\n[*] Performing aggressive detection using wordlist...")
    found_plugins = []
    found_themes = []

    for plugin in plugin_wordlist:
        path = f"{url}/wp-content/plugins/{plugin}/"
        res = requests.get(path)
        if res.status_code == 200:
            print(f"[+] Found plugin (aggressive): {plugin}")
            found_plugins.append(plugin)

    for theme in theme_wordlist:
        path = f"{url}/wp-content/themes/{theme}/"
        res = requests.get(path)
        if res.status_code == 200:
            print(f"[+] Found theme (aggressive): {theme}")
            found_themes.append(theme)

    return found_plugins, found_themes


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
        passive_plugin_theme_detection(target)
        aggressive_plugin_theme_detection(target)
        print("\n[*] Plugin and theme detection complete.")

    else:
        print("[-] Target does not appear to be a WordPress site.")

if __name__ == "__main__":
    main()
