import requests
import time
import random
import argparse
import re
from colorama import Fore, Style
from urllib.parse import urlparse

# Color configuration
GREEN = Fore.GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
RESET = Style.RESET_ALL

# List of common WordPress paths
routes = [
    "/wp-admin", "/wp-login.php", "/wp-content/", "/wp-content/themes/",
    "/wp-content/plugins/", "/wp-content/uploads/", "/wp-includes/",
    "/wp-json/", "/xmlrpc.php", "/readme.html", "/license.txt",
    "/wp-config.php", "/wp-cron.php", "/feed/", "/sitemap.xml",
    "/robots.txt", "/wp-admin/admin-ajax.php", "/wp-admin/admin-post.php",
    "/wp-content/debug.log", "/wp-content/db.php", "/wp-sitemap.xml"
]

# List of User-Agents to avoid detection
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36"
]

# Realistic HTTP headers
DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Accept-Language": "en-US,en;q=0.5"
}

# ASCII Banner
def print_banner():
    print(GREEN + """
     _       ______  ____        __  __    ___                __                     
    | |     / / __ \/ __ \____ _/ /_/ /_  /   |  ____  ____ _/ /_  ______  ___  _____
    | | /| / / /_/ / /_/ / __ `/ __/ __ \/ /| | / __ \/ __ `/ / / / /_  / / _ \/ ___/
    | |/ |/ / ____/ ____/ /_/ / /_/ / / / ___ |/ / / / /_/ / / /_/ / / /_/  __/ /    
    |__/|__/_/   /_/    \__,_/\__/_/ /_/_/  |_/_/ /_/\__,_/_/\__, / /___/\___/_/     
                                                        /____/                   
    """ + RESET)
    print(f"{GREEN}[+] WP Path Analyzer - Common Path Scanner for WordPress{RESET}\n")

# Function to validate and normalize URLs
def normalize_url(url):
    # Clean the URL and ensure it has the correct format
    url = url.strip()

    # If the URL does not have http:// or https://, add https://
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    # Try to parse the URL to ensure it's valid
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        print(f"{RED}[-] Malformed URL: {url}. Please ensure it's written correctly.{RESET}")
        return None
    
    return url.rstrip("/")

# Function to detect if a site is WordPress and get the version
def detect_wordpress(base_url):
    print(f"{BLUE}🔍 Checking if {base_url} is using WordPress...{RESET}")

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        **DEFAULT_HEADERS
    }

    try:
        # Check /wp-json/
        response = requests.get(f"{base_url}/wp-json/", headers=headers, timeout=10)
        if response.status_code == 200 and "wp:" in response.text:
            print(f"{GREEN}[+] WordPress detected on {base_url} via /wp-json/{RESET}")
        else:
            # Check meta generator
            response = requests.get(base_url, headers=headers, timeout=10)
            if response.status_code == 200 and 'name="generator"' in response.text:
                print(f"{GREEN}[+] WordPress detected on {base_url} via meta-generator{RESET}")
            else:
                print(f"{RED}[-] This doesn't appear to be a WordPress site.{RESET}")
                return False

        # Extract WordPress version from meta generator
        match = re.search(r'<meta name="generator" content="WordPress ([\d\.]+)"', response.text)
        if match:
            print(f"{YELLOW}[!] Version detected: {match.group(1)}{RESET}")
        else:
            # Try to detect the version through the readme.html or license.txt files
            for file in ["/readme.html", "/license.txt"]:
                response = requests.get(base_url + file, headers=headers, timeout=10)
                if response.status_code == 200:
                    match = re.search(r'WordPress (\d+\.\d+)', response.text)
                    if match:
                        print(f"{YELLOW}[!] Version detected in {file}: {match.group(1)}{RESET}")
                        return True

            # Check wp-includes/version.php if accessible
            response = requests.get(base_url + "/wp-includes/version.php", headers=headers, timeout=10)
            if response.status_code == 200:
                match = re.search(r"\$wp_version = '(\d+\.\d+(\.\d+)?)';", response.text)
                if match:
                    print(f"{YELLOW}[!] Version detected in wp-includes/version.php: {match.group(1)}{RESET}")
                    return True

            # Check resource file URLs to detect version
            for route in ["/wp-content/themes", "/wp-content/plugins"]:
                response = requests.get(base_url + route, headers=headers, timeout=10)
                if response.status_code == 200:
                    match = re.search(r"wp-content/(themes|plugins)/[^\s/]+/.*\.css\?ver=(\d+\.\d+(\.\d+)?)", response.text)
                    if match:
                        print(f"{YELLOW}[!] Version detected in CSS resource: {match.group(2)}{RESET}")
                        return True

            print(f"{YELLOW}[!] Could not determine the WordPress version.{RESET}")

        return True

    except requests.exceptions.RequestException as e:
        print(f"{RED}[-] Error connecting to {base_url}: {e}{RESET}")
        return False

# Function to scan WordPress routes
def scan_wordpress(base_url):
    print(f"{BLUE} Scanning routes on {base_url}...\n{RESET}")

    for route in routes:
        full_url = base_url + route
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Referer": base_url,
            **DEFAULT_HEADERS
        }

        try:
            time.sleep(random.uniform(1, 4))
            response = requests.get(full_url, headers=headers, allow_redirects=True, timeout=10)

            if response.status_code == 200:
                print(f"{GREEN}[+] Route found: {full_url} (200 OK){RESET}")
            elif response.status_code == 403:
                print(f"{YELLOW}[!] Route blocked: {full_url} (403 Forbidden){RESET}")
            elif response.status_code == 401:
                print(f"{YELLOW}[!] Route protected: {full_url} (401 Unauthorized){RESET}")
            elif 300 <= response.status_code < 400:
                print(f"{BLUE}[~] Redirection detected: {full_url} → {response.url} ({response.status_code}){RESET}")
            elif response.status_code == 404:
                print(f"{RED}[-] Route not found: {full_url} (404 Not Found){RESET}")
            else:
                print(f"{RED}[-] Unknown status: {full_url} ({response.status_code}){RESET}")

        except requests.exceptions.Timeout:
            print(f"{RED}[-] Timeout connecting to {full_url}{RESET}")
        except requests.exceptions.ConnectionError:
            print(f"{RED}[-] Connection error with {full_url}{RESET}")
        except requests.exceptions.RequestException as e:
            print(f"{RED}[-] Error connecting to {full_url}: {e}{RESET}")

# Main function with CLI arguments and interactive option
def main():
    parser = argparse.ArgumentParser(description="Common Path Scanner for WordPress with version detection")
    parser.add_argument("-u", "--url", help="Site URL or multiple URLs separated by commas")
    args = parser.parse_args()

    print_banner()

    if not args.url:
        user_input = input(f"{YELLOW}[?] Enter the site URL to analyze: {RESET}").strip()
        if not user_input:
            print(f"{RED}[-] No URL entered. Exiting...{RESET}")
            return
        url_list = [normalize_url(user_input)]
    else:
        url_list = [normalize_url(url) for url in args.url.split(",")]

    for url in url_list:
        if url:  # Only process if the URL is valid
            if detect_wordpress(url):
                scan_wordpress(url)

    print("\n Analysis completed.")

if __name__ == "__main__":
    main()
