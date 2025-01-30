import os
import re
import tldextract
import requests
import socket
import ssl
from urllib.parse import urlparse

# Load API keys from environment variables
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Trusted and blacklisted domains
trusted_domains = {"google.com", "microsoft.com", "github.com", "facebook.com", "amazon.com"}
blacklisted_domains = {"g0ogle.com", "phishingsite.com", "fakebank.com", "malicioussite.net"}

# Normalize URL

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url  # Default to HTTP
    return url

# Validate URL format
def is_valid_url(url):
    regex = re.compile(
        r"^(http|https)://"  # Protocol
        r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}|\d{1,3}(?:\.\d{1,3}){3})"  # Domain or IP
        r"(:\d+)?(/.*)?$"  # Port and path
    )
    return re.match(regex, url) is not None

# Check if the URL is an IP address
def is_ip_address(url):
    try:
        ip = urlparse(url).hostname
        if ip and socket.inet_aton(ip):
            return True
        return False
    except (socket.error, TypeError):
        return False

# Check if the domain has SSL
def check_ssl(url):
    try:
        hostname = urlparse(url).hostname
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.version() is not None
    except Exception:
        return False

# Check if the site is accessible
def is_site_working(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

# Get site headers
def get_site_info(url):
    try:
        response = requests.head(url, timeout=5)
        return response.headers
    except requests.exceptions.RequestException:
        return None

# Google Safe Browsing API check
def google_safe_browsing_check(url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    payload = {
        "client": {"clientId": "phishing-checker", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(api_url, json=payload, timeout=10)
        if response.status_code == 200:
            result = response.json()
            return result if "matches" in result else None
    except requests.exceptions.RequestException:
        return None

# VirusTotal API check
def virustotal_check(url):
    scan_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.post(scan_url, headers=headers, data={"url": url}, timeout=10)
        if response.status_code == 200:
            scan_id = response.json()["data"]["id"]
            report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
            report_response = requests.get(report_url, headers=headers, timeout=10)
            return report_response.json()
        return None
    except requests.exceptions.RequestException:
        return None

# Phishing link scanner
def phishing_link_scanner(url):
    print(f"Checking URL: {url}")
    url = normalize_url(url)
    print(f"Normalized URL: {url}")

    if not is_valid_url(url):
        print("[ERROR] Invalid URL format!")
        return "Invalid URL format."

    print("[INFO] URL format is valid.")

    if is_ip_address(url):
        print("[WARNING] URL is an IP address. Proceed with caution.")
        return "Potentially suspicious: URL is an IP address."

    domain = tldextract.extract(url).registered_domain

    if domain in trusted_domains:
        print("[INFO] Trusted website.")
        return "Trusted Website."
    elif domain in blacklisted_domains:
        print("[WARNING] Blacklisted website!")
        return "Blacklisted Website."

    if not is_site_working(url):
        print("[WARNING] The website is not accessible.")
        return "Not a working site."

    print("[INFO] Checking SSL...")
    if check_ssl(url):
        print("[INFO] Valid SSL certificate.")
    else:
        print("[WARNING] No SSL certificate detected.")

    print("[INFO] Retrieving site headers...")
    site_info = get_site_info(url)
    if site_info:
        for key, value in site_info.items():
            print(f"{key}: {value}")
    else:
        print("[WARNING] Failed to retrieve site info.")

    print("[INFO] Checking Google Safe Browsing...")
    gsb_result = google_safe_browsing_check(url)
    if gsb_result:
        print("[ALERT] Google Safe Browsing flagged this URL:")
        print(gsb_result)
    else:
        print("[INFO] Google Safe Browsing did not flag this URL.")

    print("[INFO] Checking VirusTotal...")
    vt_result = virustotal_check(url)
    if vt_result:
        print("[ALERT] VirusTotal flagged this URL:")
        print(vt_result)
    else:
        print("[INFO] VirusTotal did not flag this URL.")

    print("Final Verdict: Scanning Complete.")

# Input URL
url_to_check = input("Enter the URL to check: ")
phishing_link_scanner(url_to_check)
