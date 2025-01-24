# Imports
import os
import re
import time
import threading
import requests
import zipfile
import io
import schedule
from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse, unquote
from Levenshtein import distance as levenshtein_distance
import validators
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler
from bs4 import BeautifulSoup
import tldextract
import socket

# Load environment variables
load_dotenv()

# Global Configurations
app = Flask(__name__)
CORS(app)  # Enables cross-origin requests

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        RotatingFileHandler("phishing_analyzer.log", maxBytes=5*1024*1024, backupCount=3),
        logging.StreamHandler()
    ]
)

SAFE_BROWSING_API_KEY = os.getenv("API_KEY")
if not SAFE_BROWSING_API_KEY:
    raise ValueError("API_KEY is not set. Please add it to your .env file.")

TRUSTED_DOMAINS = []

# Helper Functions
CRITICAL_DOMAINS = [
    "google.com",
    "paypal.com",
    "amazon.com",
    "microsoft.com",
    "bankofamerica.com"
]

def is_domain_resolvable(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False
    
def check_domain_similarity(domain, trusted_domains):
    for trusted in trusted_domains:
        # Skip self-comparison
        if domain == trusted:
            continue

        # Define a threshold for similarity (20% of the longer domain's length)
        max_distance = max(len(domain), len(trusted)) * 0.2
        if levenshtein_distance(domain, trusted) <= max_distance:
            return trusted  # Return the similar trusted domain
    return None

def fetch_tranco_list():
    try:
        url = "https://tranco-list.eu/top-1m.csv.zip"
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            with z.open("top-1m.csv") as f:
                domains = [line.decode("utf-8").split(",")[1].strip() for line in f.readlines()[1:]]
        
        combined_domains = list(set(domains[:1000] + CRITICAL_DOMAINS))
        return combined_domains
    except requests.RequestException as e:
        print(f"Error fetching Tranco list: {e}")
        return CRITICAL_DOMAINS

def check_google_safe_browsing(url):
    logging.info(f"Checking URL against Google Safe Browsing: {url}")
    payload = {
        "client": {
            "clientId": "phishing_analyzer",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}",
            json=payload
        )
        data = response.json()
        logging.debug(f"Google Safe Browsing response for {url}: {data}")
        return "matches" in data
    except requests.RequestException as e:
        logging.error(f"Error contacting Google Safe Browsing API for {url}: {e}")
        return False

def analyze_redirect_chain(url):
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        chain = [resp.url for resp in response.history]
        chain.append(response.url)
        return {
            "is_suspicious": len(chain) > 5,
            "reason": "Excessive redirects detected." if len(chain) > 5 else "Redirect chain looks normal.",
            "chain": chain,
            "final_url": response.url
        }
    except requests.exceptions.ConnectionError:
        return {
            "is_suspicious": True,
            "reason": "Domain cannot be resolved or connection failed.",
            "chain": []
        }
    except requests.RequestException as e:
        return {
            "is_suspicious": True,
            "reason": f"Error during redirect analysis: {e}",
            "chain": []
        }

def get_base_domain(domain):
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}"

def analyze_links(soup, current_domain):
    analysis_results = []
    links = soup.find_all('a', href=True)

    for link in links:
        link_text = link.text.strip().lower()
        href = link['href'].strip().lower()

        if not link_text or not href:
            continue

        if href.startswith('#') or any(phrase in link_text for phrase in [
            "privacy policy", "terms of use", "accessibility", "skip to content"
        ]):
            continue

        parsed_href = urlparse(href)
        href_domain = parsed_href.netloc
        current_base_domain = get_base_domain(current_domain)
        href_base_domain = get_base_domain(href_domain)

        if href_domain and href_base_domain != current_base_domain and link_text in current_base_domain:
            analysis_results.append(f"Suspicious link: text '{link_text}' points to unrelated domain '{href_domain}'.")
        
        if re.search(r"%[0-9A-Fa-f]{2}", href) or re.match(r"(\d{1,3}\.){3}\d{1,3}", href_domain):
            analysis_results.append(f"Obfuscated or suspicious link: '{href}'.")

    return analysis_results

def analyze_html_content(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'lxml')
        analysis_results = []

        current_domain = urlparse(url).netloc

        link_issues = analyze_links(soup, current_domain)
        analysis_results.extend(link_issues)

        return analysis_results
    except requests.RequestException as e:
        logging.error(f"Error fetching HTML content for {url}: {e}")
        return [f"Error fetching HTML content: {str(e)}"]
    except Exception as e:
        logging.error(f"Error analyzing HTML content for {url}: {e}")
        return [f"Error analyzing HTML content: {str(e)}"]

def update_trusted_domains():
    global TRUSTED_DOMAINS
    TRUSTED_DOMAINS = fetch_tranco_list()
    print(f"Updated trusted domains. Total: {len(TRUSTED_DOMAINS)} domains.")

schedule.every().monday.at("00:00").do(update_trusted_domains)

def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(1)

scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
scheduler_thread.start()

TRUSTED_DOMAINS = fetch_tranco_list()

@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    """Analyze a URL for phishing indicators."""
    data = request.get_json()
    url = data.get("url", "")
    logging.info(f"Received request to analyze URL: {url}")

    # Validate input
    if not url:
        logging.warning("No URL provided in the request.")
        return jsonify({"error": "No URL provided"}), 400
    if not validators.url(url):
        logging.warning(f"Invalid URL format: {url}")
        return jsonify({"error": "Invalid URL format"}), 400

    risk_score = 0
    reasons = []

    # Decode URL
    decoded_url = unquote(url)
    parsed_url = urlparse(decoded_url)
    domain = parsed_url.netloc.lower()

    # 0. Check if the domain is resolvable
    # This ensures that the domain exists and can be reached.
    if not is_domain_resolvable(domain):
        return jsonify({
            "risk_score": 100,
            "reasons": ["Domain cannot be resolved. It may not exist or is unreachable."]
        })

    # 1. Common Phishing Keywords
    # Checks for words like "login" or "verify" in the URL, which are commonly used in phishing attempts.
    keywords = ['login', 'secure', 'account', 'verify', 'bank']
    if any(keyword in decoded_url.lower() for keyword in keywords):
        risk_score += 50
        reasons.append("Contains sketchy keyword(s) commonly used in phishing URLs.")

    # 2. Obfuscated Characters
    # Flags URLs that contain encoded characters (e.g., %20), which can hide the intent of the URL.
    if re.search(r"%[0-9A-Fa-f]{2}", url):
        risk_score += 30
        reasons.append("URL contains encoded characters that may hide intent.")

    # 3. Suspicious Subdomains
    # Flags URLs with excessive subdomains, which may indicate a phishing attempt.
    if parsed_url.netloc.count('.') > 2:
        risk_score += 40
        reasons.append("Excessive subdomains detected.")

    # 4. Suspicious TLDs (Top-Level Domains)
    # Flags URLs with less reputable TLDs that are often associated with malicious behavior.
    suspicious_tlds = ['.xyz', '.club', '.top', '.info', '.online']
    if any(parsed_url.netloc.endswith(tld) for tld in suspicious_tlds):
        risk_score += 30
        reasons.append("Suspicious TLD detected.")

    # 5. IP Address Instead of Domain Name
    # Flags URLs that use an IP address instead of a domain name, which is unusual for legitimate sites.
    if re.match(r"(\d{1,3}\.){3}\d{1,3}", parsed_url.netloc):
        risk_score += 50
        reasons.append("Domain uses an IP address instead of a name.")

    # 6. Redirect Chain Analysis
    # Examines the redirect chain for excessive redirects or suspicious behavior.
    redirect_analysis = analyze_redirect_chain(decoded_url)
    if redirect_analysis["is_suspicious"]:
        risk_score += 50
        reasons.append(redirect_analysis["reason"])
        reasons.append(f"Redirect chain: {' -> '.join(redirect_analysis['chain'])}")

    final_url = redirect_analysis["final_url"]
    if final_url:
        # 7. Google Safe Browsing Check (for final URL)
        # Uses Google's API to check if the URL is flagged as malicious.
        if check_google_safe_browsing(final_url):
            risk_score += 100
            reasons.append("Final URL is flagged as unsafe by Google Safe Browsing.")

        # 8. Domain Similarity Check (for final domain)
        # Compares the final domain to a list of trusted domains for potential typosquatting.
        final_domain = urlparse(final_url).netloc.lower()
        similar_domain = check_domain_similarity(final_domain, TRUSTED_DOMAINS)
        if similar_domain:
            risk_score += 70
            reasons.append(f"Final domain {final_domain} is visually similar to trusted domain {similar_domain}.")

    # 9. Content-Based Analysis (HTML-specific checks)
    # Fetches the HTML of the page and analyzes links, forms, and suspicious keywords.
    html_analysis = analyze_html_content(decoded_url)
    if html_analysis:
        risk_score += 50
        reasons.extend(html_analysis)

    logging.info(f"Analysis completed for URL: {url}")
    return jsonify({
        "url": url,
        "risk_score": risk_score,
        "reasons": reasons
    })

if __name__ == '__main__':
    app.run(debug=True)
