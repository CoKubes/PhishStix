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

# Load environment variables
load_dotenv()

# Global Configurations
app = Flask(__name__)
CORS(app)  # Enables cross-origin requests

logging.basicConfig(
    level=logging.DEBUG, # Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        RotatingFileHandler("phishing_analyzer.log", maxBytes=5*1024*1024, backupCount=3),  # 5MB per file, 3 backups
        logging.StreamHandler() #prints logs to the console
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

def fetch_tranco_list():
    """Fetch the Tranco top 1000 domains and ensure critical domains are included."""
    try:
        # Fetch the Tranco list
        url = "https://tranco-list.eu/top-1m.csv.zip"
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        # Extract domains from the ZIP file
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            with z.open("top-1m.csv") as f:
                domains = [line.decode("utf-8").split(",")[1].strip() for line in f.readlines()[1:]]  # Skip header
        
        # Combine Tranco list with critical domains, avoiding duplicates
        combined_domains = list(set(domains[:1000] + CRITICAL_DOMAINS))
        return combined_domains
    except requests.RequestException as e:
        print(f"Error fetching Tranco list: {e}")
        return CRITICAL_DOMAINS  # Fallback to critical domains

def check_google_safe_browsing(url):
    """Check the URL against Google Safe Browsing."""
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

def check_domain_similarity(domain, trusted_domains):
    """Check if the domain is similar to any trusted domain."""
    for trusted in trusted_domains:
        if domain == trusted:  # Skip self-comparison
            continue
        max_distance = max(len(domain), len(trusted)) * 0.2  # Allow up to 20% difference
        if levenshtein_distance(domain, trusted) <= max_distance:
            return trusted
    return None

def analyze_redirect_chain(url):
        logging.info(f"Starting redirect chain analysis for URL: {url}")
        try:
            # Track visited URLs
            visited_urls = []

            # Make the request and follow redirects
            response = requests.get(url, timeout=10, allow_redirects=True)

            # Extract the chain (of URLs)
            for history in response.history:
                visited_urls.append(history.url)
                logging.debug(f"Redirected to: {history.url}")

            # Add the final URL
            final_url = response.url
            visited_urls.append(final_url)
            logging.info(f"Final URL after redirects: {final_url}")

            # Analysis
            is_suspicious = len(visited_urls) > 5  # Adjust threshold as needed
            reason = "Excessive redirects detected." if is_suspicious else "Redirect chain looks normal."
            
            return {
                "is_suspicious": is_suspicious,
                "reason": reason,
                "chain": visited_urls,
                "final_url": final_url
            }
        except requests.RequestException as e:
            print(f"Error during redirect analysis: {e}")
            return {
                "is_suspicious": True,
                "reason": "Error fetching URL during redirect analysis",
                "chain": [],
                "final_url": None
            }
        
import tldextract

def get_base_domain(domain):
    """Extract the base domain from a full domain."""
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}"  # e.g., "google.com" from "mail.google.com"
        
def analyze_links(soup, current_domain):
    """Analyze links to detect clearly suspicious behavior."""
    analysis_results = []
    links = soup.find_all('a', href=True)

    for link in links:
        link_text = link.text.strip().lower()
        href = link['href'].strip().lower()

        # Ignore links without meaningful text or href
        if not link_text or not href:
            continue

        # Skip internal anchors and utility links
        if href.startswith('#') or any(phrase in link_text for phrase in [
            "privacy policy", "terms of use", "accessibility", "skip to content"
        ]):
            continue

        # Extract domains for comparison
        parsed_href = urlparse(href)
        href_domain = parsed_href.netloc
        current_base_domain = get_base_domain(current_domain)
        href_base_domain = get_base_domain(href_domain)

        # Flag links where text suggests one domain but points to another
        if href_domain and href_base_domain != current_base_domain and link_text in current_base_domain:
            analysis_results.append(f"Suspicious link: text '{link_text}' points to unrelated domain '{href_domain}'.")

        # Flag obfuscated links (e.g., with encoded characters)
        if re.search(r"%[0-9A-Fa-f]{2}", href) or re.match(r"(\d{1,3}\.){3}\d{1,3}", href_domain):
            analysis_results.append(f"Obfuscated or suspicious link: '{href}'.")

    return analysis_results

def analyze_forms(soup, current_domain):
    """Analyze forms to detect phishing attempts."""
    analysis_results = []
    forms = soup.find_all('form')

    for form in forms:
        action = form.get('action', '').strip().lower()
        if action:
            parsed_action = urlparse(action)
            action_domain = parsed_action.netloc

            # Flag forms submitting to external domains
            if action_domain and action_domain != current_domain:
                analysis_results.append(f"Form submitting to external domain: '{action}'.")
    return analysis_results

def analyze_html_content(url):
    """Fetch and analyze the HTML content of a URL for phishing indicators."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'lxml')
        analysis_results = []

        # Extract current domain
        current_domain = urlparse(url).netloc

        # Analyze links and forms
        link_issues = analyze_links(soup, current_domain)
        form_issues = analyze_forms(soup, current_domain)

        # Combine results
        analysis_results.extend(link_issues)
        analysis_results.extend(form_issues)

        return analysis_results
    except requests.RequestException as e:
        logging.error(f"Error fetching HTML content for {url}: {e}")
        return [f"Error fetching HTML content: {str(e)}"]
    except Exception as e:
        logging.error(f"Error analyzing HTML content for {url}: {e}")
        return [f"Error analyzing HTML content: {str(e)}"]

# Scheduler Logic
def update_trusted_domains():
    global TRUSTED_DOMAINS
    TRUSTED_DOMAINS = fetch_tranco_list()
    print(f"Updated trusted domains. Total: {len(TRUSTED_DOMAINS)} domains.")

schedule.every().monday.at("00:00").do(update_trusted_domains)

def run_scheduler():
    """Run the scheduler in a background thread."""
    while True:
        schedule.run_pending()
        time.sleep(1)

scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
scheduler_thread.start()

# Fetch the initial trusted domains list
TRUSTED_DOMAINS = fetch_tranco_list()


# Flask Application Logic
@app.route('/analyze_url', methods=['GET', 'POST'])
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

    # 1. Common Phishing Keywords
    keywords = ['login', 'secure', 'account', 'verify', 'bank']
    if any(keyword in decoded_url.lower() for keyword in keywords):
        risk_score += 50
        reasons.append("Contains sketchy keyword(s) commonly used in phishing URLs.")

    # 2. Obfuscated Characters
    if re.search(r"%[0-9A-Fa-f]{2}", url):
        risk_score += 30
        reasons.append("URL contains encoded characters that may hide intent.")

    # 3. Suspicious Subdomains
    if parsed_url.netloc.count('.') > 2:
        risk_score += 40
        reasons.append("Excessive subdomains detected.")

    # 4. Suspicious TLDs
    suspicious_tlds = ['.xyz', '.club', '.top', '.info', '.online']
    if any(parsed_url.netloc.endswith(tld) for tld in suspicious_tlds):
        risk_score += 30
        reasons.append("Suspicious TLD detected.")

    # 5. IP Address Instead of Domain Name
    if re.match(r"(\d{1,3}\.){3}\d{1,3}", parsed_url.netloc):
        risk_score += 50
        reasons.append("Domain uses an IP address instead of a name.")

    # 6. Redirect Chain Analysis
    redirect_analysis = analyze_redirect_chain(decoded_url)
    if redirect_analysis["is_suspicious"]:
        risk_score += 50
        reasons.append(redirect_analysis["reason"])
        reasons.append(f"Redirect chain: {' -> '.join(redirect_analysis['chain'])}")

    final_url = redirect_analysis["final_url"]
    if final_url:
        # 7. Google Safe Browsing Check (for final URL)
        if check_google_safe_browsing(final_url):
            risk_score += 100
            reasons.append("Final URL is flagged as unsafe by Google Safe Browsing.")

        # 8. Domain Similarity Check (for final domain)
        final_domain = urlparse(final_url).netloc.lower()
        similar_domain = check_domain_similarity(final_domain, TRUSTED_DOMAINS)
        if similar_domain:
            risk_score += 70
            reasons.append(f"Final domain {final_domain} is visually similar to trusted domain {similar_domain}.")

    # 9. Content-Based Analysis (HTML-specific checks)
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

# Main Execution
if __name__ == '__main__':
    app.run(debug=True)
