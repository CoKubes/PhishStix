# Imports
import os
import threading
import time
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import schedule
import validators
from urllib.parse import unquote


# Import utility functions
from utils.url_checks import *
from utils.domain_checks import *
from utils.html_analysis import *

#Import global variables
from config import SAFE_BROWSING_API_KEY

# Load environment variables
load_dotenv()

# Global Configurations
app = Flask(__name__)
CORS(app)  # Enables cross-origin requests

#logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        RotatingFileHandler("phishing_analyzer.log", maxBytes=5*1024*1024, backupCount=3),
        logging.StreamHandler()
    ]
)

# Global variables
TRUSTED_DOMAINS = []
TRUSTED_DOMAINS = fetch_tranco_list()

# Scheduler setup
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
