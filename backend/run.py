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

# Load environment variables
load_dotenv()

# Global Configurations
app = Flask(__name__)
CORS(app)  # Enables cross-origin requests

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
    payload = {
        "client": {
            "clientId": "yourapp",
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
        return "matches" in data
    except requests.RequestException as e:
        print(f"Error contacting Google Safe Browsing API: {e}")
        return False

def check_domain_similarity(domain, trusted_domains):
    """Check if the domain is similar to any trusted domain."""
    for trusted in trusted_domains:
        max_distance = max(len(domain), len(trusted)) * 0.2  # Allow up to 20% difference
        if levenshtein_distance(domain, trusted) <= max_distance:
            return trusted
    return None

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
@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    """Analyze a URL for phishing indicators."""
    data = request.get_json()
    url = data.get("url", "")

    # Form checks
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    if not validators.url(url):
        return jsonify({"error": "Invalid URL format"}), 400

    # Starter phishing detection logic
    risk_score = 0
    reasons = []

    # Decode URL
    decoded_url = unquote(url)
    parsed_url = urlparse(decoded_url)
    domain = parsed_url.netloc.lower()

    # 1. Check for common phishing keywords
    keywords = ['login', 'secure', 'account', 'verify', 'bank']
    if any(keyword in decoded_url.lower() for keyword in keywords):
        risk_score += 50
        reasons.append("Contains sketchy keyword(s) commonly used in phishing URLs.")

    # 2. Detect obfuscated characters
    if re.search(r"%[0-9A-Fa-f]{2}", url):
        risk_score += 30
        reasons.append("URL contains encoded characters that may hide intent.")

    # 3. Suspicious subdomains
    if parsed_url.netloc.count('.') > 2:
        risk_score += 40
        reasons.append("Excessive subdomains detected.")

    # 4. Suspicious TLDs
    suspicious_tlds = ['.xyz', '.club', '.top', '.info', '.online']
    if any(parsed_url.netloc.endswith(tld) for tld in suspicious_tlds):
        risk_score += 30
        reasons.append("Suspicious TLD detected.")

    # 5. Check for IP address instead of domain name
    if re.match(r"(\d{1,3}\.){3}\d{1,3}", parsed_url.netloc):
        risk_score += 50
        reasons.append("Domain uses an IP address instead of a name.")

    # 6. Google Safe Browsing Check
    if check_google_safe_browsing(decoded_url):
        risk_score += 100
        reasons.append("URL is flagged as unsafe by Google Safe Browsing.")

    # 7. Typosquat check
    print(f"Trusted domains: {TRUSTED_DOMAINS[:10]}")  # Print the first 10 domains
    similar_domain = check_domain_similarity(domain, TRUSTED_DOMAINS)
    if similar_domain:
        risk_score += 70
        reasons.append(f"Domain {domain} is visually similar to trusted domain {similar_domain}.")

    return jsonify({
        "url": url,
        "risk_score": risk_score,
        "reasons": reasons
    })

# Main Execution
if __name__ == '__main__':
    app.run(debug=True)
