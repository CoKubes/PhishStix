import requests
from urllib.parse import urlparse, unquote
import re
from flask import Flask, request, jsonify
from flask_cors import CORS
import validators
from dotenv import load_dotenv
import os

#Load environment variables from .env
load_dotenv()

app = Flask(__name__)
CORS(app) #enables cross-origin requests

SAFE_BROWSING_API_KEY = os.getenv("API_KEY")
if not SAFE_BROWSING_API_KEY:
    raise ValueError("API_KEY is not set. Please add your .env file")

def check_google_safe_browsing(url):
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

@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    data = request.get_json()
    url = data.get("url", "")

    #Form checks
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    if not validators.url(url):
        return jsonify({"error": "Invalid URL format"}), 400

    #starter phishing detection logic
    risk_score = 0
    reasons = []

    #Decode URL
    decoded_url = unquote(url)
    parsed_url = urlparse(decoded_url)

    #1 Check for common phishing keywords
    keywords = ['login', 'secure', 'account', 'verify', 'bank']
    if any(keyword in decoded_url.lower() for keyword in keywords):
        risk_score += 50
        reasons.append("Contains sketchy key word(s) commonly used in phishing URLs.")

    #2 Detect obfuscated chatacters
    if re.search(r"%[0-9A-Fa-f]{2}", url):
        risk_score += 30
        reasons.append("URL contains encoded characters that may hide intent.")

    #3 Suspicious subdomains
    if parsed_url.netloc.count('.') > 2:
        risk_score += 40
        reasons.append("Excessive subdomains detected.")

    #4 Suspicios TLD
    suspicious_tlds = ['.xyz', '.club', '.top', '.info', '.online']
    if any(parsed_url.netloc.endswith(tld) for tld in suspicious_tlds):
        risk_score += 30
        reasons.append("Suspicious TLD detected.")

    #5 Check for IP address instead of domain name
    if re.match(r"(\d{1,3}\.){3}\d{1,3}", parsed_url.netloc):
        risk_score += 50
        reasons.append("Domain uses an IP address instead of a name.")

    #6 Google Safe Browsing Check
    if check_google_safe_browsing(decoded_url):
        risk_score += 100
        reasons.append("URL is flagged as unsafe by Google Safe Browsing.")

    return jsonify({
        "url": url,
        "risk_score": risk_score,
        "reasons": reasons
    })

if __name__ == '__main__':
    app.run(debug=True)