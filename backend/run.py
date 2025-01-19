from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import validators

app = Flask(__name__)
CORS(app) #enables cross-origin requests

@app.route('/test', methods=['GET'])
def test():
    return jsonify({"message": "Backend is running!"})

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

    if 'login' in url or 'secure' in url:
        risk_score += 50
        reasons.append("Contains sketchy key words commonly used in phishing URLs.")

    if re.search(r"(\d{1,3}\.){3}\d{1,3}", url):
        risk_score += 30
        reasons.append("Its kind of weird to use an IP address instead of a domain name.")

    if len(url) > 100:
        risk_score += 20
        reasons.append("URL is suspiciously long.")

    return jsonify({
        "url": url,
        "risk_score": risk_score,
        "reasons": reasons
    })

if __name__ == '__main__':
    app.run(debug=True)