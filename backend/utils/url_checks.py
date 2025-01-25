import requests
import logging
import os
from config import SAFE_BROWSING_API_KEY

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
