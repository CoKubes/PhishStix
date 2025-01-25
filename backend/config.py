import os
from dotenv import load_dotenv

load_dotenv()

# Flask configurations
DEBUG = True
HOST = "127.0.0.1"
PORT = 5000

# Google Safe Browsing API Key
SAFE_BROWSING_API_KEY = os.getenv("API_KEY")

# Tranco List URL
TRANCO_LIST_URL = "https://tranco-list.eu/top-1m.csv.zip"

# Critical domains
CRITICAL_DOMAINS = [
    "google.com",
    "paypal.com",
    "amazon.com",
    "microsoft.com",
    "bankofamerica.com"
]

# Suspicious TLDs
SUSPICIOUS_TLDS = ['.xyz', '.club', '.top', '.info', '.online']
