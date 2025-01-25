import requests
import zipfile
import io
from Levenshtein import distance as levenshtein_distance
from flask import logging
import tldextract
import logging
import socket

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
    
def get_base_domain(domain):
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}"
    
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
