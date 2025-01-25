import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import logging
import requests
from utils.domain_checks import get_base_domain

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
