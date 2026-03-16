from urllib.parse import urlparse
import re
import whois
import dns.resolver
from datetime import datetime
from .logger import Logger

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            days_old = (datetime.now() - creation_date).days
            return days_old
    except Exception:
        pass
    return None

def has_dns_records(domain):
    try:
        # Checking for basic A records to see if it even resolves
        dns.resolver.resolve(domain, 'A')
        return True
    except Exception:
        return False

def check_reputation(url):
    """
    Performs a basic domain reputation check by analyzing TLDs, IP use,
    domain registration age, and DNS record presence.
    """
    Logger.security("Performing URL reputation check & DNS lookups...")

    if not url.startswith('http'):
        url = 'http://' + url

    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    score = 0
    reputation_details = []

    # 1. Suspicious TLDs
    suspicious_tlds = ['.xyz', '.club', '.tk', '.top', '.pw', '.buzz', '.info', '.online']
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        score += 50
        reputation_details.append("Suspicious TLD")

    # 2. Raw IP instead of domain name
    ip_pattern = re.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$")
    if ip_pattern.match(domain):
        score += 30
        reputation_details.append("Using IP instead of domain")

    # 3. Excessive subdomains
    dots = domain.count('.')
    if dots > 3:
        score += 20
        reputation_details.append("Excessive subdomains")

    # 4. Multiple hyphens in domain
    if domain.count('-') >= 2:
        score += 30
        reputation_details.append("Multiple hyphens")

    # 5. DNS and WHOIS (Age) check
    if not ip_pattern.match(domain):  # only check WHOIS/DNS if it's an actual domain
        if not has_dns_records(domain):
            score += 40
            reputation_details.append("Missing DNS A records")
        
        age_days = get_domain_age(domain)
        if age_days is not None:
            if age_days < 180: # less than 6 months old
                score += 40
                reputation_details.append(f"Newly registered domain ({age_days} days old)")
        else:
            score += 10
            reputation_details.append("Could not fetch WHOIS data")

    # Evaluate score
    if score >= 50:
        reputation = "High Risk"
    elif 20 <= score < 50:
        reputation = "Medium Risk"
    else:
        reputation = "Low Risk"

    Logger.security(f"Domain reputation score: {reputation}")
    return reputation, reputation_details
