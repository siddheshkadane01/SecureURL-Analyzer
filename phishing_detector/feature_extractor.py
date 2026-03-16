import re
from urllib.parse import urlparse

def extract_features(url):
    """
    Extracts 8 educational features from a URL for phishing detection.
    Returns: A list of numerical features.
    Features:
    0: URL length
    1: Number of dots in domain
    2: Number of subdomains (approx)
    3: Presence of @ symbol
    4: Presence of - symbol
    5: Presence of IP address in domain
    6: HTTPS usage (1 for yes, 0 for no)
    7: Number of suspicious keywords
    """

    features = []

    # 1. URL length
    features.append(len(url))

    # Parse URL
    if not url.startswith("http"):
        parsed_url = urlparse("http://" + url)
    else:
        parsed_url = urlparse(url)

    domain = parsed_url.netloc

    # 2. Number of dots in domain
    num_dots = domain.count('.')
    features.append(num_dots)

    # 3. Number of subdomains (approximated based on dots)
    subdomains = max(0, num_dots - 1)
    features.append(subdomains)

    # 4. Presence of @ symbol in URL (often used for obfuscation)
    has_at = 1 if '@' in url else 0
    features.append(has_at)

    # 5. Presence of - symbol in domain (often used in phishing domains)
    has_hyphen = 1 if '-' in domain else 0
    features.append(has_hyphen)

    # 6. Presence of IP address in domain
    ip_pattern = re.compile(
        r"^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    )
    has_ip = 1 if ip_pattern.match(domain) else 0
    features.append(has_ip)

    # 7. HTTPS usage
    is_https = 1 if parsed_url.scheme == 'https' else 0
    features.append(is_https)

    # 8. Suspicious keywords
    keywords = ['login', 'secure', 'verify', 'account', 'update', 'banking', 'confirm', 'password']
    keyword_count = sum(1 for keyword in keywords if keyword in url.lower())
    features.append(keyword_count)

    return features

if __name__ == "__main__":
    test_url = "http://paypal-login-secure.com"
    print(f"Features for {test_url}: {extract_features(test_url)}")
