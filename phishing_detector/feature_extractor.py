import re
import math
from urllib.parse import urlparse

def extract_features(url):
    """
    Extracts 12 advanced features from a URL matching Dataset1.csv columns.
    Returns: A list of numerical features.
    """
    if not url.startswith(('http://', 'https://')):
        url_with_scheme = 'http://' + url
    else:
        url_with_scheme = url

    parsed = urlparse(url_with_scheme)
    domain = parsed.netloc
    
    def calculate_entropy(s):
        if not s:
            return 0
        p, lns = [s.count(c)/len(s) for c in set(s)], len(s)
        return -sum(c*math.log2(c) for c in p)

    features = []

    # 1. url_length
    features.append(len(url))

    # 2. entropy_of_domain
    features.append(calculate_entropy(domain))

    # 3. average_subdomain_length
    subdomains = domain.split('.')
    if len(subdomains) > 0:
        avg_sub = sum(len(sub) for sub in subdomains) / len(subdomains)
    else:
        avg_sub = 0
    features.append(avg_sub)

    # 4. domain_length
    features.append(len(domain))

    # 5. entropy_of_url
    features.append(calculate_entropy(url))

    # 6. number_of_subdomains
    features.append(max(0, len(subdomains) - 1))

    # 7. number_of_digits_in_domain
    features.append(sum(c.isdigit() for c in domain))

    # 8. number_of_dots_in_url
    features.append(url.count('.'))

    # 9. number_of_digits_in_url
    features.append(sum(c.isdigit() for c in url))

    # 10. number_of_slash_in_url
    features.append(url.count('/'))

    # 11. number_of_special_char_in_url
    features.append(sum(not c.isalnum() for c in url))

    # 12. path_length
    features.append(len(parsed.path))

    return features

if __name__ == "__main__":
    test_url = "http://paypal-login-secure.com"
    print(f"Features for {test_url}: {extract_features(test_url)}")
