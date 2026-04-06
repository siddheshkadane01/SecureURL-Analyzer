import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from .logger import Logger


def detect_bot_challenge(response, html_text):
    """
    Detects common anti-bot challenge pages (for example Cloudflare checks)
    so we don't treat challenge HTML as a real site DOM.
    """
    server_header = response.headers.get('Server', '').lower()
    html_lower = html_text.lower()

    cloudflare_markers = [
        'cf-browser-verification',
        'verify you are human',
        'performing security verification',
        'attention required',
        '/cdn-cgi/challenge-platform/',
        'cloudflare',
        'cf-ray',
    ]

    if 'cloudflare' in server_header:
        return "Cloudflare"

    for marker in cloudflare_markers:
        if marker in html_lower:
            return "Cloudflare"

    return None

def analyze_html(url):
    """
    Safely fetches and analyzes the HTML/DOM of a provided URL for common
    phishing heuristics without executing JavaScript.
    """
    Logger.security("Scraping and analyzing HTML/DOM securely...")
    
    if not url.startswith('http'):
        url = 'http://' + url

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        # Stream=True and timeout keep the request safe from indefinitely hanging 
        # or downloading massive malicious files before we can abort.
        response = requests.get(url, headers=headers, stream=True, timeout=5)
        
        # Only read up to a certain amount of data (e.g., 1MB)
        raw_html = response.iter_content(chunk_size=1024 * 1024)
        html_content = next(raw_html)
        html_text = html_content.decode('utf-8', errors='ignore')

        challenge_provider = detect_bot_challenge(response, html_text)
        if challenge_provider:
            Logger.warning("Bot verification challenge detected. Skipping DOM heuristics.")
            return {
                "status": "Bot Verification Challenge",
                "provider": challenge_provider,
                "risk_level": "Unknown"
            }
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
    except Exception as e:
        Logger.warning("Could not fetch page HTML for DOM analysis.")
        return {"status": "Unreachable"}

    results = {
        "status": "Analyzed",
        "hidden_iframes": False,
        "right_click_disabled": False,
        "suspicious_form_actions": False,
        "risk_level": "Low"
    }

    risk_score = 0

    # 1. Check for Hidden IFrames (common for drive-by downloads or credential stealing)
    iframes = soup.find_all('iframe')
    for iframe in iframes:
        style = iframe.get('style', '').lower()
        if 'display:none' in style or 'visibility:hidden' in style or 'display: none' in style:
            results["hidden_iframes"] = True
            risk_score += 1

    # 2. Check for Right-Click Disabled (phishers block inspection)
    # This can be in body tags or scripts
    body = soup.find('body')
    if body and body.get('oncontextmenu', '').lower() == "return false;":
        results["right_click_disabled"] = True
        risk_score += 1
    elif "event.button==2" in str(html_content) or "oncontextmenu" in str(html_content).lower():
        results["right_click_disabled"] = True
        risk_score += 1

    # 3. Suspicious Form Actions
    # e.g., form that points to a totally different domain
    base_domain = urlparse(url).netloc
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action', '')
        if action.startswith('http'):
            action_domain = urlparse(action).netloc
            # If the form submits data to a different domain, that is highly suspicious
            if action_domain and action_domain != base_domain:
                results["suspicious_form_actions"] = True
                risk_score += 1
                break

    # Final Risk determination from HTML
    if risk_score >= 2:
        results["risk_level"] = "High"
    elif risk_score == 1:
        results["risk_level"] = "Medium"

    return results
