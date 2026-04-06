import argparse
import sys
import json

try:
    from phishing_detector.logger import Logger
    from phishing_detector.feature_extractor import extract_features
    from phishing_detector.ml_model import PhishingModel
    from phishing_detector.ssl_checker import print_ssl_info
    from phishing_detector.reputation_checker import check_reputation
    from phishing_detector.html_scraper import analyze_html
    from phishing_detector.traditional_crypto import caesar_encrypt, save_encrypted_log
    from phishing_detector.modern_crypto import (
        generate_sha256_hash,
        aes_encrypt,
        rsa_generate_keys,
        rsa_sign_data,
        rsa_verify_signature,
    )
except ModuleNotFoundError:
    # Support direct execution: python3 phishing_detector/main.py <url>
    from logger import Logger
    from feature_extractor import extract_features
    from ml_model import PhishingModel
    from ssl_checker import print_ssl_info
    from reputation_checker import check_reputation
    from html_scraper import analyze_html
    from traditional_crypto import caesar_encrypt, save_encrypted_log
    from modern_crypto import (
        generate_sha256_hash,
        aes_encrypt,
        rsa_generate_keys,
        rsa_sign_data,
        rsa_verify_signature,
    )


def combine_weighted_risk(prediction, confidence, ssl_status, reputation, html_analysis):
    """
    Combines ML, SSL, reputation, and DOM signals into a weighted risk score.
    Bot verification challenge adds a small uncertainty penalty but does not
    force a suspicious verdict when all other checks are healthy.
    """
    risk_score = 0
    factors = []

    if prediction == "PHISHING":
        risk_score += 55
        factors.append("ML model flagged phishing")
    elif confidence < 0.75:
        risk_score += 10
        factors.append("ML confidence is low")

    if ssl_status != "Secure":
        risk_score += 20
        factors.append("SSL not secure")

    if reputation == "High Risk":
        risk_score += 35
        factors.append("Domain reputation is high risk")
    elif reputation == "Medium Risk":
        risk_score += 20
        factors.append("Domain reputation is medium risk")

    html_status = html_analysis.get("status")
    if html_status == "Analyzed":
        html_risk = html_analysis.get("risk_level", "Low")
        if html_risk == "High":
            risk_score += 25
            factors.append("DOM heuristics are high risk")
        elif html_risk == "Medium":
            risk_score += 10
            factors.append("DOM heuristics are medium risk")
    elif html_status == "Bot Verification Challenge":
        risk_score += 10
        factors.append("DOM blocked by bot verification")
    elif html_status == "Unreachable":
        risk_score += 15
        factors.append("DOM endpoint unreachable")

    if (
        html_status == "Bot Verification Challenge"
        and prediction == "LEGITIMATE"
        and ssl_status == "Secure"
        and reputation == "Low Risk"
    ):
        return 10, "LEGITIMATE", ["DOM blocked by bot verification"]

    if risk_score >= 60:
        verdict = "PHISHING"
    elif risk_score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LEGITIMATE"

    return risk_score, verdict, factors

def main():
    parser = argparse.ArgumentParser(description="Phishing Website Detection System")
    parser.add_argument("url", type=str, nargs='?', help="The URL to analyze")
    args = parser.parse_args()

    if not args.url:
        print("Please provide a URL to analyze.")
        print("Usage: python3 phishing_detector/main.py <url>")
        print("   or: python3 -m phishing_detector.main <url>")
        sys.exit(1)

    url = args.url

    Logger.info("Starting Phishing Detection System")
    
    # 1. Feature Extraction
    Logger.info("Extracting URL features...")
    features = extract_features(url)

    # 2. Machine Learning Prediction
    # Assuming generative step was already done.
    model = PhishingModel("Dataset1.csv")
    if not model.train():
        Logger.error("Failed to train ML model.")
        sys.exit(1)
    
    Logger.ml("Evaluating URL...")
    prediction, confidence = model.predict(features)
    model.print_feature_importance()

    # 3. Security Analysis
    ssl_status = print_ssl_info(url)
    reputation, rep_details = check_reputation(url)
    html_analysis = analyze_html(url)
    risk_score, final_verdict, risk_factors = combine_weighted_risk(
        prediction,
        confidence,
        ssl_status,
        reputation,
        html_analysis,
    )

    # 4. Cryptographic Routines
    # Traditional
    log_data = {
        "url": url,
        "prediction": prediction,
        "final_verdict": final_verdict,
        "weighted_risk_score": risk_score,
        "confidence": confidence,
        "ssl_status": ssl_status,
        "reputation": reputation,
        "html_risk": html_analysis.get('risk_level', 'Unknown')
    }
    log_json = json.dumps(log_data)
    encrypted_log = caesar_encrypt(log_json, shift=3)
    save_encrypted_log(encrypted_log)

    # Modern
    url_hash = generate_sha256_hash(url)
    aes_ciphertext = aes_encrypt(log_json)
    
    priv_key, pub_key = rsa_generate_keys()
    signature = rsa_sign_data(priv_key, url_hash)
    sig_verified = rsa_verify_signature(pub_key, signature, url_hash)

    # 5. Final Output
    print("\n" + "="*40)
    print(f"URL: {url}\n")
    print(f"ML Prediction: {prediction}")
    print(f"Final Verdict: {final_verdict}")
    print(f"Weighted Risk Score: {risk_score}/100")
    print(f"Confidence: {confidence}\n")
    
    print("Security Analysis:")
    print(f"SSL: {ssl_status}")
    print(f"Domain Reputation: {reputation}")
    if rep_details:
        print(f"  └ Flags: {', '.join(rep_details)}")
        
    print("\nHTML/DOM Analysis:")
    if html_analysis.get('status') == "Analyzed":
        print(f"Risk Level: {html_analysis['risk_level']}")
        print(f"Hidden Iframes: {'Yes (Suspicious)' if html_analysis['hidden_iframes'] else 'No'}")
        print(f"Right-Click Disabled: {'Yes (Suspicious)' if html_analysis['right_click_disabled'] else 'No'}")
        print(f"External Form Targets: {'Yes (Suspicious)' if html_analysis['suspicious_form_actions'] else 'No'}")
    elif html_analysis.get('status') == "Bot Verification Challenge":
        print("Status: Protected by bot verification challenge")
        print(f"Provider: {html_analysis.get('provider', 'Unknown')}")
        print("DOM Heuristics: Skipped (challenge page detected)")
    else:
        print(f"Status: {html_analysis.get('status', 'Failed to fetch')}")

    print("\nCombined Risk Factors:")
    if risk_factors:
        print(f"- {'; '.join(risk_factors)}")
    else:
        print("- No major risk factors detected")
        
    print("\nCryptographic Logs:")
    print(f"SHA256 Hash: {url_hash[:10]}...{url_hash[-10:]}")
    print(f"AES Encryption: {'Successful' if aes_ciphertext else 'Failed'}")
    print(f"Digital Signature: {'Verified' if sig_verified else 'Failed'}\n")

    if final_verdict == "PHISHING":
        print("⚠ WARNING: This website is likely a phishing site.")
    elif final_verdict == "SUSPICIOUS":
        print("⚠ CAUTION: This website needs manual review.")
    else:
        print("✅ This website appears to be legitimate.")
    print("="*40)

if __name__ == "__main__":
    main()
