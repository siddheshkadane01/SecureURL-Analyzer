import argparse
import sys
import json
from phishing_detector.logger import Logger
from phishing_detector.feature_extractor import extract_features
from phishing_detector.ml_model import PhishingModel
from phishing_detector.ssl_checker import print_ssl_info
from phishing_detector.reputation_checker import check_reputation
from phishing_detector.html_scraper import analyze_html
from phishing_detector.traditional_crypto import caesar_encrypt, save_encrypted_log
from phishing_detector.modern_crypto import generate_sha256_hash, aes_encrypt, rsa_generate_keys, rsa_sign_data, rsa_verify_signature

def main():
    parser = argparse.ArgumentParser(description="Phishing Website Detection System")
    parser.add_argument("url", type=str, nargs='?', help="The URL to analyze")
    args = parser.parse_args()

    if not args.url:
        print("Please provide a URL to analyze.")
        print("Usage: python -m phishing_detector.main <url>")
        sys.exit(1)

    url = args.url

    Logger.info("Starting Phishing Detection System")
    
    # 1. Feature Extraction
    Logger.info("Extracting URL features...")
    features = extract_features(url)

    # 2. Machine Learning Prediction
    # Assuming generative step was already done.
    model = PhishingModel("dataset.csv")
    if not model.train():
        Logger.error("Failed to train ML model. Please run generate_dataset.py first.")
        sys.exit(1)
    
    Logger.ml("Evaluating URL...")
    prediction, confidence = model.predict(features)
    model.print_feature_importance()

    # 3. Security Analysis
    ssl_status = print_ssl_info(url)
    reputation, rep_details = check_reputation(url)
    html_analysis = analyze_html(url)

    # 4. Cryptographic Routines
    # Traditional
    log_data = {
        "url": url,
        "prediction": prediction,
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
    else:
        print(f"Status: {html_analysis.get('status', 'Failed to fetch')}")
        
    print("\nCryptographic Logs:")
    print(f"SHA256 Hash: {url_hash[:10]}...{url_hash[-10:]}")
    print(f"AES Encryption: {'Successful' if aes_ciphertext else 'Failed'}")
    print(f"Digital Signature: {'Verified' if sig_verified else 'Failed'}\n")

    if prediction == "PHISHING":
        print("⚠ WARNING: This website is likely a phishing site.")
    else:
        print("✅ This website appears to be legitimate.")
    print("="*40)

if __name__ == "__main__":
    main()
