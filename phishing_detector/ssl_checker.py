import ssl
import socket
import certifi
from datetime import datetime
from urllib.parse import urlparse
from .logger import Logger

def check_ssl(url):
    """
    Connects to the given URL and retrieves SSL certificate information.
    """
    if not url.startswith('http'):
        url = 'https://' + url

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    if not hostname:
        return {"status": "Invalid URL"}

    context = ssl.create_default_context(cafile=certifi.where())
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        # Wrap socket
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                
                # To read structured dict info, we need a verified wrap
                cert_dict = ssl.get_server_certificate((hostname, 443), timeout=3)

                return extract_cert_info(cert_dict)
    except socket.timeout:
        Logger.warning("Connection timed out. Website might not use HTTPS or is unreachable.")
        return {"status": "Timeout"}
    except (ssl.SSLError, ConnectionRefusedError, Exception) as e:
        Logger.warning(f"Website does not use a valid HTTPS or connection failed.")
        return {"status": "Not Secure"}

def extract_cert_info(cert_info_dict):
    """
    Parses and formats dictionary based SSL information via get_server_certificate
    """
    if not cert_info_dict:
        return {"status": "Not Secure"}

    # Basic dictionary parsing (issuer, expiration date)
    issuer = dict(x[0] for x in cert_info_dict.get('issuer', []))
    issuer_name = issuer.get('organizationName', 'Unknown')
    
    # Python uses this specific string formatting for SSL dates
    expire_str = cert_info_dict.get('notAfter')
    
    try:
        if expire_str:
            # Example format: "Aug 12 12:00:00 2026 GMT"
            expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            expire_formatted = expire_date.strftime("%Y-%m-%d")
        else:
            expire_formatted = "Unknown"
    except Exception:
        expire_formatted = expire_str
        
    return {
        "status": "Secure",
        "issuer": issuer_name,
        "expiration_date": expire_formatted
    }

def print_ssl_info(url):
    Logger.security("Checking SSL certificate...")

    parsed_url = urlparse(url if url.startswith('http') else 'https://' + url)
    hostname = parsed_url.hostname
    
    try:
        context = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                issuer = dict(x[0] for x in cert.get('issuer', []))
                issuer_name = issuer.get('organizationName', 'Unknown')
                
                expire_str = cert.get('notAfter')
                try:
                    expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                    expire_formatted = expire_date.strftime("%Y-%m-%d")
                except:
                    expire_formatted = expire_str
                    
                Logger.security("SSL Certificate Found")
                print(f"Issuer: {issuer_name}")
                print(f"Expiration Date: {expire_formatted}")
                return "Secure"

    except Exception:
        Logger.warning("Website does not use HTTPS or cert is invalid.")
        return "Not Secure"