import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

def check_ssl_certificate(target_url, timeout=5):
    """
    Safely inspects the SSL/TLS certificate of the target domain.
    Returns certificate details, validity, issuer, and days until expiration.
    """
    parsed = urlparse(target_url)
    hostname = parsed.hostname or target_url
    port = parsed.port or (443 if parsed.scheme == 'https' else 443)
    
    result = {
        'ssl_valid': False,
        'issuer': 'N/A',
        'expiry_date': 'N/A',
        'days_remaining': 0,
        'cipher': 'N/A',
        'tls_version': 'N/A',
        'error': None
    }
    
    # If the target is HTTP, return informational status
    if parsed.scheme == 'http' and port == 80:
        result['error'] = 'Target uses plain HTTP. No SSL/TLS certificate deployed.'
        return result
        
    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                # Extract Issuer
                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                issuer_common_name = issuer_dict.get('commonName', issuer_dict.get('organizationName', 'Unknown Issuer'))
                
                # Extract Expiry Date
                not_after_str = cert.get('notAfter')
                expiry_dt = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry_dt - datetime.utcnow()).days
                
                result['ssl_valid'] = days_left > 0
                result['issuer'] = issuer_common_name
                result['expiry_date'] = expiry_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                result['days_remaining'] = days_left
                result['cipher'] = f"{cipher[0]} ({cipher[1]} bits)" if cipher else "Unknown"
                result['tls_version'] = version or "Unknown"
                
    except ssl.SSLCertVerificationError as e:
        result['ssl_valid'] = False
        result['error'] = f"SSL Certificate Verification Failed: {str(e)}"
    except socket.timeout:
        result['error'] = f"Connection timed out while connecting to {hostname}:{port}"
    except Exception as e:
        result['error'] = f"SSL Handshake Error: {str(e)}"
        
    return result
