import socket
from urllib.parse import urlparse
from config import Config
from modules.http_client import safe_get
from .cert_checker import check_ssl_certificate
from .header_analyzer import analyze_security_headers
from .tech_detector import detect_technologies
from .port_scanner import scan_target_ports

def run_reconnaissance(target_url, log_callback=None):
    """
    Module 1: Information Gathering and Reconnaissance Engine.
    Executes DNS resolution, HTTP probe, SSL evaluation, header analysis,
    tech stack identification, and safe port profiling.
    """
    def log(msg):
        if log_callback:
            log_callback(f"[MODULE 1 RECON] {msg}")

    log(f"Starting reconnaissance on: {target_url}")
    parsed = urlparse(target_url)
    hostname = parsed.hostname or target_url
    protocol = parsed.scheme.upper()
    
    # 1. IP & DNS Resolution
    log("Resolving domain and IP address...")
    try:
        ip_address = socket.gethostbyname(hostname)
        log(f"Resolved IP Address: {ip_address}")
    except socket.gaierror:
        ip_address = "Resolution Failed"
        log("DNS resolution failed for hostname.")

    # 2. HTTP Probing
    log("Executing HTTP probe and collecting headers...")
    headers = {}
    http_status = 0
    server_banner = "Not Disclosed"
    html_body = ""
    
    try:
        response = safe_get(target_url, allow_redirects=True)
        http_status = response.status_code
        headers = dict(response.headers)
        server_banner = headers.get('Server', headers.get('server', 'Not Disclosed'))
        html_body = response.text[:50000] # First 50KB for signature analysis
        log(f"HTTP Status: {http_status} | Server Banner: {server_banner}")
    except Exception as e:
        log(f"HTTP request encountered an error: {str(e)}")

    # 3. SSL/TLS Analysis
    log("Analyzing SSL/TLS certificate validity...")
    ssl_data = check_ssl_certificate(target_url)
    log(f"SSL Valid: {ssl_data.get('ssl_valid')} | Issuer: {ssl_data.get('issuer')}")

    # 4. Security Header Analysis
    log("Evaluating HTTP security headers...")
    header_data = analyze_security_headers(headers)
    log(f"Found {len(header_data['present'])} security headers. Missing: {len(header_data['missing'])}")

    # 5. Technology Identification
    log("Fingerprinting server technologies and frameworks...")
    technologies = detect_technologies(headers, html_body)
    log(f"Technologies identified: {', '.join(technologies)}")

    # 6. Controlled Port Scan
    log("Scanning standard authorized web ports...")
    open_ports = scan_target_ports(target_url)
    log(f"Discovered {len(open_ports)} accessible service ports.")

    # Reconnaissance Summary Text
    summary = (
        f"Target {hostname} ({ip_address}) responded with HTTP {http_status}. "
        f"Server banner identifies as '{server_banner}'. "
        f"SSL/TLS certificate is {'valid' if ssl_data.get('ssl_valid') else 'insecure/unverified'}. "
        f"Identified {len(header_data['missing'])} missing security headers and {len(open_ports)} open web ports."
    )

    return {
        'target_url': target_url,
        'ip_address': ip_address,
        'protocol': protocol,
        'http_status': http_status,
        'server_banner': server_banner,
        'ssl_valid': ssl_data.get('ssl_valid', False),
        'ssl_issuer': ssl_data.get('issuer', 'N/A'),
        'ssl_expiry': ssl_data.get('expiry_date', 'N/A'),
        'ssl_cipher': ssl_data.get('cipher', 'N/A'),
        'security_headers_present': header_data.get('present', {}),
        'security_headers_missing': header_data.get('missing', []),
        'information_leaks': header_data.get('information_leaks', {}),
        'technologies': technologies,
        'open_ports': open_ports,
        'recon_summary': summary
    }
