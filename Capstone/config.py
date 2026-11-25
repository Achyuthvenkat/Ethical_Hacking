import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Application Configuration Settings"""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cyber-capstone-security-key-2026')
    
    # Database
    DATABASE_PATH = os.path.join(BASE_DIR, 'database', 'vulnerability_scanner.db')
    
    # Scanner Limits and Safeguards
    REQUEST_TIMEOUT = 10  # Seconds per HTTP request
    MAX_CRAWL_URLS = 15   # Max URLs to crawl per target to prevent scanning loops
    MAX_CONCURRENT_THREADS = 4
    SCAN_RATE_LIMIT_DELAY = 0.3  # Delay between requests in seconds
    
    # User-Agent for ethical auditing identification
    CUSTOM_USER_AGENT = "EthicalSecScanner/1.0 (+Academic Capstone Security Audit)"
    
    # Reports
    REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
    
    # SSRF & Target Safeguards
    # Set to True for academic demonstration on localhost (Juice Shop, DVWA, etc.)
    ALLOW_LOCAL_TESTING = True
    
    # Blocked private networks when ALLOW_LOCAL_TESTING is False
    BLOCKED_IP_RANGES = [
        '127.0.0.0/8',
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '169.254.0.0/16',  # Cloud metadata IP (AWS/GCP/Azure)
        '::1/128',
        'fc00::/7'
    ]
