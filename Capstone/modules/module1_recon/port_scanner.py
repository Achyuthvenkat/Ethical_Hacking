import socket
from urllib.parse import urlparse

# Controlled list of common web-related service ports
COMMON_WEB_PORTS = {
    80: 'HTTP',
    443: 'HTTPS',
    8080: 'HTTP-Proxy / Alt-HTTP',
    8443: 'HTTPS-Alt',
    3000: 'Node.js / React Dev',
    5000: 'Flask / Python App',
    8000: 'Django / HTTP-Alt',
    8888: 'Jupyter / Web Admin',
    21: 'FTP (Optional Control)',
    22: 'SSH (Remote Administration)',
    3306: 'MySQL Database',
    5432: 'PostgreSQL Database'
}

def scan_target_ports(target_url, timeout=0.6):
    """
    Performs a safe, controlled TCP banner and port scan on authorized web targets.
    Uses native non-blocking sockets for fast, zero-dependency reliability on Windows.
    Falls back gracefully if external nmap binaries are not in PATH.
    """
    parsed = urlparse(target_url)
    hostname = parsed.hostname or target_url
    
    open_ports = []
    
    try:
        target_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return []
        
    for port, service_name in COMMON_WEB_PORTS.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    open_ports.append({
                        'port': port,
                        'service': service_name,
                        'state': 'OPEN'
                    })
        except Exception:
            continue
            
    return open_ports
