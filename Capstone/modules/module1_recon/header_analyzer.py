def analyze_security_headers(headers):
    """
    Evaluates HTTP response headers against OWASP Recommended Security Headers.
    Returns dictionaries of present security headers and missing security headers.
    """
    # Key security headers with their recommended configurations and risk rating
    recommended_headers = {
        'Strict-Transport-Security': {
            'description': 'Enforces secure HTTPS connections and protects against protocol downgrade attacks.',
            'severity': 'MEDIUM',
            'remediation': 'Configure Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
        },
        'Content-Security-Policy': {
            'description': 'Restricts sources from which scripts, styles, and other resources can be loaded to mitigate XSS.',
            'severity': 'HIGH',
            'remediation': "Define a robust Content-Security-Policy header (e.g., default-src 'self')."
        },
        'X-Frame-Options': {
            'description': 'Protects visitors against Clickjacking attacks by restricting framing.',
            'severity': 'MEDIUM',
            'remediation': 'Set X-Frame-Options: SAMEORIGIN or DENY.'
        },
        'X-Content-Type-Options': {
            'description': 'Prevents MIME-sniffing attacks by instructing browsers to adhere to Content-Type.',
            'severity': 'LOW',
            'remediation': 'Set X-Content-Type-Options: nosniff.'
        },
        'Referrer-Policy': {
            'description': 'Controls how much referrer information is included with requests.',
            'severity': 'LOW',
            'remediation': 'Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer.'
        },
        'Permissions-Policy': {
            'description': 'Controls which browser features and APIs (camera, microphone, geolocation) can be used.',
            'severity': 'LOW',
            'remediation': 'Configure Permissions-Policy: geolocation=(), microphone=(), camera=()'
        }
    }
    
    # Headers that leak server architecture information
    info_leak_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']
    
    present = {}
    missing = []
    information_leaks = {}
    
    # Normalize header keys to lowercase for case-insensitive lookup
    normalized_headers = {k.lower(): v for k, v in headers.items()}
    
    for header_name, meta in recommended_headers.items():
        lowered = header_name.lower()
        if lowered in normalized_headers:
            present[header_name] = normalized_headers[lowered]
        else:
            missing.append({
                'header': header_name,
                'description': meta['description'],
                'severity': meta['severity'],
                'remediation': meta['remediation']
            })
            
    for leak_hdr in info_leak_headers:
        if leak_hdr in normalized_headers:
            information_leaks[leak_hdr.capitalize()] = normalized_headers[leak_hdr]
            
    return {
        'present': present,
        'missing': missing,
        'information_leaks': information_leaks
    }
