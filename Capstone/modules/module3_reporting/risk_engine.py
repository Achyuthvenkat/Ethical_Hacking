def calculate_risk_and_findings(recon_data, raw_vulns):
    """
    Module 3: Aggregates findings across Module 1 and Module 2,
    creates structured vulnerability records for missing security headers,
    and calculates an overall website security risk score (0.0 to 10.0).
    """
    consolidated_vulns = list(raw_vulns)
    
    # 1. Transform missing security headers into structured findings
    for missing_header in recon_data.get('security_headers_missing', []):
        consolidated_vulns.append({
            'module_source': 'Security Header Audit',
            'vuln_name': f"Missing {missing_header['header']} Header",
            'severity': missing_header.get('severity', 'LOW'),
            'affected_url': recon_data.get('target_url', 'N/A'),
            'parameter': 'HTTP Response Headers',
            'evidence': f"Header '{missing_header['header']}' was absent in server responses.",
            'impact': missing_header.get('description', 'Potential exposure to client-side attacks.'),
            'remediation': missing_header.get('remediation', 'Configure the appropriate HTTP header.')
        })

    # 2. Check for Plain HTTP / Insecure SSL
    if not recon_data.get('ssl_valid', False):
        consolidated_vulns.append({
            'module_source': 'Transport Layer Security',
            'vuln_name': 'Insecure Transport / Missing Valid SSL Certificate',
            'severity': 'MEDIUM',
            'affected_url': recon_data.get('target_url', 'N/A'),
            'parameter': 'Transport Layer',
            'evidence': f"Target protocol: {recon_data.get('protocol')}. SSL Validity: Insecure/Unverified.",
            'impact': 'Communications between client and server are unencrypted or unverified, exposing data to eavesdropping or Man-in-the-Middle (MitM) interception.',
            'remediation': 'Install a valid TLS/SSL certificate signed by a recognized Certificate Authority (CA) and enforce HTTPS via HSTS.'
        })

    # 3. Check for Server Information Leakage
    server_banner = recon_data.get('server_banner', '')
    if server_banner and server_banner not in ('Not Disclosed', 'N/A'):
        consolidated_vulns.append({
            'module_source': 'Information Disclosure',
            'vuln_name': 'Server Version Banner Disclosure',
            'severity': 'INFORMATIONAL',
            'affected_url': recon_data.get('target_url', 'N/A'),
            'parameter': 'Server Header',
            'evidence': f"Server returned banner: '{server_banner}'.",
            'impact': 'Disclosing exact software banners helps attackers target known Common Vulnerabilities and Exposures (CVEs) specific to that version.',
            'remediation': "Disable or mask detailed version tokens in server configuration (e.g., ServerTokens Prod in Apache, server_tokens off in Nginx)."
        })

    # 4. Count Severities
    critical_count = sum(1 for v in consolidated_vulns if v['severity'].upper() == 'CRITICAL')
    high_count = sum(1 for v in consolidated_vulns if v['severity'].upper() == 'HIGH')
    medium_count = sum(1 for v in consolidated_vulns if v['severity'].upper() == 'MEDIUM')
    low_count = sum(1 for v in consolidated_vulns if v['severity'].upper() == 'LOW')
    info_count = sum(1 for v in consolidated_vulns if v['severity'].upper() == 'INFORMATIONAL')
    total_findings = len(consolidated_vulns)

    # 5. Calculate Weighted Risk Score (0.0 to 10.0 scale)
    raw_score = (
        (critical_count * 3.5) +
        (high_count * 2.0) +
        (medium_count * 1.0) +
        (low_count * 0.4) +
        (info_count * 0.1)
    )
    risk_score = round(min(10.0, raw_score), 1)

    # 6. Overall Security Assessment Rating
    if risk_score >= 8.0:
        risk_rating = "CRITICAL RISK"
        rating_color = "#dc3545"
    elif risk_score >= 5.0:
        risk_rating = "HIGH RISK"
        rating_color = "#fd7e14"
    elif risk_score >= 2.5:
        risk_rating = "MODERATE RISK"
        rating_color = "#ffc107"
    else:
        risk_rating = "LOW RISK / SECURE"
        rating_color = "#198754"

    return {
        'consolidated_vulns': consolidated_vulns,
        'total_findings': total_findings,
        'critical_count': critical_count,
        'high_count': high_count,
        'medium_count': medium_count,
        'low_count': low_count,
        'info_count': info_count,
        'risk_score': risk_score,
        'risk_rating': risk_rating,
        'rating_color': rating_color
    }
