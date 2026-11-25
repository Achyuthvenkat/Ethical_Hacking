from .crawler import crawl_and_extract_inputs
from .sqli_detector import test_sqli_in_url_params, test_sqli_in_forms
from .xss_detector import test_xss_in_url_params, test_xss_in_forms

def deduplicate_findings(findings_list):
    """
    Deduplicates vulnerability findings based on (module_source, affected_url, parameter)
    so each affected input is reported with its strongest evidence without redundant entries.
    """
    unique = {}
    for f in findings_list:
        key = (f['module_source'], f['affected_url'], f.get('parameter', ''))
        if key not in unique:
            unique[key] = f
        else:
            # If current finding is higher severity, replace it
            severity_weights = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFORMATIONAL': 0}
            existing_weight = severity_weights.get(unique[key]['severity'], 0)
            new_weight = severity_weights.get(f['severity'], 0)
            if new_weight > existing_weight:
                unique[key] = f
    return list(unique.values())

def run_vulnerability_detection(target_url, log_callback=None):
    """
    Module 2: Vulnerability Detection Engine.
    Coordinates crawling, harmless SQL injection boundary testing,
    and safe canary-based reflected XSS auditing with automatic deduplication.
    """
    def log(msg):
        if log_callback:
            log_callback(f"[MODULE 2 AUDIT] {msg}")

    raw_vulnerabilities = []
    
    # 1. Crawling and Input Discovery
    log("Crawling target web application for inputs, endpoints, and forms...")
    crawl_data = crawl_and_extract_inputs(target_url)
    endpoints = crawl_data.get('endpoints', [])
    forms = crawl_data.get('forms', [])
    crawled_urls = crawl_data.get('crawled_urls', [])
    
    log(f"Discovered {len(crawled_urls)} URLs, {len(endpoints)} parameter-bearing endpoints, and {len(forms)} interactive forms.")

    # Always test the root target URL itself if it has query parameters
    if target_url not in [ep['url'] for ep in endpoints]:
        endpoints.append({'url': target_url, 'method': 'GET', 'params': []})

    # 2. SQL Injection Auditing (Safe & Non-Destructive)
    log("Initiating safe SQL Injection boundary and syntax analysis...")
    for ep in endpoints:
        url = ep['url']
        log(f"Checking URL parameters for SQL error patterns: {url}")
        sqli_url_findings = test_sqli_in_url_params(url)
        raw_vulnerabilities.extend(sqli_url_findings)

    for form in forms:
        log(f"Testing form action '{form['action']}' for SQL syntax anomalies...")
        sqli_form_findings = test_sqli_in_forms(form)
        raw_vulnerabilities.extend(sqli_form_findings)

    # 3. Reflected XSS Auditing (Harmless Benign Canary Reflection)
    log("Initiating benign Reflected XSS canary analysis...")
    for ep in endpoints:
        url = ep['url']
        log(f"Testing URL parameters for unencoded reflection: {url}")
        xss_url_findings = test_xss_in_url_params(url)
        raw_vulnerabilities.extend(xss_url_findings)

    for form in forms:
        log(f"Testing form action '{form['action']}' for unencoded canary reflection...")
        xss_form_findings = test_xss_in_forms(form)
        raw_vulnerabilities.extend(xss_form_findings)

    # 4. Clean Deduplication
    vulnerabilities = deduplicate_findings(raw_vulnerabilities)
    log(f"Vulnerability detection completed. Identified {len(vulnerabilities)} unique vulnerabilities.")
    return vulnerabilities
