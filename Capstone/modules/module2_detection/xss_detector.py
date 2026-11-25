import random
import string
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from config import Config
from modules.http_client import safe_get, safe_post

def generate_benign_canary():
    """
    Generates a harmless, unique canary string containing safe HTML markers
    to test if user input is reflected without contextual HTML entity encoding.
    Does NOT execute any JavaScript or cause browser actions.
    """
    random_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    canary_tag = f"<span id='sec_canary_{random_id}'>canary_{random_id}</span>"
    return canary_tag, f"sec_canary_{random_id}"

def test_xss_in_url_params(url):
    """
    Tests GET parameters of a URL using harmless canary markers to detect reflected XSS.
    """
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        return findings

    for param_name in params.keys():
        canary_payload, canary_marker = generate_benign_canary()
        
        modified_params = params.copy()
        modified_params[param_name] = canary_payload
        query_str = urlencode(modified_params, doseq=True)
        probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_str, parsed.fragment))
        
        try:
            response = safe_get(probe_url)
            
            # Check if our benign HTML canary is reflected raw in the response body
            if canary_payload in response.text:
                findings.append({
                    'module_source': 'Cross-Site Scripting (XSS)',
                    'vuln_name': 'Reflected Cross-Site Scripting (XSS) Indicator',
                    'severity': 'HIGH',
                    'affected_url': url,
                    'parameter': param_name,
                    'evidence': f"The benign HTML marker '{canary_payload}' was reflected in the HTTP response unencoded.",
                    'impact': "Failure to encode user input allows an attacker to inject arbitrary client-side scripts, hijack active user sessions, steal cookies, or deface web pages.",
                    'remediation': "Apply context-aware contextual output encoding (e.g., HTML entity encoding, escaping '<', '>', '&', '\"', ''') before rendering user input in responses."
                })
        except Exception:
            continue

    return findings

def test_xss_in_forms(form):
    """
    Tests HTML form inputs using harmless canary markers to detect unencoded reflection.
    """
    findings = []
    action = form['action']
    method = form['method']
    inputs = form['inputs']
    
    for input_field in inputs:
        param_name = input_field['name']
        input_type = input_field.get('type', 'text')
        
        if input_type in ('submit', 'button', 'hidden', 'checkbox', 'radio'):
            continue
            
        canary_payload, canary_marker = generate_benign_canary()
        
        data = {}
        for field in inputs:
            data[field['name']] = canary_payload if field['name'] == param_name else field.get('value', 'test')
            
        try:
            if method == 'POST':
                resp = safe_post(action, data=data)
            else:
                resp = safe_get(action, params=data)
                
            if canary_payload in resp.text:
                findings.append({
                    'module_source': 'Cross-Site Scripting (XSS)',
                    'vuln_name': 'Form-Reflected Cross-Site Scripting (XSS)',
                    'severity': 'HIGH',
                    'affected_url': action,
                    'parameter': param_name,
                    'evidence': f"Form field '{param_name}' reflected benign HTML marker '{canary_payload}' without HTML entity encoding.",
                    'impact': "Vulnerable forms can be exploited to reflect malicious scripts, compromise browser sessions, or execute actions on behalf of authenticated users.",
                    'remediation': "Ensure strict output encoding for all echoed form fields and enforce Content-Security-Policy (CSP) headers to restrict unauthorized script execution."
                })
        except Exception:
            continue

    return findings
