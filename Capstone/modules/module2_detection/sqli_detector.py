import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from config import Config
from modules.http_client import safe_get, safe_post

# Known database error regex signatures (MySQL, PostgreSQL, Oracle, SQLite, MSSQL)
DBMS_ERROR_PATTERNS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning: mysql_",
    r"check the manual that corresponds to your (mysql|mariadb) server version",
    r"mysql_fetch_array\(\)",
    # PostgreSQL
    r"postgresql.*?error",
    r"warning:\s+pg_.*?\(",
    r"valid postgresql result",
    r"npgsql\.",
    r"pg_query\(\)",
    # SQLite
    r"sqlite3::sqlexception",
    r"sqlite_error",
    r"unrecognized token:",
    r"operationalerror: near",
    # Oracle
    r"ora-[0-9]{5}",
    r"oracle error",
    r"quoted string not properly terminated",
    # Microsoft SQL Server
    r"driver.*?sql[\-\_\ ]*server",
    r"ole db.*?sql server",
    r"unclosed quotation mark after the character string",
    r"microsoft ole db provider for sql server"
]

# Safe, non-destructive syntax boundary probes
BENIGN_SQL_PROBES = [
    "'",
    "''",
    "\"",
    "\"\"",
    "1' OR '1'='2",
    "1 AND 1=2"
]

def test_sqli_in_url_params(url):
    """
    Tests GET parameters of a URL using safe boundary probes to detect unhandled SQL syntax errors.
    """
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        return findings

    for param_name in params.keys():
        for probe in BENIGN_SQL_PROBES:
            modified_params = params.copy()
            modified_params[param_name] = probe
            query_str = urlencode(modified_params, doseq=True)
            probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_str, parsed.fragment))
            
            try:
                response = safe_get(probe_url)
                matched_error = check_db_errors(response.text)
                if matched_error:
                    findings.append({
                        'module_source': 'SQL Injection',
                        'vuln_name': 'Error-Based SQL Injection Indicator',
                        'severity': 'HIGH',
                        'affected_url': url,
                        'parameter': param_name,
                        'evidence': f"Target returned database syntax error when injected with safe probe '{probe}'. Pattern match: '{matched_error}'.",
                        'impact': "An attacker may manipulate backend SQL queries, bypass authentication, or access unauthorized database tables if inputs are not properly parameterized.",
                        'remediation': "Use Parameterized Queries (Prepared Statements) with bound parameters or Object-Relational Mapping (ORM) frameworks instead of string concatenation."
                    })
                    break
            except Exception:
                continue

    return findings

def test_sqli_in_forms(form):
    """
    Tests HTML form inputs using safe boundary probes to detect unhandled SQL syntax errors.
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
            
        for probe in BENIGN_SQL_PROBES:
            data = {}
            for field in inputs:
                data[field['name']] = probe if field['name'] == param_name else field.get('value', '1')
                
            try:
                if method == 'POST':
                    resp = safe_post(action, data=data)
                else:
                    resp = safe_get(action, params=data)
                    
                matched_error = check_db_errors(resp.text)
                if matched_error:
                    findings.append({
                        'module_source': 'SQL Injection',
                        'vuln_name': 'Form-Based SQL Injection Indicator',
                        'severity': 'CRITICAL',
                        'affected_url': action,
                        'parameter': param_name,
                        'evidence': f"Form input '{param_name}' triggered a database syntax error on safe probe '{probe}'. Snippet: '{matched_error}'.",
                        'impact': "Vulnerable form inputs allow malicious SQL control, potentially leading to unauthorized data modification or administrative account bypass.",
                        'remediation': "Implement Prepared Statements with parameterized inputs. Ensure all database queries strictly separate query structure from user data."
                    })
                    break
            except Exception:
                continue

    return findings

def check_db_errors(html_content):
    """
    Scans HTML content for known database error strings using regular expressions.
    """
    for pattern in DBMS_ERROR_PATTERNS:
        match = re.search(pattern, html_content, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 20)
            end = min(len(html_content), match.end() + 40)
            return html_content[start:end].strip()
    return None
