import re

def detect_technologies(headers, html_body=""):
    """
    Identifies web technologies, web servers, frameworks, and programming languages
    based on HTTP response headers, cookies, and DOM signatures.
    """
    technologies = set()
    normalized_headers = {k.lower(): v for k, v in headers.items()}
    
    # 1. Server Header Identification
    server = normalized_headers.get('server', '')
    if server:
        technologies.add(f"Web Server: {server}")
        
    # 2. X-Powered-By Header Identification
    powered_by = normalized_headers.get('x-powered-by', '')
    if powered_by:
        technologies.add(f"Framework/Runtime: {powered_by}")
        
    # 3. Cookie signatures
    cookies = normalized_headers.get('set-cookie', '')
    if 'PHPSESSID' in cookies:
        technologies.add("Backend: PHP")
    if 'JSESSIONID' in cookies:
        technologies.add("Backend: Java (Servlet/JSP)")
    if 'ASPSESSIONID' in cookies or 'ASP.NET_SessionId' in cookies:
        technologies.add("Backend: ASP.NET")
    if 'csrftoken' in cookies or 'sessionid' in cookies:
        technologies.add("Framework: Django (Potential)")
        
    # 4. DOM Pattern Matchers
    if html_body:
        lower_body = html_body.lower()
        
        # CMS
        if 'wp-content' in lower_body or 'wp-includes' in lower_body:
            technologies.add("CMS: WordPress")
        if 'drupal.js' in lower_body or 'drupal' in lower_body:
            technologies.add("CMS: Drupal")
        if 'joomla' in lower_body:
            technologies.add("CMS: Joomla")
            
        # Frontend Libraries
        if 'react' in lower_body or 'react-dom' in lower_body:
            technologies.add("Frontend: React.js")
        if 'vue' in lower_body or 'vue.js' in lower_body:
            technologies.add("Frontend: Vue.js")
        if 'bootstrap' in lower_body:
            technologies.add("UI Library: Bootstrap")
        if 'jquery' in lower_body:
            technologies.add("JavaScript Library: jQuery")
            
        # Look for meta generator tag
        gen_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', html_body, re.I)
        if gen_match:
            technologies.add(f"Generator: {gen_match.group(1).strip()}")
            
    if not technologies:
        technologies.add("Standard Modern Web Stack (Signatures hidden/obscured)")
        
    return sorted(list(technologies))
