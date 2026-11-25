from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, parse_qs
from config import Config
from modules.http_client import safe_get

class SimpleHTMLFormParser(HTMLParser):
    """
    Zero-dependency HTML Parser to extract forms, input fields, and links.
    Guarantees seamless execution on any standard Python environment.
    """
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.forms = []
        self.links = set()
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attr_dict = {k.lower(): v for k, v in attrs if k}
        
        # Capture links
        if tag == 'a' and 'href' in attr_dict:
            href = attr_dict['href'].strip()
            if href and not href.startswith(('javascript:', 'mailto:', '#', 'tel:')):
                full_url = urljoin(self.base_url, href)
                self.links.add(full_url)
                
        # Capture forms
        if tag == 'form':
            action = attr_dict.get('action', '')
            action_url = urljoin(self.base_url, action) if action else self.base_url
            method = attr_dict.get('method', 'get').upper()
            self.current_form = {
                'action': action_url,
                'method': method,
                'inputs': []
            }
            
        # Capture inputs inside forms
        if tag in ('input', 'textarea', 'select') and self.current_form is not None:
            name = attr_dict.get('name')
            if name:
                input_type = attr_dict.get('type', 'text').lower()
                value = attr_dict.get('value', 'test')
                self.current_form['inputs'].append({
                    'name': name,
                    'type': input_type,
                    'value': value
                })

    def handle_endtag(self, tag):
        if tag == 'form' and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None

def crawl_and_extract_inputs(target_url, max_urls=Config.MAX_CRAWL_URLS):
    """
    Safely crawls the target web application within the same domain scope,
    collecting reachable endpoints, query parameters, and interactive forms.
    """
    visited = set()
    to_visit = [target_url]
    parsed_base = urlparse(target_url)
    base_domain = parsed_base.netloc
    
    discovered_forms = []
    discovered_endpoints = []

    while to_visit and len(visited) < max_urls:
        current_url = to_visit.pop(0)
        if current_url in visited:
            continue
            
        visited.add(current_url)
        
        # Check query parameters on the current URL
        parsed_current = urlparse(current_url)
        if parsed_current.query:
            query_params = parse_qs(parsed_current.query)
            discovered_endpoints.append({
                'url': current_url,
                'method': 'GET',
                'params': list(query_params.keys())
            })
            
        try:
            resp = safe_get(current_url, allow_redirects=True)
            
            # Check content
            content_type = resp.headers.get('Content-Type', '').lower()
            if 'text/html' not in content_type and '<html' not in resp.text.lower():
                continue
                
            parser = SimpleHTMLFormParser(current_url)
            parser.feed(resp.text)
            
            # Collect forms
            for form in parser.forms:
                discovered_forms.append(form)
                
            # Filter links to stay within same domain
            for link in parser.links:
                parsed_link = urlparse(link)
                if parsed_link.netloc == base_domain and link not in visited and link not in to_visit:
                    to_visit.append(link)
                    
        except Exception:
            continue

    return {
        'endpoints': discovered_endpoints,
        'forms': discovered_forms,
        'crawled_urls': list(visited)
    }
