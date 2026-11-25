import requests
import urllib3
from config import Config

# Suppress insecure request warnings for local test labs with self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_SESSION = None

def get_http_session():
    """
    Returns a configured requests.Session instance.
    Disables environment proxy interception for reliable local testing labs (Juice Shop, DVWA).
    """
    global _SESSION
    if _SESSION is None:
        _SESSION = requests.Session()
        _SESSION.trust_env = False
        _SESSION.headers.update({'User-Agent': Config.CUSTOM_USER_AGENT})
    return _SESSION

def safe_get(url, **kwargs):
    """Executes a safe GET request with default timeout and SSL verification settings."""
    session = get_http_session()
    kwargs.setdefault('timeout', Config.REQUEST_TIMEOUT)
    kwargs.setdefault('verify', False)
    return session.get(url, **kwargs)

def safe_post(url, **kwargs):
    """Executes a safe POST request with default timeout and SSL verification settings."""
    session = get_http_session()
    kwargs.setdefault('timeout', Config.REQUEST_TIMEOUT)
    kwargs.setdefault('verify', False)
    return session.post(url, **kwargs)
