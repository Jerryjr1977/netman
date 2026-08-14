#auth_engine
import socket
import ssl
import base64
import urllib.request
import urllib.error
import urllib.parse
import json
import re
import queue
import logging

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

result_queue = queue.Queue()
is_running = False

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _http_get(url: str, headers: dict = None, timeout: int = 8) -> tuple:
    """Perform a GET, return (status_code, response_headers, body_text)."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), dict(resp.headers), resp.read().decode('utf-8', errors='ignore')
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode('utf-8', errors='ignore')
    except Exception as e:
        raise


def _http_post(url: str, data: bytes, headers: dict = None, timeout: int = 8) -> tuple:
    """Perform a POST."""
    req = urllib.request.Request(url, data=data, headers=headers or {}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), dict(resp.headers), resp.read().decode('utf-8', errors='ignore')
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode('utf-8', errors='ignore')

# ---------------------------------------------------------------------------
# Basic Auth
# ---------------------------------------------------------------------------

def test_basic_auth(base_url: str, usernames: list, passwords: list):
    """Try Basic Auth credential combinations."""
    result_queue.put(("STATUS", f"Testing Basic Auth on {base_url}"))
    for user in usernames:
        for pwd in passwords:
            if not is_running:
                return
            credentials = base64.b64encode(f"{user}:{pwd}".encode()).decode()
            headers = {'Authorization': f'Basic {credentials}'}
            try:
                status, _, _ = _http_get(base_url, headers=headers)
                if status == 200:
                    result_queue.put(("VULN", f"Basic Auth success: {user}:{pwd}"))
                    logger.info(f"Basic Auth found: {user}:{pwd}")
                elif status == 401:
                    result_queue.put(("FAILED", f"Rejected: {user}:{pwd}"))
                else:
                    result_queue.put(("INFO", f"HTTP {status}: {user}:{pwd}"))
            except Exception as e:
                result_queue.put(("ERROR", f"Request failed: {e}"))

# ---------------------------------------------------------------------------
# Session Security
# ---------------------------------------------------------------------------

def test_session_security(base_url: str):
    """Check session cookie security attributes."""
    result_queue.put(("STATUS", f"Checking session security on {base_url}"))
    try:
        status, headers, body = _http_get(base_url)
        cookie_header = headers.get('Set-Cookie', '')
        if not cookie_header:
            result_queue.put(("INFO", "No Set-Cookie header found"))
            return

        for cookie in cookie_header.split('\n'):
            cookie_lower = cookie.lower()
            if 'session' in cookie_lower or 'sess' in cookie_lower or 'auth' in cookie_lower:
                result_queue.put(("INFO", f"Session cookie: {cookie[:80]}"))
                if 'httponly' not in cookie_lower:
                    result_queue.put(("VULN", "Missing HttpOnly flag — cookie accessible via JS"))
                else:
                    result_queue.put(("OK", "HttpOnly flag present"))
                if 'secure' not in cookie_lower:
                    result_queue.put(("VULN", "Missing Secure flag — cookie sent over HTTP"))
                else:
                    result_queue.put(("OK", "Secure flag present"))
                if 'samesite' not in cookie_lower:
                    result_queue.put(("WARN", "Missing SameSite — potential CSRF risk"))
                else:
                    result_queue.put(("OK", "SameSite attribute present"))
    except Exception as e:
        result_queue.put(("ERROR", f"Session check failed: {e}"))

# ---------------------------------------------------------------------------
# JWT Analysis
# ---------------------------------------------------------------------------

def analyse_jwt(token: str):
    """Decode JWT (no signature verification) and flag issues."""
    result_queue.put(("STATUS", "Analysing JWT..."))
    parts = token.strip().split('.')
    if len(parts) != 3:
        result_queue.put(("ERROR", "Invalid JWT format (expected 3 parts)"))
        return

    def _b64_decode(s):
        s += '=' * (4 - len(s) % 4)
        return json.loads(base64.urlsafe_b64decode(s).decode('utf-8', errors='ignore'))

    try:
        header = _b64_decode(parts[0])
        payload = _b64_decode(parts[1])

        alg = header.get('alg', 'unknown')
        result_queue.put(("INFO", f"Algorithm: {alg}"))

        if alg.upper() == 'NONE':
            result_queue.put(("VULN", "Algorithm is 'none' — signature bypass possible!"))
        elif alg.upper() in ('HS256', 'HS384', 'HS512'):
            result_queue.put(("INFO", "HMAC algorithm — ensure strong secret"))
        elif alg.upper() in ('RS256', 'RS384', 'RS512'):
            result_queue.put(("OK", "RSA algorithm in use"))

        import datetime
        exp = payload.get('exp')
        if exp:
            exp_dt = datetime.datetime.utcfromtimestamp(exp)
            if exp_dt < datetime.datetime.utcnow():
                result_queue.put(("VULN", f"Token EXPIRED at {exp_dt}"))
            else:
                result_queue.put(("OK", f"Token valid until {exp_dt}"))
        else:
            result_queue.put(("WARN", "No expiry (exp) claim — token never expires"))

        for claim in ['iss', 'sub', 'aud']:
            val = payload.get(claim, '(not set)')
            result_queue.put(("INFO", f"Claim '{claim}': {val}"))

        sensitive_keys = ['password', 'secret', 'key', 'token', 'credit', 'ssn']
        for k, v in payload.items():
            if any(s in k.lower() for s in sensitive_keys):
                result_queue.put(("VULN", f"Sensitive data in payload: '{k}'"))

    except Exception as e:
        result_queue.put(("ERROR", f"JWT decode failed: {e}"))

# ---------------------------------------------------------------------------
# CSRF Check
# ---------------------------------------------------------------------------

def test_csrf_protection(base_url: str):
    """Check for CSRF protection mechanisms."""
    result_queue.put(("STATUS", f"CSRF check: {base_url}"))
    try:
        status, headers, body = _http_get(base_url)
        csp = headers.get('Content-Security-Policy', '')
        cors = headers.get('Access-Control-Allow-Origin', '')
        samesite_present = 'samesite' in body.lower() or 'csrf' in body.lower()
        token_present = bool(re.search(r'csrf|_token|xsrf', body, re.IGNORECASE))

        if token_present:
            result_queue.put(("OK", "CSRF token found in page"))
        else:
            result_queue.put(("WARN", "No CSRF token detected in page"))

        if cors == '*':
            result_queue.put(("VULN", "CORS wildcard (*) — any origin allowed"))
        elif cors:
            result_queue.put(("INFO", f"CORS origin: {cors}"))
        else:
            result_queue.put(("INFO", "No CORS header"))

        if csp:
            result_queue.put(("OK", "Content-Security-Policy present"))
        else:
            result_queue.put(("WARN", "No Content-Security-Policy header"))

    except Exception as e:
        result_queue.put(("ERROR", f"CSRF check failed: {e}"))

# ---------------------------------------------------------------------------
# Main dispatcher
# ---------------------------------------------------------------------------

def run_auth_scan(mode: str, target: str, extra1: str = "", extra2: str = ""):
    """Dispatcher for auth scan modes."""
    global is_running
    is_running = True

    try:
        if mode == "basic_auth":
            usernames = [u.strip() for u in extra1.split(',') if u.strip()] or ['admin', 'root', 'user']
            passwords = [p.strip() for p in extra2.split(',') if p.strip()] or ['admin', 'password', '123456']
            test_basic_auth(target, usernames, passwords)
        elif mode == "session":
            test_session_security(target)
        elif mode == "jwt":
            analyse_jwt(target)
        elif mode == "csrf":
            test_csrf_protection(target)
    except Exception as e:
        result_queue.put(("ERROR", f"Scan error: {e}"))
        logger.error(f"Auth scan error: {e}")

    if is_running:
        result_queue.put(("DONE", "Auth scan complete."))
    else:
        result_queue.put(("DONE", "Scan aborted."))
    is_running = False


def stop_auth_scan():
    global is_running
    is_running = False
