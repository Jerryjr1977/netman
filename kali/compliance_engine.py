#compliance_engine
import urllib.request
import urllib.error
import re
import queue
import logging

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

result_queue = queue.Queue()
is_running = False

# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _get(url: str, headers: dict = None, timeout: int = 10) -> tuple:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), dict(resp.headers), resp.read().decode('utf-8', errors='ignore')
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode('utf-8', errors='ignore')


def _post(url: str, data: bytes, headers: dict = None, timeout: int = 10) -> tuple:
    req = urllib.request.Request(url, data=data, headers=headers or {}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), dict(resp.headers), resp.read().decode('utf-8', errors='ignore')
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode('utf-8', errors='ignore')

# ---------------------------------------------------------------------------
# A1 – Injection
# ---------------------------------------------------------------------------

INJECTION_PROBES = ["' OR '1'='1", "\" OR \"1\"=\"1", "1; DROP TABLE users--", "<script>alert(1)</script>"]

def check_injection(base_url: str):
    result_queue.put(("CHECK", "A01 – Injection"))
    params = ['id', 'q', 'search', 'user', 'username', 'input']
    found = False
    for param in params:
        for probe in INJECTION_PROBES:
            if not is_running:
                return
            url = f"{base_url}?{param}={urllib.parse.quote(probe)}"
            try:
                status, _, body = _get(url)
                errors = ['sql syntax', 'mysql', 'sqlite', 'ora-', 'odbc', 'pg_query', 'unclosed']
                if any(e in body.lower() for e in errors):
                    result_queue.put(("FAIL", f"SQL error on ?{param}= — possible injection"))
                    found = True
                if '<script>alert(1)</script>' in body:
                    result_queue.put(("FAIL", f"XSS reflection on ?{param}="))
                    found = True
            except Exception as e:
                result_queue.put(("ERROR", f"Probe failed: {e}"))
    if not found:
        result_queue.put(("PASS", "No obvious injection errors detected"))


import urllib.parse

# ---------------------------------------------------------------------------
# A2 – Broken Auth / Credential exposure
# ---------------------------------------------------------------------------

def check_broken_auth(base_url: str):
    result_queue.put(("CHECK", "A07 – Broken Auth"))
    try:
        status, headers, body = _get(base_url)
        cookie = headers.get('Set-Cookie', '')
        if cookie:
            if 'secure' not in cookie.lower():
                result_queue.put(("FAIL", "Cookie missing Secure flag"))
            else:
                result_queue.put(("PASS", "Cookie has Secure flag"))
            if 'httponly' not in cookie.lower():
                result_queue.put(("FAIL", "Cookie missing HttpOnly flag"))
            else:
                result_queue.put(("PASS", "Cookie has HttpOnly flag"))
            if 'samesite' not in cookie.lower():
                result_queue.put(("WARN", "Cookie missing SameSite attribute"))
            else:
                result_queue.put(("PASS", "Cookie has SameSite attribute"))
        else:
            result_queue.put(("INFO", "No Set-Cookie header found"))

        login_endpoints = ['/login', '/signin', '/admin', '/wp-login.php']
        for ep in login_endpoints:
            url = base_url.rstrip('/') + ep
            try:
                s, h, b = _get(url)
                if s == 200:
                    result_queue.put(("WARN", f"Login page accessible: {url}"))
                elif s == 403:
                    result_queue.put(("PASS", f"Login page protected (403): {url}"))
            except Exception:
                pass

    except Exception as e:
        result_queue.put(("ERROR", f"Auth check failed: {e}"))

# ---------------------------------------------------------------------------
# A3 – Sensitive Data Exposure
# ---------------------------------------------------------------------------

SENSITIVE_PATTERNS = [
    (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', "Email address in response"),
    (r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b', "Possible credit card number"),
    (r'(?i)(api[_\-]?key|secret|password|passwd|token)\s*[:=]\s*\S+', "Credential in response"),
    (r'(?i)BEGIN (RSA|EC|PRIVATE) KEY', "Private key material in response"),
]

def check_sensitive_data(base_url: str):
    result_queue.put(("CHECK", "A02 – Sensitive Data Exposure"))
    try:
        status, headers, body = _get(base_url)
        server = headers.get('Server', '')
        x_powered = headers.get('X-Powered-By', '')
        if server:
            result_queue.put(("WARN", f"Server header reveals: {server}"))
        else:
            result_queue.put(("PASS", "Server header absent"))
        if x_powered:
            result_queue.put(("WARN", f"X-Powered-By reveals: {x_powered}"))

        for pattern, label in SENSITIVE_PATTERNS:
            if re.search(pattern, body):
                result_queue.put(("FAIL", label))

        if 'https' not in base_url:
            result_queue.put(("WARN", "Target using HTTP — no transport encryption"))
        else:
            result_queue.put(("PASS", "HTTPS transport in use"))
    except Exception as e:
        result_queue.put(("ERROR", f"Sensitive data check failed: {e}"))

# ---------------------------------------------------------------------------
# A5 – Security Misconfiguration (headers)
# ---------------------------------------------------------------------------

SECURITY_HEADERS = {
    'Strict-Transport-Security': 'HSTS missing — HTTPS not enforced',
    'X-Content-Type-Options': 'MIME sniffing not prevented (nosniff missing)',
    'X-Frame-Options': 'Clickjacking protection absent',
    'Content-Security-Policy': 'No Content-Security-Policy',
    'Referrer-Policy': 'No Referrer-Policy',
    'Permissions-Policy': 'No Permissions-Policy',
}

def check_security_headers(base_url: str):
    result_queue.put(("CHECK", "A05 – Security Misconfiguration (Headers)"))
    try:
        _, headers, _ = _get(base_url)
        for header, fail_msg in SECURITY_HEADERS.items():
            if header in headers:
                result_queue.put(("PASS", f"{header} present"))
            else:
                result_queue.put(("FAIL", fail_msg))
    except Exception as e:
        result_queue.put(("ERROR", f"Header check failed: {e}"))

# ---------------------------------------------------------------------------
# A6 – Vulnerable / Exposed Files
# ---------------------------------------------------------------------------

KNOWN_PATHS = [
    '/.git/config', '/.env', '/config.php', '/wp-config.php',
    '/robots.txt', '/sitemap.xml', '/backup.zip', '/phpinfo.php',
    '/admin', '/server-status', '/.htaccess',
]

def check_exposed_files(base_url: str):
    result_queue.put(("CHECK", "A05 – Exposed Sensitive Files"))
    for path in KNOWN_PATHS:
        if not is_running:
            return
        url = base_url.rstrip('/') + path
        try:
            status, _, body = _get(url)
            if status == 200:
                result_queue.put(("FAIL", f"Accessible: {url}"))
            elif status == 403:
                result_queue.put(("WARN", f"Forbidden (possible resource): {url}"))
            else:
                result_queue.put(("PASS", f"{status}: {url}"))
        except Exception as e:
            result_queue.put(("ERROR", f"{path}: {e}"))

# ---------------------------------------------------------------------------
# A10 – SSRF probe
# ---------------------------------------------------------------------------

def check_ssrf(base_url: str):
    result_queue.put(("CHECK", "A10 – SSRF / Request Forgery"))
    ssrf_probes = ['url', 'uri', 'path', 'dest', 'redirect', 'next', 'target', 'src']
    ssrf_payloads = ['http://127.0.0.1/', 'http://169.254.169.254/']
    for param in ssrf_probes:
        for payload in ssrf_payloads:
            if not is_running:
                return
            url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            try:
                status, _, body = _get(url, timeout=4)
                if status == 200 and ('instance' in body or 'localhost' in body or payload in body):
                    result_queue.put(("FAIL", f"SSRF indicator on ?{param}={payload}"))
            except Exception:
                pass
    result_queue.put(("INFO", "SSRF probe complete (no conclusive hits)"))

# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run_compliance_scan(target_url: str, checks: list = None):
    """Run OWASP compliance checks on *target_url*.

    *checks* is an optional list of check names from:
    ['injection', 'auth', 'sensitive', 'headers', 'files', 'ssrf']
    If omitted, all are run.
    """
    global is_running
    is_running = True
    all_checks = checks or ['injection', 'auth', 'sensitive', 'headers', 'files', 'ssrf']
    result_queue.put(("STATUS", f"Starting OWASP scan against {target_url}"))

    dispatch = {
        'injection': lambda: check_injection(target_url),
        'auth':      lambda: check_broken_auth(target_url),
        'sensitive': lambda: check_sensitive_data(target_url),
        'headers':   lambda: check_security_headers(target_url),
        'files':     lambda: check_exposed_files(target_url),
        'ssrf':      lambda: check_ssrf(target_url),
    }

    for key in all_checks:
        if not is_running:
            break
        fn = dispatch.get(key)
        if fn:
            try:
                fn()
            except Exception as e:
                result_queue.put(("ERROR", f"Check '{key}' failed: {e}"))
                logger.error(f"Compliance check '{key}' error: {e}")

    result_queue.put(("DONE", "Compliance scan finished."))
    is_running = False


def stop_compliance_scan():
    global is_running
    is_running = False
