#tech_engine
import urllib.request
import urllib.error
import re
import queue
import logging

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

result_queue = queue.Queue()
is_running = False

# --- Fingerprint databases ---

SERVER_SIGNATURES = {
    'apache': 'Apache',
    'nginx': 'Nginx',
    'iis': 'Microsoft IIS',
    'lighttpd': 'Lighttpd',
    'cloudflare': 'Cloudflare',
    'gunicorn': 'Gunicorn (Python)',
    'kestrel': 'Kestrel (.NET)',
    'jetty': 'Jetty (Java)',
    'tomcat': 'Apache Tomcat',
    'caddy': 'Caddy',
}

HEADER_TECH_MAP = {
    'x-powered-by': {
        'php': 'PHP',
        'asp.net': 'ASP.NET',
        'express': 'Express.js (Node)',
        'next.js': 'Next.js',
        'django': 'Django (Python)',
        'laravel': 'Laravel (PHP)',
    },
    'x-generator': {
        'wordpress': 'WordPress',
        'drupal': 'Drupal',
        'joomla': 'Joomla',
        'ghost': 'Ghost CMS',
    },
    'x-drupal-cache': {'': 'Drupal'},
    'x-wp-total': {'': 'WordPress'},
}

SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'X-XSS-Protection',
    'Referrer-Policy',
    'Permissions-Policy',
]

HTML_SIGNATURES = [
    (r'<meta[^>]+generator[^>]+(wordpress)', 'WordPress'),
    (r'<meta[^>]+generator[^>]+(drupal)', 'Drupal'),
    (r'<meta[^>]+generator[^>]+(joomla)', 'Joomla'),
    (r'wp-content/', 'WordPress'),
    (r'sites/default/files', 'Drupal'),
    (r'var\s+Shopify\s*=', 'Shopify'),
    (r'cdn\.shopify\.com', 'Shopify'),
    (r'squarespace\.com', 'Squarespace'),
    (r'wixsite\.com|_wix_', 'Wix'),
    (r'<[^>]+data-reactroot', 'React'),
    (r'ng-version=', 'Angular'),
    (r'__vue', 'Vue.js'),
    (r'cdn\.jsdelivr\.net/npm/bootstrap', 'Bootstrap'),
    (r'jquery[.\-][\d.]+\.min\.js', 'jQuery'),
    (r'gtag\(|googletagmanager\.com', 'Google Analytics / GTM'),
]

COOKIE_SIGNATURES = {
    'PHPSESSID': 'PHP',
    'ASP.NET_SessionId': 'ASP.NET',
    'JSESSIONID': 'Java / Servlet',
    'laravel_session': 'Laravel',
    'wordpress_logged_in': 'WordPress',
    '__cf_bm': 'Cloudflare Bot Management',
    '_ga': 'Google Analytics',
    'wp-settings': 'WordPress',
}


def _check_security_headers(resp_headers: dict) -> list:
    """Return list of missing and present security headers."""
    present = []
    missing = []
    for h in SECURITY_HEADERS:
        if h.lower() in resp_headers:
            present.append(h)
        else:
            missing.append(h)
    return present, missing


def _analyse_headers(resp_headers: dict) -> list:
    """Detect technologies from HTTP response headers."""
    findings = []
    server = resp_headers.get('server', '')
    for sig, label in SERVER_SIGNATURES.items():
        if sig in server.lower():
            findings.append(('SERVER', label))
            break

    for header, patterns in HEADER_TECH_MAP.items():
        header_val = resp_headers.get(header, '').lower()
        if header_val:
            for pattern, label in patterns.items():
                if not pattern or pattern in header_val:
                    findings.append(('TECH', label))

    return findings


def _analyse_cookies(cookie_header: str) -> list:
    """Detect technologies from Set-Cookie headers."""
    findings = []
    for cookie_name, label in COOKIE_SIGNATURES.items():
        if cookie_name.lower() in cookie_header.lower():
            findings.append(('COOKIE', f"{label} (cookie: {cookie_name})"))
    return findings


def _analyse_html(html: str) -> list:
    """Detect technologies from HTML body."""
    findings = []
    seen = set()
    for pattern, label in HTML_SIGNATURES:
        if re.search(pattern, html, re.IGNORECASE) and label not in seen:
            findings.append(('HTML', label))
            seen.add(label)
    return findings


def run_tech_scan(target_url: str):
    """Run the full technology detection scan."""
    global is_running
    is_running = True

    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    result_queue.put(("STATUS", f"Scanning {target_url}"))
    logger.info(f"Tech scan: {target_url}")

    try:
        req = urllib.request.Request(
            target_url,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; NetMan/1.0)'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            status = response.getcode()
            resp_headers = {k.lower(): v for k, v in response.headers.items()}
            html = response.read().decode('utf-8', errors='ignore')
            cookie_header = response.headers.get('Set-Cookie', '')

        result_queue.put(("STATUS", f"Got HTTP {status} — analysing..."))

        findings = []
        findings += _analyse_headers(resp_headers)
        findings += _analyse_cookies(cookie_header)
        findings += _analyse_html(html)

        seen = set()
        for kind, label in findings:
            if label not in seen:
                result_queue.put((kind, label))
                seen.add(label)

        # Security headers
        present, missing = _check_security_headers(resp_headers)
        for h in present:
            result_queue.put(("SECURE", f"{h}: present"))
        for h in missing:
            result_queue.put(("MISSING", f"{h}: MISSING"))

        if not seen:
            result_queue.put(("STATUS", "No specific technologies identified"))

    except urllib.error.HTTPError as e:
        result_queue.put(("ERROR", f"HTTP {e.code}: {e.reason}"))
    except Exception as e:
        result_queue.put(("ERROR", f"Scan failed: {e}"))
        logger.error(f"Tech scan failed: {e}")

    if is_running:
        result_queue.put(("DONE", "Technology scan complete."))
    else:
        result_queue.put(("DONE", "Scan aborted by user."))

    is_running = False


def stop_tech_scan():
    global is_running
    is_running = False
