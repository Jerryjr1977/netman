#subdomain_engine
import socket
import queue
import threading
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

result_queue = queue.Queue()
is_running = False

BUILTIN_WORDLIST = [
    'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail', 'cpanel',
    'admin', 'login', 'portal', 'secure', 'vpn', 'remote', 'access',
    'api', 'api2', 'rest', 'graphql', 'cdn', 'static', 'assets', 'images',
    'dev', 'staging', 'test', 'demo', 'beta', 'qa', 'uat',
    'app', 'apps', 'mobile', 'ws', 'socket',
    'blog', 'shop', 'store', 'docs', 'wiki', 'help', 'support', 'kb',
    'cloud', 'aws', 'azure', 'gcp',
    'db', 'mysql', 'postgres', 'redis', 'es', 'elastic', 'mongo',
    'm', 'ns', 'ns1', 'ns2', 'mx', 'mx1', 'mx2',
    'status', 'monitor', 'health', 'metrics', 'logs',
    'v1', 'v2', 'v3',
]


def _resolve(hostname: str) -> list:
    """Try to resolve a hostname. Returns list of IP addresses or empty list."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
        ips = list({r[4][0] for r in results})
        return ips
    except socket.gaierror:
        return []
    except Exception as e:
        logger.debug(f"Resolve error for {hostname}: {e}")
        return []


def _build_wordlist(wordlist_path: str) -> list:
    """Load wordlist from file or use built-in list."""
    if wordlist_path:
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
            logger.info(f"Loaded {len(words)} words from {wordlist_path}")
            return words
        except Exception as e:
            logger.warning(f"Could not load wordlist: {e}. Using built-in list.")
    return BUILTIN_WORDLIST


def _check_subdomain(sub: str, domain: str) -> tuple:
    """Check a single subdomain. Returns (subdomain, ips) or None."""
    if not is_running:
        return None
    hostname = f"{sub}.{domain}"
    ips = _resolve(hostname)
    if ips:
        return hostname, ips
    return None


def run_subdomain_scan(domain: str, wordlist_path: str = "", max_threads: int = 50):
    """Run subdomain enumeration scan."""
    global is_running
    is_running = True

    domain = domain.strip().lstrip("https://").lstrip("http://").split("/")[0]
    words = _build_wordlist(wordlist_path)

    result_queue.put(("STATUS", f"Scanning {domain} with {len(words)} subdomains..."))
    logger.info(f"Subdomain scan: {domain}, {len(words)} words, {max_threads} threads")

    found = 0
    workers = min(max_threads, len(words))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_check_subdomain, sub, domain): sub
            for sub in words
        }
        for future in as_completed(futures):
            if not is_running:
                break
            result = future.result()
            if result:
                hostname, ips = result
                ip_str = ', '.join(ips[:3])
                result_queue.put(("FOUND", f"{hostname}  →  {ip_str}"))
                found += 1

    if is_running:
        result_queue.put(("DONE", f"Scan complete. Found {found} subdomain(s)."))
    else:
        result_queue.put(("DONE", "Scan aborted by user."))

    is_running = False


def stop_subdomain_scan():
    global is_running
    is_running = False
