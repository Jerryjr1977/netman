#ssl_engine
import ssl
import socket
import datetime
import hashlib
import queue
import logging
from typing import Optional

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

result_queue = queue.Queue()
is_running = False

WEAK_CIPHERS = ['RC4', 'DES', 'NULL', 'EXPORT', 'MD5', 'ADH', 'AECDH']
DEPRECATED_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']

CIPHER_TESTS = [
    ('TLS 1.0', ssl.TLSVersion.TLSv1),
    ('TLS 1.1', ssl.TLSVersion.TLSv1_1),
    ('TLS 1.2', ssl.TLSVersion.TLSv1_2),
    ('TLS 1.3', ssl.TLSVersion.TLSv1_3),
]

def _connect_ssl(host: str, port: int, protocol_version=None, timeout: float = 5.0) -> Optional[ssl.SSLSocket]:
    """Attempt SSL connection with optional protocol constraint."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if protocol_version is not None:
            ctx.minimum_version = protocol_version
            ctx.maximum_version = protocol_version
        sock = socket.create_connection((host, port), timeout=timeout)
        ssl_sock = ctx.wrap_socket(sock, server_hostname=host)
        return ssl_sock
    except Exception as e:
        logger.debug(f"SSL connection failed ({protocol_version}): {e}")
        return None


def check_certificate(host: str, port: int) -> dict:
    """Extract and analyse the server certificate."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert(binary_form=True)
                cert_dict = s.getpeercert()
                der_cert = cert
                sha256_fp = hashlib.sha256(der_cert).hexdigest().upper()
                sha256_fp = ':'.join(sha256_fp[i:i+2] for i in range(0, len(sha256_fp), 2))

                subject = dict(x[0] for x in cert_dict.get('subject', []))
                issuer = dict(x[0] for x in cert_dict.get('issuer', []))
                not_before_str = cert_dict.get('notBefore', '')
                not_after_str = cert_dict.get('notAfter', '')

                try:
                    not_after = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                    days_left = (not_after - datetime.datetime.utcnow()).days
                    expired = days_left < 0
                    expiring_soon = 0 <= days_left <= 30
                except Exception:
                    days_left = -1
                    expired = False
                    expiring_soon = False

                san_list = [v for k, v in cert_dict.get('subjectAltName', [])]

                return {
                    'common_name': subject.get('commonName', 'N/A'),
                    'issuer': issuer.get('organizationName', 'N/A'),
                    'not_before': not_before_str,
                    'not_after': not_after_str,
                    'days_left': days_left,
                    'expired': expired,
                    'expiring_soon': expiring_soon,
                    'san': san_list,
                    'sha256': sha256_fp,
                    'self_signed': subject == issuer,
                }
    except Exception as e:
        logger.warning(f"Certificate check failed: {e}")
        return {'error': str(e)}


def check_protocol_support(host: str, port: int) -> list:
    """Check which TLS protocol versions the server supports."""
    supported = []
    for label, version in CIPHER_TESTS:
        ssl_sock = _connect_ssl(host, port, protocol_version=version)
        if ssl_sock:
            try:
                supported.append((label, ssl_sock.version(), ssl_sock.cipher()))
            finally:
                ssl_sock.close()
    return supported


def check_cipher_suites(host: str, port: int) -> list:
    """List negotiated cipher suite and check for weak ciphers."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cipher = s.cipher()
                if cipher:
                    name, proto, bits = cipher
                    is_weak = any(w in name.upper() for w in WEAK_CIPHERS)
                    return [{'name': name, 'protocol': proto, 'bits': bits, 'weak': is_weak}]
    except Exception as e:
        logger.warning(f"Cipher check failed: {e}")
    return []


def run_ssl_scan(host: str, port_str: str):
    """Run the full SSL/TLS security scan."""
    global is_running
    is_running = True

    try:
        port = int(port_str)
    except ValueError:
        result_queue.put(("ERROR", "Invalid port number"))
        is_running = False
        return

    result_queue.put(("STATUS", f"Starting SSL/TLS scan on {host}:{port}"))

    # --- Certificate ---
    if is_running:
        result_queue.put(("STATUS", "Analysing certificate..."))
        cert = check_certificate(host, port)
        if 'error' in cert:
            result_queue.put(("ERROR", f"Certificate error: {cert['error']}"))
        else:
            result_queue.put(("CERT", f"Common Name: {cert['common_name']}"))
            result_queue.put(("CERT", f"Issuer: {cert['issuer']}"))
            result_queue.put(("CERT", f"Valid Until: {cert['not_after']} ({cert['days_left']} days left)"))
            result_queue.put(("CERT", f"SHA-256 Fingerprint: {cert['sha256'][:29]}..."))
            if cert.get('self_signed'):
                result_queue.put(("WARN", "Certificate is self-signed"))
            if cert.get('expired'):
                result_queue.put(("VULN", "Certificate is EXPIRED"))
            elif cert.get('expiring_soon'):
                result_queue.put(("WARN", f"Certificate expiring in {cert['days_left']} days"))
            else:
                result_queue.put(("OK", f"Certificate valid ({cert['days_left']} days remaining)"))
            if cert.get('san'):
                result_queue.put(("CERT", f"SANs: {', '.join(cert['san'][:5])}"))

    # --- Protocol Versions ---
    if is_running:
        result_queue.put(("STATUS", "Checking TLS protocol versions..."))
        protocols = check_protocol_support(host, port)
        if not protocols:
            result_queue.put(("ERROR", "Could not negotiate any TLS connection"))
        else:
            for label, version, cipher in protocols:
                if label in ('TLS 1.0', 'TLS 1.1'):
                    result_queue.put(("VULN", f"{label} is ENABLED (deprecated)"))
                else:
                    result_queue.put(("OK", f"{label} supported"))

    # --- Cipher Suites ---
    if is_running:
        result_queue.put(("STATUS", "Checking cipher suites..."))
        ciphers = check_cipher_suites(host, port)
        for c in ciphers:
            if c.get('weak'):
                result_queue.put(("VULN", f"WEAK cipher: {c['name']} ({c['bits']} bits)"))
            else:
                result_queue.put(("OK", f"Cipher: {c['name']} ({c['bits']} bits)"))

    if is_running:
        result_queue.put(("DONE", "SSL/TLS scan complete."))
    else:
        result_queue.put(("DONE", "Scan aborted by user."))

    is_running = False


def stop_ssl_scan():
    global is_running
    is_running = False
