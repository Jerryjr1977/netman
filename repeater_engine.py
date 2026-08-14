#repeater_engine
import socket
import ssl
import re
import logging
import http_utils
try:
    from intruder_engine import create_ssl_context
except ImportError:
    def create_ssl_context():
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

_XFF_REFLECT_HEADERS = [
    'x-forwarded-for', 'x-real-ip', 'cf-connecting-ip',
    'x-client-ip', 'true-client-ip', 'x-original-forwarded-for',
]


def _detect_xff_reflection(request_text: str, response_text: str) -> str:
    """Return an annotation line if the X-Forwarded-For value from the request
    is reflected back in any known forwarding header in the response."""
    match = re.search(r'(?i)^X-Forwarded-For:\s*(.+)$', request_text, re.MULTILINE)
    if not match:
        return ""
    xff_value = match.group(1).strip()
    for line in response_text.splitlines():
        if any(line.lower().startswith(h + ':') for h in _XFF_REFLECT_HEADERS):
            if xff_value in line:
                return f"\n[!] [XFF] X-Forwarded-For reflected in response header: {line.strip()}"
    return ""

def send_request(raw_request):
    """Send an HTTP request and return decoded response."""
    if "\n\n" in raw_request:
        headers, body = raw_request.split("\n\n", 1)
    else:
        headers = raw_request
        body = ""
    
    target_host = None
    target_port = 80
    
    # Extract Host header
    for line in headers.split('\n'):
        if line.lower().startswith("host:"):
            try:
                host_header = line.split(':', 1)[1].strip()
                if ":" in host_header:
                    parts = host_header.split(':')
                    target_host = parts[0].strip()
                    try:
                        target_port = int(parts[1].strip())
                    except ValueError:
                        logger.warning(f"Invalid port in Host header, using 80")
                        target_port = 80
                else:
                    target_host = host_header
                    target_port = 443  # Default to HTTPS
                break
            except Exception as e:
                logger.warning(f"Failed to parse Host header: {e}")
                continue
    
    if not target_host:
        logger.error("No Host header found in request")
        return "[-] No Host header found in request."
    
    logger.debug(f"Target: {target_host}:{target_port}")
    
    # Normalize line endings and headers
    headers = re.sub(r"(?i)Connection:[^\n]*", "Connection: close", headers)

    # Normalize body to CRLF FIRST, then measure — so Content-Length matches what's actually sent
    body_crlf = body.replace('\r\n', '\n').replace('\r', '\n').replace('\n', '\r\n')
    body_bytes = body_crlf.encode('utf-8')
    body_length = len(body_bytes)

    if re.search(r"(?i)Content-Length:\s*\d+", headers):
        headers = re.sub(r"(?i)Content-Length:\s*\d+", f"Content-Length: {body_length}", headers)
    elif body_length > 0:
        headers += f"\nContent-Length: {body_length}"

    # Convert headers to CRLF (normalize first to avoid doubling existing \r\n)
    headers_crlf = headers.replace('\r\n', '\n').replace('\r', '\n').replace('\n', '\r\n')
    full_request = headers_crlf + "\r\n\r\n" + body_crlf
    payload = full_request.encode('utf-8', errors='ignore')
    
    try:
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.settimeout(5.0)
        if target_port == 443:
            target_socket = create_ssl_context().wrap_socket(target_socket, server_hostname=target_host)
        
        logger.debug(f"Connecting to {target_host}:{target_port}...")
        target_socket.connect((target_host, target_port))
        target_socket.sendall(payload)
        
        response_data = b""
        target_socket.settimeout(2.0)
        try:
            while True:
                chunk = target_socket.recv(8192)
                if not chunk:
                    break
                response_data += chunk
        except socket.timeout:
            logger.debug("Response receive timeout (expected)")
        finally:
            target_socket.close()
        
        if response_data:
            logger.debug(f"Response received: {len(response_data)} bytes")
            decoded_resp = http_utils.decode_response(response_data)
            xff_note = _detect_xff_reflection(raw_request, decoded_resp)
            return decoded_resp + xff_note
        else:
            logger.warning("Server closed connection without sending data")
            return "[-] Server closed connection without sending data."
            
    except socket.gaierror as e:
        logger.error(f"DNS resolution failed for {target_host}: {e}")
        return f"[-] DNS resolution failed:\n{e}"
    except socket.timeout as e:
        logger.error(f"Connection timeout: {e}")
        return f"[-] Connection timeout:\n{e}"
    except Exception as e:
        logger.error(f"Payload execution failed: {e}")
        return f"[-] Payload failed to fire:\n{e}"