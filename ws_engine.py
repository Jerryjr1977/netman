#ws_engine
import socket
import ssl
import threading
import hashlib
import base64
import queue
import logging
import os

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

message_queue = queue.Queue()
is_connected = False
ws_socket = None

WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _make_handshake_request(host: str, path: str, extra_headers: dict | None = None) -> tuple[bytes, str]:
    """Build the HTTP Upgrade handshake request."""
    key_bytes = os.urandom(16)
    ws_key = base64.b64encode(key_bytes).decode('utf-8')
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {ws_key}",
        "Sec-WebSocket-Version: 13",
    ]
    if extra_headers:
        for k, v in extra_headers.items():
            lines.append(f"{k}: {v}")
    lines += ["", ""]
    return "\r\n".join(lines).encode('utf-8'), ws_key


def _verify_handshake(response: bytes, ws_key: str) -> bool:
    """Verify the server's Sec-WebSocket-Accept header."""
    expected_digest = hashlib.sha1((ws_key + WS_MAGIC).encode()).digest()
    expected_accept = base64.b64encode(expected_digest).decode()
    for line in response.decode('utf-8', errors='ignore').split('\r\n'):
        if line.lower().startswith('sec-websocket-accept:'):
            server_accept = line.split(':', 1)[1].strip()
            return server_accept == expected_accept
    return False


def _send_frame(sock, payload: bytes, opcode: int = 0x1) -> None:
    """Send a WebSocket frame (client masking applied)."""
    mask_key = os.urandom(4)
    masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    length = len(payload)
    header = bytearray()
    header.append(0x80 | opcode)  # FIN + opcode
    if length <= 125:
        header.append(0x80 | length)
    elif length <= 65535:
        header.append(0x80 | 126)
        header += length.to_bytes(2, 'big')
    else:
        header.append(0x80 | 127)
        header += length.to_bytes(8, 'big')
    header += mask_key
    sock.sendall(bytes(header) + masked)


def _recv_frame(sock) -> tuple:
    """Receive and decode a WebSocket frame."""
    header = b""
    while len(header) < 2:
        chunk = sock.recv(2 - len(header))
        if not chunk:
            raise ConnectionError("Connection closed")
        header += chunk

    fin = (header[0] & 0x80) != 0
    opcode = header[0] & 0x0F
    masked = (header[1] & 0x80) != 0
    length = header[1] & 0x7F

    if length == 126:
        length = int.from_bytes(sock.recv(2), 'big')
    elif length == 127:
        length = int.from_bytes(sock.recv(8), 'big')

    mask = sock.recv(4) if masked else b""
    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            raise ConnectionError("Connection closed")
        payload += chunk

    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

    return opcode, payload


def _receive_loop(sock) -> None:
    """Background thread: continuously receive WebSocket frames."""
    global is_connected
    try:
        while is_connected:
            opcode, payload = _recv_frame(sock)
            if opcode == 0x1:  # Text
                text = payload.decode('utf-8', errors='ignore')
                message_queue.put(("RECV", text))
                logger.debug(f"Received text frame: {len(text)} chars")
            elif opcode == 0x2:  # Binary
                message_queue.put(("BINARY", f"<binary {len(payload)} bytes>"))
            elif opcode == 0x8:  # Close
                message_queue.put(("CLOSED", "Server closed the connection"))
                is_connected = False
                break
            elif opcode == 0x9:  # Ping
                _send_frame(sock, payload, opcode=0xA)  # Pong
                message_queue.put(("PING", "Ping received, Pong sent"))
    except Exception as e:
        if is_connected:
            message_queue.put(("ERROR", f"Receive error: {e}"))
        is_connected = False


def connect(url: str, extra_headers: dict | None = None) -> None:
    """Connect to a WebSocket server."""
    global ws_socket, is_connected

    message_queue.put(("STATUS", f"Connecting to {url}"))

    try:
        use_ssl = url.startswith("wss://")
        url_stripped = url.replace("wss://", "").replace("ws://", "")
        if "/" in url_stripped:
            host_port, path = url_stripped.split("/", 1)
            path = "/" + path
        else:
            host_port = url_stripped
            path = "/"

        host = host_port.split(":")[0]
        port = int(host_port.split(":")[1]) if ":" in host_port else (443 if use_ssl else 80)

        raw_sock = socket.create_connection((host, port), timeout=10)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw_sock = ctx.wrap_socket(raw_sock, server_hostname=host)

        handshake, ws_key = _make_handshake_request(host, path, extra_headers)
        raw_sock.sendall(handshake)

        response = b""
        while b"\r\n\r\n" not in response:
            response += raw_sock.recv(4096)

        if b"101" not in response:
            message_queue.put(("ERROR", f"Handshake failed: {response[:200].decode('utf-8', errors='ignore')}"))
            raw_sock.close()
            return

        if not _verify_handshake(response, ws_key):
            message_queue.put(("WARN", "WebSocket key verification failed (server may be non-standard)"))

        ws_socket = raw_sock
        is_connected = True
        message_queue.put(("CONNECTED", f"Connected to {url}"))
        logger.info(f"WebSocket connected: {url}")

        threading.Thread(target=_receive_loop, args=(raw_sock,), daemon=True).start()

    except Exception as e:
        message_queue.put(("ERROR", f"Connection failed: {e}"))
        logger.error(f"WebSocket connection failed: {e}")


def send_message(text: str) -> None:
    """Send a text message over the WebSocket."""
    global ws_socket
    if not is_connected or ws_socket is None:
        message_queue.put(("ERROR", "Not connected"))
        return
    try:
        _send_frame(ws_socket, text.encode('utf-8'))
        message_queue.put(("SENT", text))
        logger.debug(f"Sent WS message: {text[:80]}")
    except Exception as e:
        message_queue.put(("ERROR", f"Send failed: {e}"))


def disconnect() -> None:
    """Close the WebSocket connection."""
    global ws_socket, is_connected
    is_connected = False
    if ws_socket:
        try:
            _send_frame(ws_socket, b"", opcode=0x8)  # Close frame
            ws_socket.close()
        except Exception:
            pass
        ws_socket = None
    message_queue.put(("CLOSED", "Connection closed"))
    logger.info("WebSocket disconnected")
