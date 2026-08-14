#http_utils
import re
import gzip
import zlib
import brotli
import zstandard
import json
import logging
import base64
from typing import Dict, List, Optional, Tuple, Union, Any
from urllib.parse import urlparse, parse_qs, urlencode

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

class HTTPParseError(Exception):
    """Custom exception for HTTP parsing errors."""
    pass

def _decompress_body(body_bytes: bytes, encoding: str) -> bytes:
    """Decompress response body based on content encoding.

    Args:
        body_bytes: Compressed body bytes
        encoding: Content encoding (gzip, deflate, br, zstd)

    Returns:
        Decompressed body bytes

    Raises:
        Exception: If decompression fails
    """
    encoding = encoding.lower().strip()

    if encoding == "gzip":
        try:
            return gzip.decompress(body_bytes)
        except Exception as e:
            logger.warning(f"Gzip decompression failed: {e}")
            raise
    elif encoding == "deflate":
        try:
            return zlib.decompress(body_bytes, -zlib.MAX_WBITS)
        except Exception as e:
            logger.warning(f"Deflate decompression failed: {e}")
            raise
    elif encoding == "br":
        try:
            return brotli.decompress(body_bytes)
        except Exception as e:
            logger.warning(f"Brotli decompression failed: {e}")
            raise
    elif encoding == "zstd":
        try:
            dctx = zstandard.ZstdDecompressor()
            return dctx.decompress(body_bytes)
        except Exception as e:
            logger.warning(f"Zstd decompression failed: {e}")
            raise
    else:
        logger.warning(f"Unsupported content encoding: {encoding}")
        return body_bytes

def _dechunk_body(body_bytes: bytes) -> bytes:
    """Dechunk HTTP chunked transfer encoding.

    Args:
        body_bytes: Chunked body bytes

    Returns:
        Dechunked body bytes
    """
    try:
        dechunked = b""
        idx = 0
        while idx < len(body_bytes):
            crlf = body_bytes.find(b"\r\n", idx)
            if crlf == -1:
                break
            size_str = body_bytes[idx:crlf].strip()
            if not size_str:
                break
            try:
                size = int(size_str, 16)
            except ValueError:
                logger.warning(f"Invalid chunk size: {size_str}")
                break
            if size == 0:
                break
            chunk_start = crlf + 2
            chunk_end = chunk_start + size
            if chunk_end > len(body_bytes):
                logger.warning("Incomplete chunk data")
                break
            dechunked += body_bytes[chunk_start:chunk_end]
            idx = chunk_end + 2  # Skip \r\n
        return dechunked
    except Exception as e:
        logger.error(f"Dechunking failed: {e}")
        return body_bytes

def _prettify_json(json_str: str) -> str:
    """Pretty-print JSON if valid.

    Args:
        json_str: JSON string

    Returns:
        Pretty-printed JSON or original string
    """
    try:
        parsed = json.loads(json_str)
        return json.dumps(parsed, indent=4)
    except (json.JSONDecodeError, TypeError):
        return json_str

def decode_response(response_data: bytes) -> str:
    """Decode HTTP response with compression and chunked transfer handling.

    Args:
        response_data: Raw response bytes

    Returns:
        Decoded response as string
    """
    if not isinstance(response_data, bytes):
        logger.error("Response data must be bytes")
        return str(response_data)

    if b"\r\n\r\n" not in response_data:
        logger.debug("No header/body separator found")
        return response_data.decode('utf-8', errors='ignore')

    headers_bytes, body_bytes = response_data.split(b"\r\n\r\n", 1)
    resp_headers = headers_bytes.decode('utf-8', errors='ignore')

    # Handle chunked transfer encoding
    if re.search(r"(?i)Transfer-Encoding:\s*chunked", resp_headers):
        logger.debug("Dechunking response body")
        body_bytes = _dechunk_body(body_bytes)

    # Handle content encoding
    encoding_match = re.search(r"(?i)Content-Encoding:\s*(\w+)", resp_headers)
    if encoding_match:
        encoding = encoding_match.group(1)
        logger.debug(f"Decompressing with {encoding}")
        try:
            body_bytes = _decompress_body(body_bytes, encoding)
        except Exception:
            logger.warning(f"Failed to decompress with {encoding}, using raw body")

    # Decode to string
    resp_body = body_bytes.decode('utf-8', errors='ignore')

    # Pretty-print JSON if applicable
    content_type_match = re.search(r"(?i)Content-Type:\s*([^;\r\n]+)", resp_headers)
    if content_type_match and 'json' in content_type_match.group(1).lower():
        logger.debug("Pretty-printing JSON response")
        resp_body = _prettify_json(resp_body)

    decoded_resp = resp_headers + "\r\n\r\n" + resp_body
    logger.debug(f"Decoded response: {len(decoded_resp)} chars")
    return decoded_resp

def format_http_request(raw_req: str) -> str:
    """Format and normalize HTTP request.

    Args:
        raw_req: Raw request string

    Returns:
        Formatted request string
    """
    if not isinstance(raw_req, str):
        logger.error("Request must be a string")
        return str(raw_req)

    # Normalize line endings
    raw_req = raw_req.replace('\r', '')

    # Split headers and body
    if "\n\n" in raw_req:
        headers, body = raw_req.split("\n\n", 1)
    else:
        headers = raw_req
        body = ""

    # Clean up extra newlines in headers
    while "\n\n" in headers:
        headers = headers.replace('\n\n', '\n')

    # Normalize HTTP version
    headers = re.sub(r"HTTP/[23]\.?0?", "HTTP/1.1", headers, count=1)

    # Set connection to close
    headers = re.sub(r"(?i)Connection:\s*keep-alive", "Connection: close", headers)

    # Ensure proper termination
    formatted = headers.strip() + "\n\n" + body.strip()
    if not formatted.endswith("\n\n"):
        formatted += "\n\n"

    logger.debug("Formatted HTTP request")
    return formatted

def format_history_text(raw_text: str) -> str:
    """Format history text for display.

    Args:
        raw_text: Raw history text

    Returns:
        Formatted text
    """
    if not isinstance(raw_text, str):
        logger.error("History text must be a string")
        return str(raw_text)

    # Clean up formatting
    req = raw_text.replace('\r', '').replace('==========', '')
    while "\n\n" in req:
        req = req.replace('\n\n', '\n')
    req = req.strip()

    logger.debug("Formatted history text")
    return req

def parse_http_headers(header_text: str) -> Dict[str, str]:
    """Parse HTTP headers into a dictionary.

    Args:
        header_text: Raw header text

    Returns:
        Dictionary of header name -> value
    """
    headers = {}
    for line in header_text.split('\n'):
        line = line.strip()
        if ':' in line:
            name, value = line.split(':', 1)
            headers[name.strip()] = value.strip()
    return headers

def extract_url_params(url: str) -> Dict[str, List[str]]:
    """Extract URL parameters.

    Args:
        url: URL string

    Returns:
        Dictionary of parameter name -> list of values
    """
    try:
        parsed = urlparse(url)
        return parse_qs(parsed.query)
    except Exception as e:
        logger.warning(f"Failed to parse URL params: {e}")
        return {}

def build_url_with_params(base_url: str, params: Dict[str, Any]) -> str:
    """Build URL with query parameters.

    Args:
        base_url: Base URL
        params: Parameter dictionary

    Returns:
        URL with parameters
    """
    try:
        parsed = urlparse(base_url)
        query = urlencode(params, doseq=True)
        return parsed._replace(query=query).geturl()
    except Exception as e:
        logger.warning(f"Failed to build URL: {e}")
        return base_url

def encode_basic_auth(username: str, password: str) -> str:
    """Encode username/password for Basic authentication.

    Args:
        username: Username
        password: Password

    Returns:
        Basic auth header value
    """
    credentials = f"{username}:{password}"
    encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
    return f"Basic {encoded}"

def parse_request_line(request_line: str) -> Tuple[str, str, str]:
    """Parse HTTP request line.

    Args:
        request_line: Request line (e.g., "GET /path HTTP/1.1")

    Returns:
        Tuple of (method, path, version)

    Raises:
        HTTPParseError: If parsing fails
    """
    parts = request_line.strip().split()
    if len(parts) != 3:
        raise HTTPParseError(f"Invalid request line: {request_line}")
    return parts[0], parts[1], parts[2]

def parse_status_line(status_line: str) -> Tuple[str, int, str]:
    """Parse HTTP status line.

    Args:
        status_line: Status line (e.g., "HTTP/1.1 200 OK")

    Returns:
        Tuple of (version, status_code, reason)

    Raises:
        HTTPParseError: If parsing fails
    """
    parts = status_line.strip().split(None, 2)
    if len(parts) != 3:
        raise HTTPParseError(f"Invalid status line: {status_line}")
    try:
        status_code = int(parts[1])
    except ValueError:
        raise HTTPParseError(f"Invalid status code: {parts[1]}")
    return parts[0], status_code, parts[2]

def is_json_content_type(content_type: str) -> bool:
    """Check if content type indicates JSON.

    Args:
        content_type: Content-Type header value

    Returns:
        True if JSON content type
    """
    return bool(content_type and 'json' in content_type.lower())

def get_content_length(headers: Dict[str, str]) -> int:
    """Extract Content-Length from headers.

    Args:
        headers: Header dictionary

    Returns:
        Content length or -1 if not found/invalid
    """
    length_str = headers.get('Content-Length', headers.get('content-length', ''))
    try:
        return int(length_str)
    except ValueError:
        return -1