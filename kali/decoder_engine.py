#decoder_engine
import base64
import subprocess
from urllib import parse
import html


def _is_printable_ascii(byte_value):
    return 32 <= byte_value <= 126


def _decode_input_to_bytes(raw_text):
    stripped = raw_text.strip()
    if not stripped:
        return b"", "empty"

    # Hex-like input (supports spaces, commas, colons, and 0x prefixes).
    hexish = stripped.lower().replace("0x", " ").replace(",", " ").replace(":", " ")
    tokens = [tok for tok in hexish.split() if tok]
    if tokens and all(all(ch in "0123456789abcdef" for ch in tok) for tok in tokens):
        if all(len(tok) == 2 for tok in tokens):
            return bytes(int(tok, 16) for tok in tokens), "hex-bytes"
        compact_hex = "".join(tokens)
        if compact_hex and len(compact_hex) % 2 == 0:
            return bytes.fromhex(compact_hex), "hex-compact"

    # Binary-like input (supports spaces, commas, and 0b prefixes).
    binaryish = stripped.replace("0b", " ").replace(",", " ")
    bits_tokens = [tok for tok in binaryish.split() if set(tok) <= {"0", "1"}]
    if bits_tokens:
        if all(len(tok) == 8 for tok in bits_tokens):
            return bytes(int(tok, 2) for tok in bits_tokens), "binary-bytes"
        compact_bits = "".join(bits_tokens)
        if compact_bits and len(compact_bits) % 8 == 0 and set(compact_bits) <= {"0", "1"}:
            return bytes(int(compact_bits[i:i+8], 2) for i in range(0, len(compact_bits), 8)), "binary-compact"

    # Fallback to UTF-8 text bytes.
    return stripped.encode("utf-8", errors="ignore"), "utf8-text"


def inspect_bytes(raw_text):
    try:
        data, detected_mode = _decode_input_to_bytes(raw_text)
        if not data:
            return "[-] Byte Inspector: no input bytes to inspect"

        lines = [f"[Byte Inspector] mode={detected_mode} bytes={len(data)}", ""]

        # Wireshark/hex-editor style 16-byte grouped view.
        lines.append("[Hexdump 16-byte blocks]")
        lines.append("offset  hex bytes                                         ascii")
        lines.append("------  -----------------------------------------------  ----------------")
        for offset in range(0, len(data), 16):
            chunk = data[offset : offset + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if _is_printable_ascii(b) else "." for b in chunk)
            lines.append(f"{offset:06x}  {hex_part:<47}  {ascii_part}")

        lines.append("")
        lines.append("[Per-byte table]")
        lines.append("idx  hex  dec  binary      chr")
        lines.append("---  ---  ---  ----------  ---")

        for idx, byte_value in enumerate(data):
            char_repr = chr(byte_value) if _is_printable_ascii(byte_value) else "."
            lines.append(
                f"{idx:>3}  {byte_value:02x}  {byte_value:>3}  {byte_value:08b}  {char_repr}"
            )

        printable_preview = "".join(
            chr(b) if _is_printable_ascii(b) else "." for b in data
        )
        lines.append("")
        lines.append(f"ASCII preview: {printable_preview}")
        return "\n".join(lines)
    except Exception as e:
        return f"[-] Byte Inspector Error: {e}"

def encode_base64(raw_text):
    encoded_bytes = base64.b64encode(raw_text.encode('utf-8'))
    result = encoded_bytes.decode('utf-8')
    return result

def decode_base64(raw_text):
    try:
        padded_text = raw_text + "=" * ((4 - len(raw_text) % 4) % 4)
        decoded_bytes = base64.b64decode(padded_text)
        result = decoded_bytes.decode('utf-8', errors='ignore')
        return result
    except Exception as e:
        return f"[-] Decode Error: {e}"
    
def decode_base85(raw_text):
    try:
        import struct

        z85_chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
        decoded = []
        if len(raw_text) % 5 != 0:
            return "[-] Error: Z85 strings must be a multiple of 5 characters long."
        for i in range(0, len(raw_text), 5):
            value = 0
            for j in range(5):
                value = value * 85 + z85_chars.index(raw_text[i + j])
            decoded.append(struct.pack('>I', value))
        return b"".join(decoded).decode('utf-8', errors='ignore')
    except Exception as e:
        return f"[-] Z85 Decode Error: {e}"
    
def encode_base85(raw_text):
    try:
        import struct

        z85_chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
        encoded = ""
        raw_bytes = raw_text.encode('utf-8')
        padding = (4 - len(raw_bytes) % 4) % 4
        padded_bytes = raw_bytes + (b'\x00' * padding)
        for i in range(0, len(padded_bytes), 4):
            chunk = padded_bytes[i:i+4]
            value = struct.unpack('>I', chunk)[0]
            chunk_encoded = ""
            for _ in range(5):
                chunk_encoded = z85_chars[value % 85] + chunk_encoded
                value //= 85
            encoded += chunk_encoded
        return encoded
    except Exception as e:
        return f"[-] Z85 Encode Error: {e}"

def encode_url(raw_text):
    return parse.quote(raw_text)

def decode_url(raw_text):
    return parse.unquote(raw_text)

def encode_html(raw_text):
    return html.escape(raw_text)

def decode_html(raw_text):
    return html.unescape(raw_text)

def encode_hex(raw_text):
    try:
        return " ".join(format(b, "02x") for b in raw_text.encode("utf-8"))
    except Exception as e:
        return f"[-] Hex Encode Error: {e}"

def decode_hex(raw_text):
    try:
        cleaned = raw_text.lower().replace("0x", " ").replace(",", " ").replace(":", " ")
        tokens = [tok for tok in cleaned.split() if tok]

        # Prefer tokenized bytes (Wireshark-like) if tokens are present.
        if tokens:
            if any(any(ch not in "0123456789abcdef" for ch in tok) for tok in tokens):
                return "[-] Hex Decode Error: invalid hex characters"

            if all(len(tok) == 2 for tok in tokens):
                data = bytes(int(tok, 16) for tok in tokens)
                return data.decode("utf-8", errors="ignore")

            # Fallback: join tokens into one continuous hex stream.
            compact = "".join(tokens)
        else:
            compact = "".join(ch for ch in cleaned if ch in "0123456789abcdef")

        if not compact:
            return "[-] Hex Decode Error: no hex data found"
        if len(compact) % 2 != 0:
            return "[-] Hex Decode Error: hex length must be even"

        data = bytes.fromhex(compact)
        return data.decode("utf-8", errors="ignore")
    except Exception as e:
        return f"[-] Hex Decode Error: {e}"

def encode_binary(raw_text):
    try:
        return " ".join(format(b, "08b") for b in raw_text.encode("utf-8"))
    except Exception as e:
        return f"[-] Binary Encode Error: {e}"

def decode_binary(raw_text):
    try:
        cleaned = raw_text.replace("0b", " ").replace(",", " ")
        compact = "".join(ch for ch in cleaned if ch in "01")
        if not compact:
            return "[-] Binary Decode Error: no binary data found"

        # Support both spaced bytes and compact streams of 8-bit chunks.
        tokens = [tok for tok in cleaned.split() if set(tok) <= {"0", "1"}]
        if tokens:
            if any(len(tok) != 8 for tok in tokens):
                return "[-] Binary Decode Error: each binary token must be 8 bits"
            data = bytes(int(tok, 2) for tok in tokens)
            return data.decode("utf-8", errors="ignore")

        if len(compact) % 8 != 0:
            return "[-] Binary Decode Error: compact binary length must be a multiple of 8"

        data = bytes(int(compact[i:i+8], 2) for i in range(0, len(compact), 8))
        return data.decode("utf-8", errors="ignore")
    except Exception as e:
        return f"[-] Binary Decode Error: {e}"
    
def load_wordlist(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        return f"[-] File Error: {e}"
    
def try_openssl_decrypt(raw_data, password):
    cmd = [
        'openssl', 'enc', '-d', '-aes-256-cbc',
        '-salt', '-pass', f'pass:{password}'
    ]
    process = subprocess.Popen(
        cmd, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = process.communicate(input=raw_data)
    if process.returncode == 0:
        return stdout.decode('utf-8', errors='ignore')
    return None


def brute_force_openssl(encrypted_data, passwords):
    for pwd in passwords:
        result = try_openssl_decrypt(encrypted_data, pwd)
        if result and not result.startswith("[-]"):
            # Simple heuristic: check if result is mostly printable
            if all(32 <= ord(c) <= 126 or c in '\n\r\t' for c in result[:100]):
                return pwd, result
    return None, None