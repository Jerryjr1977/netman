#decoder_engine
import base64
from urllib import parse
import html

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
        return raw_text.encode('utf-8').hex()
    except Exception as e:
        return f"[-] Hex Encode Error: {e}"

def decode_hex(raw_text):
    try:
        cleaned = raw_text.strip().replace(' ', '').replace('0x', '').replace('\\x', '')
        return bytes.fromhex(cleaned).decode('utf-8', errors='replace')
    except Exception as e:
        return f"[-] Hex Decode Error: {e}"

def encode_binary(raw_text):
    try:
        return ' '.join(format(b, '08b') for b in raw_text.encode('utf-8'))
    except Exception as e:
        return f"[-] Binary Encode Error: {e}"

def decode_binary(raw_text):
    try:
        chunks = raw_text.strip().split()
        return bytes(int(b, 2) for b in chunks).decode('utf-8', errors='replace')
    except Exception as e:
        return f"[-] Binary Decode Error: {e}"