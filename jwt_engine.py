#jwt_engine
import base64
import json

def pad_base64(b64_string):
    return b64_string + "=" * ((4 - len(b64_string) % 4) % 4)

def decode_part(jwt_part):
    try:
        padded = pad_base64(jwt_part)
        decoded_bytes = base64.urlsafe_b64decode(padded)
        parsed_json = json.loads(decoded_bytes.decode('utf-8', errors='ignore'))
        return json.dumps(parsed_json, indent=4)
    except Exception as e:
        return f"[-] Decode Error: {e}"
    
def parse_token(jwt_token):
    parts = jwt_token.strip().split('.')
    
    if len(parts) != 3:
        return "Invalid Token", "Invalid Token", "Invalid Token"
    header_json = decode_part(parts[0])
    payload_json = decode_part(parts[1])
    signature_raw = parts[2]
    return header_json, payload_json, signature_raw

def encode_part(json_text):
    encoded_bytes = base64.urlsafe_b64encode(json_text.encode('utf-8'))
    return encoded_bytes.decode('utf-8').rstrip('=')

def forge_token(header_json, payload_json):
    b64_header = encode_part(header_json)
    b64_payload = encode_part(payload_json)
    return f"{b64_header}.{b64_payload}."