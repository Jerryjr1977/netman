#jwt_engine
import base64
import hashlib
import hmac
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def pad_base64(b64_string):
    return b64_string + "=" * ((4 - len(b64_string) % 4) % 4)


HMAC_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

RSA_ALGORITHMS = {
    "RS256": hashes.SHA256,
    "RS384": hashes.SHA384,
    "RS512": hashes.SHA512,
}

PSS_ALGORITHMS = {
    "PS256": hashes.SHA256,
    "PS384": hashes.SHA384,
    "PS512": hashes.SHA512,
}


def get_verification_hint(jwt_token):
    parts = jwt_token.strip().split('.')
    if len(parts) != 3:
        return "Hint: invalid token format", "Verification Secret / Public Key"

    try:
        header_obj = decode_part_object(parts[0])
    except Exception:
        return "Hint: cannot decode JWT header", "Verification Secret / Public Key"

    alg = str(header_obj.get("alg", "")).upper()
    if alg in HMAC_ALGORITHMS:
        return f"Hint: alg={alg} expects shared secret text", "Verification Secret"
    if alg in RSA_ALGORITHMS:
        return f"Hint: alg={alg} expects RSA public key (PEM)", "Verification Public Key (PEM)"
    if alg in PSS_ALGORITHMS:
        return f"Hint: alg={alg} expects RSA-PSS public key (PEM)", "Verification Public Key (PEM)"
    if alg == "NONE":
        return "Hint: alg=none should have empty signature", "No key required"

    if alg:
        return f"Hint: alg={alg} is not currently supported", "Verification Secret / Public Key"
    return "Hint: JWT alg is missing", "Verification Secret / Public Key"

def decode_part(jwt_part):
    try:
        padded = pad_base64(jwt_part)
        decoded_bytes = base64.urlsafe_b64decode(padded)
        parsed_json = json.loads(decoded_bytes.decode('utf-8', errors='ignore'))
        return json.dumps(parsed_json, indent=4)
    except Exception as e:
        return f"[-] Decode Error: {e}"


def decode_part_object(jwt_part):
    padded = pad_base64(jwt_part)
    decoded_bytes = base64.urlsafe_b64decode(padded)
    return json.loads(decoded_bytes.decode('utf-8', errors='ignore'))
    
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


def _encode_signature(signature_bytes):
    return base64.urlsafe_b64encode(signature_bytes).decode('utf-8').rstrip('=')


def _decode_signature(signature_text):
    padded = pad_base64(signature_text)
    return base64.urlsafe_b64decode(padded)


def _verify_hmac_token(parts, alg, verification_key):
    digest = HMAC_ALGORITHMS.get(alg)
    if digest is None:
        return None

    if verification_key is None or verification_key == "":
        return False, "Secret is required for HMAC JWT verification"

    signing_input = f"{parts[0]}.{parts[1]}".encode('utf-8')
    expected_sig = _encode_signature(
        hmac.new(verification_key.encode('utf-8'), signing_input, digest).digest()
    )
    if hmac.compare_digest(expected_sig, parts[2]):
        return True, f"Valid {alg} signature"
    return False, f"Invalid {alg} signature"


def _verify_rsa_token(parts, alg, verification_key):
    hash_cls = RSA_ALGORITHMS.get(alg)
    if hash_cls is None:
        return None

    if verification_key is None or verification_key.strip() == "":
        return False, "Public key PEM is required for RSA JWT verification"

    try:
        public_key = serialization.load_pem_public_key(verification_key.encode('utf-8'))
    except Exception as e:
        return False, f"Invalid public key PEM: {e}"

    signing_input = f"{parts[0]}.{parts[1]}".encode('utf-8')
    try:
        signature = _decode_signature(parts[2])
    except Exception as e:
        return False, f"Invalid JWT signature encoding: {e}"

    try:
        public_key.verify(
            signature,
            signing_input,
            padding.PKCS1v15(),
            hash_cls(),
        )
        return True, f"Valid {alg} signature"
    except Exception:
        return False, f"Invalid {alg} signature"


def _verify_pss_token(parts, alg, verification_key):
    hash_cls = PSS_ALGORITHMS.get(alg)
    if hash_cls is None:
        return None

    if verification_key is None or verification_key.strip() == "":
        return False, "Public key PEM is required for RSA-PSS JWT verification"

    try:
        public_key = serialization.load_pem_public_key(verification_key.encode('utf-8'))
    except Exception as e:
        return False, f"Invalid public key PEM: {e}"

    signing_input = f"{parts[0]}.{parts[1]}".encode('utf-8')
    try:
        signature = _decode_signature(parts[2])
    except Exception as e:
        return False, f"Invalid JWT signature encoding: {e}"

    try:
        public_key.verify(
            signature,
            signing_input,
            padding.PSS(
                mgf=padding.MGF1(hash_cls()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hash_cls(),
        )
        return True, f"Valid {alg} signature"
    except Exception:
        return False, f"Invalid {alg} signature"


def verify_token(jwt_token, verification_key):
    parts = jwt_token.strip().split('.')
    if len(parts) != 3:
        return False, "Invalid token format"

    try:
        header_obj = decode_part_object(parts[0])
    except Exception as e:
        return False, f"Invalid JWT header: {e}"

    alg = str(header_obj.get("alg", "")).upper()
    if alg == "NONE":
        if parts[2] == "":
            return True, "Unsigned token with alg=none"
        return False, "alg=none token should not include a signature"

    hmac_result = _verify_hmac_token(parts, alg, verification_key)
    if hmac_result is not None:
        return hmac_result

    rsa_result = _verify_rsa_token(parts, alg, verification_key)
    if rsa_result is not None:
        return rsa_result

    pss_result = _verify_pss_token(parts, alg, verification_key)
    if pss_result is not None:
        return pss_result

    return False, f"Unsupported verification algorithm: {alg or 'missing alg'}"

def forge_token(header_json, payload_json):
    b64_header = encode_part(header_json)
    b64_payload = encode_part(payload_json)
    return f"{b64_header}.{b64_payload}."