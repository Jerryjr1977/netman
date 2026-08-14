#cracker_engine
import hashlib


HASH_ALGORITHMS = {
    "md5":        (hashlib.md5,     32),
    "sha1":       (hashlib.sha1,    40),
    "sha224":     (hashlib.sha224,  56),
    "sha256":     (hashlib.sha256,  64),
    "sha384":     (hashlib.sha384,  96),
    "sha512":     (hashlib.sha512,  128),
    "sha3_256":   (hashlib.sha3_256, 64),
    "sha3_512":   (hashlib.sha3_512, 128),
    "blake2b":    (hashlib.blake2b, 128),
    "blake2s":    (hashlib.blake2s, 64),
}

# NTLM hashes are MD4 over UTF-16LE — hashlib exposes MD4 via openssl on most systems
def _ntlm_hash(word):
    import hashlib
    try:
        h = hashlib.new("md4", word.encode("utf-16-le"))
        return h.hexdigest()
    except ValueError:
        return None


def detect_hash_algorithm(target_hash):
    normalized = target_hash.strip().lower()
    if not normalized:
        return None

    # NTLM detection: 32-char hex that is NOT a valid MD5 of any short word
    # — we can't distinguish from MD5 purely by length, so we label both
    length = len(normalized)
    if not all(ch in "0123456789abcdef" for ch in normalized):
        return None

    length_map = {
        32:  "md5",     # also could be NTLM — crack_hash tries both
        40:  "sha1",
        56:  "sha224",
        64:  "sha256",  # also sha3_256, blake2s
        96:  "sha384",
        128: "sha512",  # also sha3_512, blake2b
    }
    return length_map.get(length)


def crack_hash(target_hash, wordlist_path, algorithm=None):
    """Crack a hex hash against a wordlist.

    If algorithm is None, it is auto-detected by length.
    For 32-char hashes, both MD5 and NTLM are tried.
    Returns (plaintext, algorithm_used) or (None, algorithm_attempted).
    """
    normalized = target_hash.strip().lower()
    selected = algorithm or detect_hash_algorithm(normalized)
    if not selected:
        raise ValueError(f"Unsupported or unrecognised hash length ({len(normalized)} chars).")

    candidates = [selected]
    # For 32-char hashes also try NTLM; for 64-char also try sha3_256 / blake2s
    if selected == "md5":
        candidates.append("ntlm")
    elif selected == "sha256":
        candidates += ["sha3_256", "blake2s"]
    elif selected == "sha512":
        candidates += ["sha3_512", "blake2b"]

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        words = [line.strip() for line in f if line.strip()]

    for algo in candidates:
        if algo == "ntlm":
            for word in words:
                digest = _ntlm_hash(word)
                if digest and digest == normalized:
                    return word, "ntlm"
        else:
            entry = HASH_ALGORITHMS.get(algo)
            if not entry:
                continue
            hash_func, _ = entry
            for word in words:
                try:
                    digest = hash_func(word.encode("utf-8")).hexdigest()
                except TypeError:
                    # blake2b/blake2s need digest_size keyword
                    digest = hash_func(word.encode("utf-8"), digest_size=HASH_ALGORITHMS[algo][1] // 2).hexdigest()
                if digest == normalized:
                    return word, algo

    return None, selected


def crack_md5(target_hash, wordlist_path):
    result, _algorithm = crack_hash(target_hash, wordlist_path, algorithm="md5")
    return result


def identify_hash(target_hash):
    """Return a human-readable description of what hash type(s) a string could be."""
    normalized = target_hash.strip().lower()
    if not normalized:
        return "empty input"
    if not all(ch in "0123456789abcdef" for ch in normalized):
        return "not a hex hash"
    descriptions = {
        32:  "MD5 or NTLM (32 hex chars)",
        40:  "SHA-1 (40 hex chars)",
        56:  "SHA-224 (56 hex chars)",
        64:  "SHA-256 / SHA3-256 / BLAKE2s (64 hex chars)",
        96:  "SHA-384 (96 hex chars)",
        128: "SHA-512 / SHA3-512 / BLAKE2b (128 hex chars)",
    }
    return descriptions.get(len(normalized), f"Unknown hash length ({len(normalized)} chars)")
