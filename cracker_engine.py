#cracker_engine
# NetMan - For authorized security testing only.
# See DISCLAIMER.md in the project root before use.
import hashlib

def crack_md5(target_hash, wordlist_path):
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            word = line.strip()
            hashed_word = hashlib.md5(word.encode('utf-8')).hexdigest()
            if hashed_word == target_hash:
                return word
    return None
