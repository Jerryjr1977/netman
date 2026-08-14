# hashcat_engine.py — hashcat subprocess wrapper (GPU-accelerated cracking)
# Supports all common hash types with auto-detection by length.
# WPA/WPA2 hashes (hc22000) from hcxtools are also supported.
import shutil
import subprocess
import queue
import re
import os

result_queue = queue.Queue()
is_running = False
_active_proc = None

HASHCAT_PATH = shutil.which("hashcat")

# ---------------------------------------------------------------------------
# Hash-mode map (hashcat -m value)
# ---------------------------------------------------------------------------

HASH_MODES = {
    "md5":       0,
    "sha1":      100,
    "sha256":    1400,
    "sha384":    10800,
    "sha512":    1700,
    "sha3_256":  17300,
    "sha3_512":  17600,
    "ntlm":      1000,
    "ntlmv2":    5600,
    "bcrypt":    3200,
    "wpa2":      22000,   # hc22000 PMKID+EAPOL (hcxtools output)
    "md5crypt":  500,     # $1$ unix crypt
    "sha512crypt":1800,   # $6$ unix crypt
    "mysql41":   300,
    "mssql":     131,
    "oracle11g": 112,
}

# Map hash length → most likely hashcat mode(s) to try
_AUTO_DETECT = {
    32:  [0, 1000],         # MD5 or NTLM
    40:  [100],             # SHA-1
    56:  [1410],            # SHA-224
    64:  [1400, 17300],     # SHA-256 or SHA3-256
    96:  [10800],           # SHA-384
    128: [1700, 17600],     # SHA-512 or SHA3-512
}

# Attack modes
ATTACK_MODES = {
    "wordlist":    0,
    "combination": 1,
    "brute":       3,
    "hybrid":      6,
}


def _detect_mode(hash_str):
    """Guess hashcat -m value from hash string."""
    h = hash_str.strip()
    if h.startswith("$2") and len(h) == 60:
        return [3200]   # bcrypt
    if h.startswith("$1$"):
        return [500]    # md5crypt
    if h.startswith("$6$"):
        return [1800]   # sha512crypt
    if h.startswith("$P$") or h.startswith("$H$"):
        return [400]    # phpass (WordPress)
    if re.match(r"^[0-9a-fA-F]{32}$", h):
        return [0, 1000]
    if re.match(r"^[0-9a-fA-F]{40}$", h):
        return [100]
    if re.match(r"^[0-9a-fA-F]{64}$", h):
        return [1400, 17300]
    if re.match(r"^[0-9a-fA-F]{128}$", h):
        return [1700, 17600]
    return [0]  # default MD5


def _stream_proc(proc):
    global is_running
    cracked_re = re.compile(r"^(.+):(.+)$")
    for raw_line in proc.stdout:
        if not is_running:
            proc.terminate()
            break
        line = raw_line.rstrip()
        if not line:
            continue
        lower = line.lower()
        if "cracked" in lower or "recovered" in lower:
            result_queue.put(("FAIL", f"[CRACKED] {line}"))
        elif "error" in lower or "warning" in lower:
            result_queue.put(("ERROR", line))
        elif "exhausted" in lower or "no hashes loaded" in lower:
            result_queue.put(("PASS", line))
        else:
            result_queue.put(("INFO", line))


def run_hashcat(hash_input, wordlist_path, hash_type=None, attack_mode="wordlist",
                rules=None, extra_args=None, timeout=3600):
    """Crack hash_input using hashcat.

    Args:
        hash_input:   Path to a file containing hashes, OR a single hash string.
        wordlist_path: Path to the wordlist file.
        hash_type:    Key from HASH_MODES (e.g. 'md5', 'wpa2') or raw int mode.
                      Auto-detected from hash length if None.
        attack_mode:  One of 'wordlist', 'combination', 'brute', 'hybrid'.
        rules:        Path to a hashcat rules file (e.g. /usr/share/hashcat/rules/best64.rule).
        extra_args:   Additional raw hashcat arguments (list of strings).
        timeout:      Max seconds to wait.
    """
    global is_running, _active_proc
    is_running = True

    if not HASHCAT_PATH:
        result_queue.put(("ERROR", "hashcat not found. Install with: sudo apt install hashcat"))
        result_queue.put(("DONE", "hashcat aborted."))
        is_running = False
        return

    # Resolve hash file or single hash
    hash_file = hash_input
    _tmp_file = None
    if not os.path.exists(hash_input):
        import tempfile
        fd, _tmp_file = tempfile.mkstemp(suffix=".txt", prefix="hc_hash_")
        with os.fdopen(fd, "w") as fh:
            fh.write(hash_input.strip() + "\n")
        hash_file = _tmp_file

    # Resolve hash mode
    if hash_type is None:
        sample = open(hash_file).readline().strip()
        modes = _detect_mode(sample)
    elif isinstance(hash_type, int):
        modes = [hash_type]
    else:
        modes = [HASH_MODES.get(hash_type, 0)]

    a_mode = ATTACK_MODES.get(attack_mode, 0)

    for mode in modes:
        if not is_running:
            break

        cmd = [
            HASHCAT_PATH,
            "-m", str(mode),
            "-a", str(a_mode),
            "--status",
            "--status-timer", "10",
            "--potfile-disable",
            hash_file,
            wordlist_path,
        ]
        if rules:
            cmd += ["-r", rules]
        if extra_args:
            cmd += extra_args

        result_queue.put(("STATUS", f"hashcat: mode={mode} attack={attack_mode} wordlist={wordlist_path}"))

        try:
            _active_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            _stream_proc(_active_proc)
            ret = _active_proc.wait(timeout=timeout)
            # hashcat returns 0 = cracked, 1 = exhausted, others = error
            if ret == 0:
                result_queue.put(("FAIL", f"hashcat: hash cracked (mode {mode})"))
                break
            elif ret == 1:
                result_queue.put(("PASS", f"hashcat: wordlist exhausted (mode {mode})"))
        except subprocess.TimeoutExpired:
            result_queue.put(("ERROR", f"hashcat timed out after {timeout}s"))
            if _active_proc:
                _active_proc.kill()
            break
        except Exception as exc:
            result_queue.put(("ERROR", f"hashcat error: {exc}"))
            break
        finally:
            _active_proc = None

    if _tmp_file:
        try:
            os.unlink(_tmp_file)
        except Exception:
            pass

    is_running = False
    result_queue.put(("DONE", "hashcat complete."))


def run_wpa_crack(pcap_hc22000_path, wordlist_path, extra_args=None, timeout=3600):
    """Convenience wrapper: crack a WPA2 hc22000 file (output of hcxtools)."""
    run_hashcat(
        pcap_hc22000_path,
        wordlist_path,
        hash_type="wpa2",
        extra_args=extra_args,
        timeout=timeout,
    )


def stop_hashcat():
    global is_running, _active_proc
    is_running = False
    if _active_proc:
        try:
            _active_proc.terminate()
        except Exception:
            pass
