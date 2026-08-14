# john_engine.py — John the Ripper subprocess wrapper (400+ hash formats)
# Complements hashcat_engine for CPU-based cracking and unsupported GPU formats.
import shutil
import subprocess
import queue
import re
import os
import tempfile

result_queue = queue.Queue()
is_running = False
_active_proc = None

JOHN_PATH = shutil.which("john") or shutil.which("john-the-ripper")

# ---------------------------------------------------------------------------
# John format names
# ---------------------------------------------------------------------------

JOHN_FORMATS = {
    "md5":         "raw-md5",
    "sha1":        "raw-sha1",
    "sha256":      "raw-sha256",
    "sha512":      "raw-sha512",
    "ntlm":        "nt",
    "ntlmv2":      "netntlmv2",
    "bcrypt":      "bcrypt",
    "md5crypt":    "md5crypt",
    "sha512crypt": "sha512crypt",
    "descrypt":    "descrypt",
    "mysql":       "mysql",
    "mssql":       "mssql",
    "zip":         "pkzip",
    "pdf":         "pdf",
    "ssh":         "ssh",
    "wpa":         "wpapsk",
}

_CRACKED_RE = re.compile(r"^(.+?)\s+\((.+?)\)")


def _detect_format(hash_str):
    """Heuristic format detection from hash string."""
    h = hash_str.strip()
    if h.startswith("$2") and len(h) == 60:
        return "bcrypt"
    if h.startswith("$1$"):
        return "md5crypt"
    if h.startswith("$6$"):
        return "sha512crypt"
    if h.startswith("$5$"):
        return "sha256crypt"
    if re.match(r"^[0-9a-fA-F]{32}$", h):
        return "raw-md5"
    if re.match(r"^[0-9a-fA-F]{40}$", h):
        return "raw-sha1"
    if re.match(r"^[0-9a-fA-F]{64}$", h):
        return "raw-sha256"
    if re.match(r"^[0-9a-fA-F]{128}$", h):
        return "raw-sha512"
    return None


def _stream_proc(proc):
    global is_running
    for raw_line in proc.stdout:
        if not is_running:
            proc.terminate()
            break
        line = raw_line.rstrip()
        if not line:
            continue
        lower = line.lower()
        m = _CRACKED_RE.match(line)
        if m:
            result_queue.put(("FAIL", f"[CRACKED] password={m.group(1)} hash/user={m.group(2)}"))
        elif "no password hashes loaded" in lower:
            result_queue.put(("ERROR", line))
        elif "error" in lower:
            result_queue.put(("ERROR", line))
        elif "no" in lower and "cracked" in lower:
            result_queue.put(("PASS", line))
        else:
            result_queue.put(("INFO", line))


def run_john(hash_input, wordlist_path=None, fmt=None, rules=None,
             extra_args=None, timeout=3600):
    """Crack hashes with John the Ripper.

    Args:
        hash_input:   Path to a hash file OR a single hash/username:hash string.
        wordlist_path: Path to wordlist. If None, uses John's built-in wordlist.
        fmt:          John format name (key from JOHN_FORMATS or raw john string).
                      Auto-detected if None.
        rules:        Rule set name (e.g. 'best64', 'jumbo') or path to rules file.
        extra_args:   Additional raw john arguments (list of strings).
        timeout:      Max seconds to wait.
    """
    global is_running, _active_proc
    is_running = True

    if not JOHN_PATH:
        result_queue.put(("ERROR", "john not found. Install with: sudo apt install john"))
        result_queue.put(("DONE", "john aborted."))
        is_running = False
        return

    # Write single hash to temp file if needed
    hash_file = hash_input
    _tmp_file = None
    if not os.path.exists(hash_input):
        fd, _tmp_file = tempfile.mkstemp(suffix=".txt", prefix="john_hash_")
        with os.fdopen(fd, "w") as fh:
            fh.write(hash_input.strip() + "\n")
        hash_file = _tmp_file

    # Resolve format
    john_fmt = None
    if fmt:
        john_fmt = JOHN_FORMATS.get(fmt, fmt)
    else:
        sample = open(hash_file).readline().strip().split(":")[-1]
        john_fmt = _detect_format(sample)

    cmd = [JOHN_PATH, hash_file]
    if john_fmt:
        cmd += [f"--format={john_fmt}"]
    if wordlist_path and os.path.exists(wordlist_path):
        cmd += [f"--wordlist={wordlist_path}"]
    if rules:
        cmd += [f"--rules={rules}"]
    if extra_args:
        cmd += extra_args

    result_queue.put(("STATUS", f"john: format={john_fmt or 'auto'} wordlist={wordlist_path or 'built-in'}"))

    try:
        _active_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        _stream_proc(_active_proc)
        _active_proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        result_queue.put(("ERROR", f"john timed out after {timeout}s"))
        if _active_proc:
            _active_proc.kill()
    except Exception as exc:
        result_queue.put(("ERROR", f"john error: {exc}"))
    finally:
        _active_proc = None

    # Show cracked results via john --show
    if JOHN_PATH and hash_file and os.path.exists(hash_file):
        try:
            show_cmd = [JOHN_PATH, "--show", hash_file]
            if john_fmt:
                show_cmd += [f"--format={john_fmt}"]
            show_result = subprocess.run(show_cmd, capture_output=True, text=True, timeout=10)
            for line in show_result.stdout.splitlines():
                if line.strip() and "password hash" not in line.lower():
                    result_queue.put(("FAIL", f"[FOUND] {line.strip()}"))
        except Exception:
            pass

    if _tmp_file:
        try:
            os.unlink(_tmp_file)
        except Exception:
            pass

    is_running = False
    result_queue.put(("DONE", "john complete."))


def run_john_zip(zip_path, wordlist_path=None, timeout=3600):
    """Convenience: crack a password-protected ZIP file."""
    try:
        zip2john = shutil.which("zip2john")
        if not zip2john:
            result_queue.put(("ERROR", "zip2john not found. Install john-the-ripper extras."))
            result_queue.put(("DONE", "john aborted."))
            return

        fd, hash_file = tempfile.mkstemp(suffix=".txt", prefix="john_zip_")
        os.close(fd)
        result = subprocess.run([zip2john, zip_path], capture_output=True, text=True, timeout=30)
        with open(hash_file, "w") as fh:
            fh.write(result.stdout)

        run_john(hash_file, wordlist_path=wordlist_path, fmt="zip", timeout=timeout)
    finally:
        try:
            os.unlink(hash_file)
        except Exception:
            pass


def stop_john():
    global is_running, _active_proc
    is_running = False
    if _active_proc:
        try:
            _active_proc.terminate()
        except Exception:
            pass
