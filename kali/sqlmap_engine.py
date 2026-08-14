# sqlmap_engine.py — sqlmap subprocess wrapper
# Pipes captured HTTP requests directly into sqlmap for automated SQL injection.
import shutil
import subprocess
import queue
import os
import tempfile

result_queue = queue.Queue()
is_running = False
_active_proc = None

SQLMAP_PATH = shutil.which("sqlmap") or shutil.which("sqlmap3")

# ---------------------------------------------------------------------------
# Injection techniques
# ---------------------------------------------------------------------------

TECHNIQUES = {
    "all":       "BEUSTQ",   # all techniques
    "boolean":   "B",
    "error":     "E",
    "union":     "U",
    "stacked":   "S",
    "time":      "T",
    "inline":    "Q",
}


def _stream_proc(proc):
    """Yield stdout lines from a running subprocess, emitting to result_queue."""
    global is_running
    for raw_line in proc.stdout:
        if not is_running:
            proc.terminate()
            break
        line = raw_line.rstrip()
        if not line:
            continue

        lower = line.lower()
        if any(k in lower for k in ("injectable", "sql injection", "payload:", "parameter")):
            result_queue.put(("FAIL", line))
        elif any(k in lower for k in ("error", "critical", "exception")):
            result_queue.put(("ERROR", line))
        elif any(k in lower for k in ("warning", "might")):
            result_queue.put(("WARN", line))
        elif any(k in lower for k in ("not injectable", "not vulnerable", "passed")):
            result_queue.put(("PASS", line))
        else:
            result_queue.put(("INFO", line))


def run_sqlmap_url(target_url, params=None, technique="all", level=1, risk=1,
                   extra_args=None, timeout=300):
    """Run sqlmap against a URL.

    Args:
        target_url: Full URL to test (query parameters in the URL are auto-detected).
        params:     Comma-separated parameter names to focus on, e.g. "id,user".
        technique:  One of 'all','boolean','error','union','stacked','time','inline'.
        level:      sqlmap level 1-5 (depth of tests).
        risk:       sqlmap risk 1-3 (aggressiveness).
        extra_args: Additional raw sqlmap arguments (list of strings).
        timeout:    Max seconds to wait.
    """
    global is_running, _active_proc
    is_running = True

    if not SQLMAP_PATH:
        result_queue.put(("ERROR", "sqlmap not found. Install with: sudo apt install sqlmap"))
        result_queue.put(("DONE", "sqlmap aborted."))
        is_running = False
        return

    tech_str = TECHNIQUES.get(technique, "BEUSTQ")
    cmd = [
        SQLMAP_PATH,
        "-u", target_url,
        "--batch",
        "--technique", tech_str,
        "--level", str(level),
        "--risk", str(risk),
        "--output-dir", tempfile.mkdtemp(prefix="sqlmap_netman_"),
    ]
    if params:
        cmd += ["-p", params]
    if extra_args:
        cmd += extra_args

    result_queue.put(("STATUS", f"sqlmap: {target_url} | technique={technique} level={level} risk={risk}"))

    try:
        _active_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=None,
        )
        _stream_proc(_active_proc)
        _active_proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        result_queue.put(("ERROR", f"sqlmap timed out after {timeout}s"))
        if _active_proc:
            _active_proc.kill()
    except Exception as exc:
        result_queue.put(("ERROR", f"sqlmap error: {exc}"))
    finally:
        _active_proc = None

    is_running = False
    result_queue.put(("DONE", "sqlmap scan complete."))


def run_sqlmap_request(raw_request, technique="all", level=1, risk=1,
                       extra_args=None, timeout=300):
    """Run sqlmap from a raw HTTP request string (as captured by NetMan proxy).

    The request is saved to a temp file and passed to sqlmap via -r.
    """
    global is_running, _active_proc
    is_running = True

    if not SQLMAP_PATH:
        result_queue.put(("ERROR", "sqlmap not found. Install with: sudo apt install sqlmap"))
        result_queue.put(("DONE", "sqlmap aborted."))
        is_running = False
        return

    # Write request to a temp file
    try:
        fd, req_path = tempfile.mkstemp(suffix=".txt", prefix="sqlmap_req_")
        with os.fdopen(fd, "w") as fh:
            fh.write(raw_request)
    except Exception as exc:
        result_queue.put(("ERROR", f"Could not write temp request file: {exc}"))
        is_running = False
        result_queue.put(("DONE", "sqlmap aborted."))
        return

    tech_str = TECHNIQUES.get(technique, "BEUSTQ")
    cmd = [
        SQLMAP_PATH,
        "-r", req_path,
        "--batch",
        "--technique", tech_str,
        "--level", str(level),
        "--risk", str(risk),
        "--output-dir", tempfile.mkdtemp(prefix="sqlmap_netman_"),
    ]
    if extra_args:
        cmd += extra_args

    result_queue.put(("STATUS", f"sqlmap: from raw request file | technique={technique} level={level} risk={risk}"))

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
        result_queue.put(("ERROR", f"sqlmap timed out after {timeout}s"))
        if _active_proc:
            _active_proc.kill()
    except Exception as exc:
        result_queue.put(("ERROR", f"sqlmap error: {exc}"))
    finally:
        _active_proc = None
        try:
            os.unlink(req_path)
        except Exception:
            pass

    is_running = False
    result_queue.put(("DONE", "sqlmap scan complete."))


def stop_sqlmap():
    global is_running, _active_proc
    is_running = False
    if _active_proc:
        try:
            _active_proc.terminate()
        except Exception:
            pass
