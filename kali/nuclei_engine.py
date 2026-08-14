# nuclei_engine.py — nuclei subprocess wrapper
# Runs Nuclei CVE/misconfiguration template scans against a target URL.
import shutil
import subprocess
import queue
import re
import os

result_queue = queue.Queue()
is_running = False
_active_proc = None

NUCLEI_PATH = shutil.which("nuclei")

# ---------------------------------------------------------------------------
# Severity levels mapped to result_queue tags
# ---------------------------------------------------------------------------

SEVERITY_MAP = {
    "critical": "FAIL",
    "high":     "FAIL",
    "medium":   "WARN",
    "low":      "WARN",
    "info":     "INFO",
    "unknown":  "INFO",
}

# Regex to parse nuclei output lines:
# [timestamp] [template-id] [protocol] [severity] host
_FINDING_RE = re.compile(
    r"\[(?P<ts>[^\]]+)\]\s+\[(?P<tmpl>[^\]]+)\]\s+\[(?P<proto>[^\]]+)\]\s+\[(?P<sev>[^\]]+)\]\s+(?P<host>.+)"
)

# Template tag presets
TEMPLATE_TAGS = {
    "cves":     ["-tags", "cve"],
    "misconfig":["-tags", "misconfig"],
    "exposed":  ["-tags", "exposure"],
    "tech":     ["-tags", "tech"],
    "default":  [],           # no tag filter — all templates
}


def _stream_proc(proc):
    global is_running
    for raw_line in proc.stdout:
        if not is_running:
            proc.terminate()
            break
        line = raw_line.rstrip()
        if not line:
            continue

        m = _FINDING_RE.match(line)
        if m:
            sev = m.group("sev").lower()
            tag = SEVERITY_MAP.get(sev, "INFO")
            tmpl = m.group("tmpl")
            host = m.group("host")
            result_queue.put((tag, f"[{sev.upper()}] {tmpl} | {host}"))
        else:
            # Non-finding output (progress, errors)
            lower = line.lower()
            if "error" in lower or "fatal" in lower:
                result_queue.put(("ERROR", line))
            else:
                result_queue.put(("STATUS", line))


def run_nuclei_scan(target_url, template_set="default", severity_filter=None,
                    rate_limit=150, extra_args=None, timeout=600):
    """Run a Nuclei template scan against target_url.

    Args:
        target_url:      URL or host to scan.
        template_set:    One of 'cves', 'misconfig', 'exposed', 'tech', 'default'.
        severity_filter: Comma-separated severities to include, e.g. 'critical,high'.
                         None means all severities.
        rate_limit:      Max requests per second (default 150).
        extra_args:      Additional raw nuclei arguments (list of strings).
        timeout:         Max seconds to wait for the scan.
    """
    global is_running, _active_proc
    is_running = True

    if not NUCLEI_PATH:
        result_queue.put(("ERROR", "nuclei not found. Install from: https://github.com/projectdiscovery/nuclei"))
        result_queue.put(("DONE", "nuclei aborted."))
        is_running = False
        return

    tag_args = list(TEMPLATE_TAGS.get(template_set, []))

    cmd = [
        NUCLEI_PATH,
        "-u", target_url,
        "-rate-limit", str(rate_limit),
        "-no-color",
        "-silent",
    ] + tag_args

    if severity_filter:
        cmd += ["-severity", severity_filter]

    if extra_args:
        cmd += extra_args

    result_queue.put(("STATUS", f"nuclei: {target_url} | templates={template_set} | severity={severity_filter or 'all'}"))

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
        result_queue.put(("ERROR", f"nuclei timed out after {timeout}s"))
        if _active_proc:
            _active_proc.kill()
    except Exception as exc:
        result_queue.put(("ERROR", f"nuclei error: {exc}"))
    finally:
        _active_proc = None

    is_running = False
    result_queue.put(("DONE", "nuclei scan complete."))


def stop_nuclei_scan():
    global is_running, _active_proc
    is_running = False
    if _active_proc:
        try:
            _active_proc.terminate()
        except Exception:
            pass
