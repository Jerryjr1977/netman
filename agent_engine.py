#agent_engine
# NetMan Autonomous Agent Layer
# Integrates with ai_engine, mitm_proxy, intruder_engine, and the GUI.
# All operations are non-blocking — every AI call is dispatched on a
# daemon thread so the proxy path is never delayed.

import threading
import time
import re
import ai_engine

# ---------------------------------------------------------------------------
# Lightweight request classifier
# ---------------------------------------------------------------------------

_INTERESTING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_SENSITIVE_PATHS = re.compile(
    r"/(login|auth|admin|password|token|reset|register|upload|api|graphql|oauth|verify|confirm)",
    re.IGNORECASE,
)
_SENSITIVE_PARAMS = re.compile(
    r"(password|passwd|pass|token|secret|key|api_key|auth|session|csrf|jwt)",
    re.IGNORECASE,
)
_INJECTION_MARKERS = re.compile(
    r"(union\s+select|'--|%27|<script|javascript:|onerror=|onload=|\.\./|\\x00|0x[0-9a-f]{4,})",
    re.IGNORECASE,
)

def _classify_request(raw_request):
    """Return a dict describing why this request is interesting (or not).

    Returns:
        dict: {
            "method": str,
            "path": str,
            "host": str,
            "interesting": bool,
            "reasons": [str],
        }
    """
    lines = raw_request.replace('\r\n', '\n').splitlines()
    first = lines[0] if lines else ""
    parts = first.split(' ')
    method = parts[0].upper() if parts else "UNKNOWN"
    path = parts[1] if len(parts) > 1 else "/"

    host = ""
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break

    reasons = []
    if method in _INTERESTING_METHODS:
        reasons.append(f"Method {method} may mutate state")
    if _SENSITIVE_PATHS.search(path):
        reasons.append(f"Sensitive path: {path}")
    if _SENSITIVE_PARAMS.search(raw_request):
        reasons.append("Contains sensitive parameters (password/token/key/…)")
    if _INJECTION_MARKERS.search(raw_request):
        reasons.append("Possible injection payload detected")

    return {
        "method": method,
        "path": path,
        "host": host,
        "interesting": bool(reasons),
        "reasons": reasons,
    }


# ---------------------------------------------------------------------------
# NetManAgent class
# ---------------------------------------------------------------------------

class NetManAgent:
    """Autonomous agent that observes proxy traffic and orchestrates AI analysis.

    The agent never blocks the calling thread.  Every heavy operation
    (AI dispatch, multi-step reasoning) is offloaded to a daemon thread.
    """

    # Minimum seconds between AI submissions for the *same host* to avoid
    # flooding the AI quota during high-traffic sessions.
    _THROTTLE_SECONDS = 30

    def __init__(self):
        self.goal = ""
        # memory is a list of dicts — each entry records one observed event
        self.memory = []
        # tools maps human-readable names to callables; engines are registered
        # here so the agent can invoke them programmatically in future steps.
        self.tools = {
            "ai_analysis":   self._send_to_ai,
            "log_memory":    self._log_memory,
            "classify":      _classify_request,
        }
        # Per-host throttle: {host: last_submission_timestamp}
        self._last_submitted = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_goal(self, text):
        """Store the operator-defined goal and echo it into the AI console."""
        self.goal = text.strip()
        self._log_memory({"type": "goal", "text": self.goal})
        # Push a notice to the AI result queue so the GUI picks it up
        ai_engine.result_queue.put(
            f"[AGENT] Goal updated: {self.goal}\n{'-'*60}\n\n"
        )

    def process_request(self, raw_request, host=None):
        """Called for every proxied request.

        Classifies the request and, if interesting, dispatches AI analysis
        asynchronously.  Returns a short summary string (non-blocking).
        """
        if not raw_request:
            return ""

        info = _classify_request(raw_request)
        effective_host = host or info["host"] or "unknown"

        entry = {
            "type": "request",
            "host": effective_host,
            "method": info["method"],
            "path": info["path"],
            "text": raw_request,
            "reasons": info["reasons"],
        }
        self._log_memory(entry)

        if not info["interesting"]:
            return f"[AGENT] Skipped {info['method']} {info['path']} (not interesting)"

        summary = (
            f"[AGENT] Flagged {info['method']} {effective_host}{info['path']}"
            f" — {'; '.join(info['reasons'])}"
        )

        # Throttle per-host AI submissions
        if self._is_throttled(effective_host):
            return summary + " (AI throttled)"

        prompt = self._build_request_prompt(raw_request, effective_host, info)
        threading.Thread(
            target=self._send_to_ai,
            args=(prompt, effective_host),
            daemon=True,
        ).start()
        return summary

    def analyze_response(self, raw_request, raw_response):
        """Called after a repeater/proxy response is received.

        Performs a multi-step analysis:
          Step 1 — classify request
          Step 2 — build response-aware prompt and dispatch AI
        """
        if not raw_request or not raw_response:
            return ""

        info = _classify_request(raw_request)
        host = info["host"] or "unknown"

        entry = {
            "type": "response",
            "host": host,
            "request_snippet": raw_request[:200],
            "response_snippet": raw_response[:200],
        }
        self._log_memory(entry)

        if not info["interesting"]:
            return f"[AGENT] Response from {host} not flagged"

        prompt = self._build_response_prompt(raw_request, raw_response, host, info)
        threading.Thread(
            target=self._send_to_ai,
            args=(prompt, host),
            daemon=True,
        ).start()
        return f"[AGENT] Dispatched response analysis for {host}"

    def observe_intruder_result(self, result_data):
        """Called for each intruder result tuple inserted into the results table.

        result_data is the same tuple stored in intruder_response_db —
        (payload, status, length, time, location, match, full_body, skimmer_hits).
        """
        if not result_data:
            return

        try:
            payload    = result_data[0]
            status     = result_data[1]
            skimmer    = result_data[7] if len(result_data) > 7 else "N/A"
        except (IndexError, TypeError):
            return

        entry = {
            "type": "intruder_result",
            "payload": payload,
            "status": status,
            "skimmer": skimmer,
        }
        self._log_memory(entry)

        # Only alert on interesting status codes or skimmer hits
        interesting = (
            skimmer not in ("None", "N/A", "") or
            str(status) in ("200", "302", "500")
        )
        if not interesting:
            return

        host = self.goal or "intruder-target"
        prompt = (
            f"You are a web security assistant.\n"
            f"Agent goal: {self.goal or 'Find vulnerabilities'}\n\n"
            f"An intruder attack produced a notable result:\n"
            f"  Payload : {payload}\n"
            f"  Status  : {status}\n"
            f"  Skimmer : {skimmer}\n\n"
            f"What does this result indicate? Is it a vulnerability? "
            f"Give a concise one-paragraph assessment."
        )
        threading.Thread(
            target=self._send_to_ai,
            args=(prompt, host),
            daemon=True,
        ).start()

    def observe_exfil(self, data):
        """Called whenever data arrives in the exfil queue."""
        if not data:
            return

        entry = {"type": "exfil", "data": str(data)[:500]}
        self._log_memory(entry)

        host = self.goal or "exfil-target"
        prompt = (
            f"You are a web security assistant.\n"
            f"Agent goal: {self.goal or 'Monitor exfiltrated data'}\n\n"
            f"The following data was captured from a target via the exfil channel:\n\n"
            f"{str(data)[:800]}\n\n"
            f"Summarise what was leaked and assess the risk level in two sentences."
        )
        threading.Thread(
            target=self._send_to_ai,
            args=(prompt, host),
            daemon=True,
        ).start()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _log_memory(self, entry):
        """Thread-safe append to agent memory."""
        with self._lock:
            # Keep memory bounded to the last 500 entries
            if len(self.memory) >= 500:
                self.memory.pop(0)
            self.memory.append(entry)

    def _is_throttled(self, host):
        """Return True if we submitted an AI request for this host recently."""
        with self._lock:
            last = self._last_submitted.get(host, 0)
            if time.time() - last < self._THROTTLE_SECONDS:
                return True
            self._last_submitted[host] = time.time()
            return False

    def _send_to_ai(self, prompt_text, target_host="agent"):
        """Push an analysis event onto ai_engine.event_queue.

        This is intentionally synchronous from the caller's perspective
        but the actual AI call is handled by the engine's background loop.
        """
        ai_engine.event_queue.put({
            "event":   "manual_analysis",
            "target":  target_host,
            "payload": prompt_text,
        })

    def _build_request_prompt(self, raw_request, host, info):
        goal_context = f"Agent goal: {self.goal}\n\n" if self.goal else ""
        reasons = "\n".join(f"  - {r}" for r in info["reasons"])
        # Truncate very long requests to stay within token budgets
        truncated = raw_request[:2000] + ("…[truncated]" if len(raw_request) > 2000 else "")
        return (
            f"You are a web security assistant integrated into a MITM proxy.\n"
            f"{goal_context}"
            f"The agent flagged this HTTP request for the following reasons:\n"
            f"{reasons}\n\n"
            f"Raw request:\n{truncated}\n\n"
            f"Analyse for: SQL injection, XSS, auth bypass, IDOR, insecure "
            f"deserialization, sensitive data exposure, or other OWASP Top 10 issues. "
            f"Be concise and actionable."
        )

    def _build_response_prompt(self, raw_request, raw_response, host, info):
        goal_context = f"Agent goal: {self.goal}\n\n" if self.goal else ""
        truncated_req = raw_request[:1000] + ("…" if len(raw_request) > 1000 else "")
        truncated_res = raw_response[:1500] + ("…" if len(raw_response) > 1500 else "")
        return (
            f"You are a web security assistant integrated into a MITM proxy.\n"
            f"{goal_context}"
            f"Analyse this request/response pair for security issues.\n\n"
            f"REQUEST:\n{truncated_req}\n\n"
            f"RESPONSE:\n{truncated_res}\n\n"
            f"Identify information disclosure, error messages, weak headers, "
            f"session tokens in URLs, or any other vulnerabilities visible in "
            f"the response. Be concise."
        )
