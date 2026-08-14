# nmap_engine.py — nmap subprocess wrapper with structured output
# Wraps the real nmap binary for service version detection, OS fingerprinting,
# and NSE vulnerability scripts. Falls back to the existing scanner_engine
# if nmap is not installed.
import shutil
import subprocess
import queue
import xml.etree.ElementTree as ET
import os

result_queue = queue.Queue()
is_running = False

NMAP_PATH = shutil.which("nmap")

# ---------------------------------------------------------------------------
# Scan profiles
# ---------------------------------------------------------------------------

SCAN_PROFILES = {
    "quick":   ["-T4", "-F"],                                   # top 100 ports, fast
    "service": ["-T4", "-sV", "--version-intensity", "5"],      # version detection
    "full":    ["-T4", "-p-", "-sV"],                           # all 65535 ports
    "vuln":    ["-T4", "-sV", "--script", "vuln"],              # NSE vuln scripts
    "os":      ["-T4", "-O", "-sV"],                            # OS fingerprinting
    "stealth": ["-T2", "-sS", "-sV"],                           # slower/quieter SYN scan
}


def _run_nmap(target, extra_args, timeout=300):
    """Run nmap with XML output, return parsed XML root or None."""
    if not NMAP_PATH:
        result_queue.put(("ERROR", "nmap not found. Install with: sudo apt install nmap"))
        return None

    cmd = [NMAP_PATH, "-oX", "-"] + extra_args + [target]
    result_queue.put(("STATUS", f"Running: {' '.join(cmd)}"))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        result_queue.put(("ERROR", f"nmap timed out after {timeout}s"))
        return None
    except Exception as exc:
        result_queue.put(("ERROR", f"nmap execution failed: {exc}"))
        return None

    if not proc.stdout.strip():
        stderr = proc.stderr.strip()
        if stderr:
            result_queue.put(("ERROR", f"nmap error: {stderr}"))
        return None

    try:
        return ET.fromstring(proc.stdout)
    except ET.ParseError as exc:
        result_queue.put(("ERROR", f"nmap XML parse error: {exc}"))
        return None


def _parse_host(host_el):
    """Parse a <host> element and emit result_queue entries."""
    # Address
    addr = host_el.findtext("address[@addrtype='ipv4']/@addr") or ""
    for addr_el in host_el.findall("address"):
        if addr_el.get("addrtype") in ("ipv4", "ipv6"):
            addr = addr_el.get("addr", "")
            break

    # Hostname
    hostname = ""
    hostnames_el = host_el.find("hostnames")
    if hostnames_el is not None:
        hn = hostnames_el.find("hostname")
        if hn is not None:
            hostname = hn.get("name", "")

    display = f"{addr} ({hostname})" if hostname else addr
    result_queue.put(("INFO", f"Host: {display}"))

    # Status
    status_el = host_el.find("status")
    if status_el is not None:
        result_queue.put(("INFO", f"  Status: {status_el.get('state', '?')} ({status_el.get('reason', '')})"))

    # OS
    os_el = host_el.find("os/osmatch")
    if os_el is not None:
        result_queue.put(("INFO", f"  OS: {os_el.get('name', '?')} (accuracy {os_el.get('accuracy', '?')}%)"))

    # Ports
    ports_el = host_el.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            port = port_el.get("portid", "?")
            proto = port_el.get("protocol", "tcp")
            state_el = port_el.find("state")
            state = state_el.get("state", "?") if state_el is not None else "?"
            if state != "open":
                continue
            svc_el = port_el.find("service")
            service = svc_el.get("name", "") if svc_el is not None else ""
            product = svc_el.get("product", "") if svc_el is not None else ""
            version = svc_el.get("version", "") if svc_el is not None else ""
            svc_str = " ".join(filter(None, [service, product, version]))

            result_queue.put(("PASS", f"  {proto}/{port} OPEN — {svc_str or 'unknown'}"))

            # NSE script output (vuln findings)
            for script_el in port_el.findall("script"):
                sid = script_el.get("id", "")
                out = script_el.get("output", "").strip()
                if out:
                    severity = "FAIL" if any(k in out.lower() for k in ("vulnerable", "exploit", "critical", "cve")) else "WARN"
                    result_queue.put((severity, f"    [{sid}] {out[:300]}"))

    # Host-level scripts
    for script_el in host_el.findall("hostscript/script"):
        sid = script_el.get("id", "")
        out = script_el.get("output", "").strip()
        if out:
            severity = "FAIL" if any(k in out.lower() for k in ("vulnerable", "exploit", "critical", "cve")) else "WARN"
            result_queue.put((severity, f"  [{sid}] {out[:300]}"))


def run_nmap_scan(target, profile="service", extra_args=None, timeout=300):
    """Run an nmap scan against target using a named profile.

    Args:
        target:     IP, hostname, or CIDR range.
        profile:    One of 'quick', 'service', 'full', 'vuln', 'os', 'stealth'.
        extra_args: Additional raw nmap arguments (list of strings).
        timeout:    Max seconds to wait.
    """
    global is_running
    is_running = True

    if not NMAP_PATH:
        result_queue.put(("ERROR", "nmap not found. Install with: sudo apt install nmap"))
        result_queue.put(("DONE", "nmap scan aborted."))
        is_running = False
        return

    args = list(SCAN_PROFILES.get(profile, SCAN_PROFILES["service"]))
    if extra_args:
        args += extra_args

    result_queue.put(("STATUS", f"nmap scan: target={target} profile={profile}"))
    root = _run_nmap(target, args, timeout=timeout)

    if root is None:
        is_running = False
        result_queue.put(("DONE", "nmap scan failed."))
        return

    for host_el in root.findall("host"):
        if not is_running:
            break
        _parse_host(host_el)

    run_stats = root.find("runstats/finished")
    if run_stats is not None:
        elapsed = run_stats.get("elapsed", "?")
        result_queue.put(("STATUS", f"nmap finished in {elapsed}s"))

    is_running = False
    result_queue.put(("DONE", "nmap scan complete."))


def stop_nmap_scan():
    global is_running
    is_running = False
