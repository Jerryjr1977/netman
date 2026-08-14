#skimmer_engine
import re

regex_rules = {
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "Password": r"(?i)(?:\"password\"|\"passwd\"|password|passwd)\s*[:=]\s*[\"']?([^\s&\"',}]+)",
    "JWT Token": r"Bearer\s+(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)",
    "C2 User-Agent": r"(?i)User-Agent:\s*(python-requests|curl|wget|powershell|Go-http-client|Java/)",
    "Suspicious B64 Cookie": r"(?i)Cookie:\s*.*?(?:session|id|auth|data)=([A-Za-z0-9+/]{50,}={0,2})",
    "URI Command Exec": r"(?i)(?:GET|POST)\s+/[^\s]*\?(?:cmd|exec|c|payload)=([^\s&]+)",
    "URI Command Exec": r"(?i)(?:GET|POST)\s+/[^\s]*\?(?:cmd|exec|c|payload)=([^\s&]+)",
    "API Key": r"(?i)(?:api_key|apikey|api-key)\s*[:=]\s*[\"']?([a-zA-Z0-9_\-]{20,})",
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "Private Key": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "SQL Error": r"(?i)(SQL syntax|mysql_fetch|ORA-[0-9]{4,}|pg_query|sqlite3|ODBC Driver)",
    "Stack Trace": r"(?i)(Traceback \(most recent|at [a-zA-Z]+\.java|System\.Exception)",
    "Internal IP": r"(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d{1,3}\.\d{1,3}",
    "SSRF Parameter": r"(?i)(?:url|redirect|next|dest|target)=(?:https?://|//)[^\s&]+",
    "Secret Token": r"(?i)(?:secret|token|auth_token|access_token)\s*[:=]\s*[\"']?([a-zA-Z0-9_\-]{16,})",
}

# Global set to track reported findings
reported_findings = set()

def scan_payload(payload_text):
    global reported_findings
    findings = []
    if not payload_text:
        return findings

    for label, pattern in regex_rules.items():
        try:
            matches = re.findall(pattern, payload_text)
            for match in set(matches):
                match_str = str(match)
                finding = f"[{label}] {match_str}"
                if len(match_str) > 3 and finding not in reported_findings:
                    findings.append(finding)
                    reported_findings.add(finding)
        except Exception:
            pass

    return findings

def reset_findings():
    global reported_findings
    reported_findings = set()