#skimmer_engine
import re

regex_rules = {
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "Password": r"(?i)(?:\"password\"|\"passwd\"|password|passwd)\s*[:=]\s*[\"']?([^\s&\"',}]+)",
    "JWT Token": r"Bearer\s+(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)",
    "C2 User-Agent": r"(?i)User-Agent:\s*(python-requests|curl|wget|powershell|Go-http-client|Java/)",
    "Suspicious B64 Cookie": r"(?i)Cookie:\s*.*?(?:session|id|auth|data)=([A-Za-z0-9+/]{50,}={0,2})",
    "URI Command Exec": r"(?i)(?:GET|POST)\s+/[^\s]*\?(?:cmd|exec|c|payload)=([^\s&]+)"
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
                if len(match) > 3 and finding not in reported_findings:
                    findings.append(finding)
                    reported_findings.add(finding)
        except Exception:
            pass

    return findings