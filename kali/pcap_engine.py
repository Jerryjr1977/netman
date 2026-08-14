import os
import shutil
import subprocess
from datetime import datetime
from decoder_engine import load_wordlist, brute_force_openssl, try_openssl_decrypt

OPENSSL_SALT_HEADER = b'Salted__'

HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT")
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_VENV_PYTHON = os.path.join(_CURRENT_DIR, ".venv", "bin", "python")
SCAPY_INSTALL_HINT = (
    'Scapy is not installed in this project environment. Run: '
    f'"{_VENV_PYTHON}" -m pip install scapy'
)

DOT11_EVENT_TYPES = {
    (0, 0): "ASSOC_REQ",
    (0, 1): "ASSOC_RESP",
    (0, 2): "REASSOC_REQ",
    (0, 3): "REASSOC_RESP",
    (0, 4): "PROBE_REQ",
    (0, 5): "PROBE_RESP",
    (0, 10): "DISASSOC",
    (0, 11): "AUTH",
    (0, 12): "DEAUTH",
}

RSN_AKM_NAMES = {
    1: "802.1X",
    2: "PSK",
    3: "FT-802.1X",
    4: "FT-PSK",
    5: "802.1X-SHA256",
    6: "PSK-SHA256",
    8: "SAE",
}

RSN_CIPHER_NAMES = {
    1: "WEP-40",
    2: "TKIP",
    4: "CCMP",
    5: "WEP-104",
    6: "BIP",
    8: "GCMP",
    9: "GCMP-256",
    10: "CCMP-256",
}


def _safe_decode(value):
    if value is None:
        return ""
    try:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore")
        return str(value)
    except Exception:
        return ""


def _format_ts(pkt):
    try:
        return datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S")
    except Exception:
        return "--:--:--"


def _extract_channel_and_security(pkt, dot11_elt_cls):
    ssid = "<Hidden>"
    channel = "?"
    rsn_info = None
    wpa_present = False

    elt = pkt.getlayer(dot11_elt_cls)
    while elt is not None:
        try:
            eid = int(getattr(elt, "ID", -1))
            info = bytes(getattr(elt, "info", b""))
        except Exception:
            eid = -1
            info = b""

        if eid == 0:
            decoded = _safe_decode(info)
            ssid = decoded if decoded else "<Hidden>"
        elif eid == 3 and len(info) >= 1:
            channel = str(info[0])
        elif eid == 48:
            rsn_info = info
        elif eid == 221 and info.startswith(b"\x00P\xf2\x01"):
            wpa_present = True

        elt = elt.payload if isinstance(getattr(elt, "payload", None), dot11_elt_cls) else None

    privacy = False
    try:
        beacon = pkt.getlayer("Dot11Beacon")
        cap = _safe_decode(getattr(beacon, "cap", "")).lower()
        privacy = "privacy" in cap
    except Exception:
        privacy = False

    security, pairwise, akm = _classify_security(rsn_info, wpa_present, privacy)
    return ssid, channel, security, pairwise, akm


def _parse_rsn_info(rsn_info):
    if not rsn_info or len(rsn_info) < 8:
        return set(), set()

    pos = 2  # RSN version
    pairwise = set()
    akm = set()

    # Group cipher suite
    if len(rsn_info) < pos + 4:
        return pairwise, akm
    pos += 4

    # Pairwise cipher suites
    if len(rsn_info) < pos + 2:
        return pairwise, akm
    pairwise_count = int.from_bytes(rsn_info[pos : pos + 2], "little")
    pos += 2
    for _ in range(pairwise_count):
        if len(rsn_info) < pos + 4:
            return pairwise, akm
        if rsn_info[pos : pos + 3] == b"\x00\x0f\xac":
            pairwise.add(RSN_CIPHER_NAMES.get(rsn_info[pos + 3], f"cipher-{rsn_info[pos + 3]}"))
        pos += 4

    # AKM suites
    if len(rsn_info) < pos + 2:
        return pairwise, akm
    akm_count = int.from_bytes(rsn_info[pos : pos + 2], "little")
    pos += 2
    for _ in range(akm_count):
        if len(rsn_info) < pos + 4:
            return pairwise, akm
        if rsn_info[pos : pos + 3] == b"\x00\x0f\xac":
            akm.add(RSN_AKM_NAMES.get(rsn_info[pos + 3], f"akm-{rsn_info[pos + 3]}"))
        pos += 4

    return pairwise, akm


def _classify_security(rsn_info, wpa_present, privacy):
    pairwise, akm = _parse_rsn_info(rsn_info)

    if rsn_info:
        if "SAE" in akm:
            return "WPA3/SAE", pairwise, akm
        return "WPA2/RSN", pairwise, akm
    if wpa_present:
        return "WPA", pairwise, akm
    if privacy:
        return "WEP or legacy protected", pairwise, akm
    return "OPEN", pairwise, akm


def _handshake_quality(frame_count, from_ap, from_client):
    if frame_count >= 4 and from_ap >= 2 and from_client >= 2:
        return "good (likely full 4-way)"
    if frame_count >= 2 and from_ap > 0 and from_client > 0:
        return "partial (bi-directional)"
    if frame_count >= 2:
        return "weak (single-direction)"
    return "very weak"


def _dot11_is_protected(pkt):
    try:
        fc_field = int(getattr(pkt, "FCfield", 0))
    except Exception:
        return False
    return bool(fc_field & 0x40)


def _build_wifi_visibility_summary(packets):
    try:
        from scapy.all import DNS, Dot11, EAPOL, IP, IPv6, Raw, TCP, UDP  # type: ignore
    except Exception:
        return []

    counts = {
        "mgmt": 0,
        "control": 0,
        "data": 0,
        "protected_data": 0,
        "eapol": 0,
        "ip": 0,
        "ipv6": 0,
        "tcp": 0,
        "udp": 0,
        "dns": 0,
        "http_like": 0,
        "tls_like": 0,
    }

    for pkt in packets:
        if pkt.haslayer(Dot11):
            dot11 = pkt[Dot11]
            if dot11.type == 0:
                counts["mgmt"] += 1
            elif dot11.type == 1:
                counts["control"] += 1
            elif dot11.type == 2:
                counts["data"] += 1
                if _dot11_is_protected(dot11):
                    counts["protected_data"] += 1

        if pkt.haslayer(EAPOL):
            counts["eapol"] += 1
        if pkt.haslayer(IP):
            counts["ip"] += 1
        if pkt.haslayer(IPv6):
            counts["ipv6"] += 1
        if pkt.haslayer(TCP):
            counts["tcp"] += 1
            tcp = pkt[TCP]
            if tcp.sport in (443, 8443, 9443) or tcp.dport in (443, 8443, 9443):
                counts["tls_like"] += 1
        if pkt.haslayer(UDP):
            counts["udp"] += 1
        if pkt.haslayer(DNS):
            counts["dns"] += 1

        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                text = bytes(pkt[Raw].load).decode("utf-8", errors="ignore")
            except Exception:
                text = ""
            if text and _looks_like_http_request(text):
                counts["http_like"] += 1

    if counts["http_like"] > 0:
        visibility = "readable application-layer traffic visible"
        detail = "HTTP request payloads are present in the capture."
    elif counts["ip"] > 0 or counts["ipv6"] > 0:
        visibility = "decrypted network-layer traffic visible"
        detail = "Inner IP/TCP/UDP layers are visible, even if most app data is encrypted."
    elif counts["protected_data"] > 0 or counts["data"] > 0:
        visibility = "wireless data frames visible, but payloads are mostly encrypted"
        detail = "You can see 802.11 data traffic, but not much decrypted inner network content."
    elif counts["mgmt"] > 0 or counts["control"] > 0 or counts["eapol"] > 0:
        visibility = "management/control traffic only"
        detail = "This capture mostly exposes discovery, association, and handshake activity."
    else:
        visibility = "unknown or minimal protocol visibility"
        detail = "Scapy did not identify enough layers to classify the payload visibility clearly."

    observed = []
    if counts["mgmt"]:
        observed.append(f"mgmt={counts['mgmt']}")
    if counts["control"]:
        observed.append(f"control={counts['control']}")
    if counts["data"]:
        observed.append(f"data={counts['data']}")
    if counts["protected_data"]:
        observed.append(f"protected={counts['protected_data']}")
    if counts["eapol"]:
        observed.append(f"eapol={counts['eapol']}")
    if counts["ip"]:
        observed.append(f"ip={counts['ip']}")
    if counts["ipv6"]:
        observed.append(f"ipv6={counts['ipv6']}")
    if counts["tcp"]:
        observed.append(f"tcp={counts['tcp']}")
    if counts["udp"]:
        observed.append(f"udp={counts['udp']}")
    if counts["dns"]:
        observed.append(f"dns={counts['dns']}")
    if counts["tls_like"]:
        observed.append(f"tls-like={counts['tls_like']}")
    if counts["http_like"]:
        observed.append(f"http-like={counts['http_like']}")

    observed_line = ", ".join(observed) if observed else "no major protocol layers identified"

    return [
        f"[CAPTURE TYPE] {visibility}",
        f"[CAPTURE DETAIL] {detail}",
        f"[CAPTURE OBSERVED] {observed_line}",
    ]

def extract_wifi_details_from_pcap(file_path):
    try:
        from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt, EAPOL, RadioTap
    except ImportError:
        return [], SCAPY_INSTALL_HINT

    findings = []
    seen_aps = set()
    handshake_stats = {}
    timeline = []
    max_timeline = 120

    try:
        packets = rdpcap(file_path)
    except Exception as e:
        return [], f"Error reading PCAP: {e}"

    findings.extend(_build_wifi_visibility_summary(packets))

    for pkt in packets:
        # Logic: Find Access Points (APs)
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr3
            if bssid not in seen_aps:
                ssid, channel, security, pairwise, akm = _extract_channel_and_security(pkt, Dot11Elt)
                rssi = "?"
                if pkt.haslayer(RadioTap):
                    rssi_value = getattr(pkt[RadioTap], "dBm_AntSignal", None)
                    if isinstance(rssi_value, int):
                        rssi = str(rssi_value)

                detail_parts = [
                    f"[AP FOUND] SSID: {ssid}",
                    f"BSSID: {bssid}",
                    f"SEC: {security}",
                    f"CH: {channel}",
                    f"RSSI: {rssi}",
                ]
                if pairwise:
                    detail_parts.append("CIPHERS: " + ",".join(sorted(pairwise)))
                if akm:
                    detail_parts.append("AKM: " + ",".join(sorted(akm)))

                findings.append(" | ".join(detail_parts))
                seen_aps.add(bssid)

        # Logic: Find Reconnection Handshakes
        elif pkt.haslayer(EAPOL):
            dot11 = pkt[Dot11]
            bssid = dot11.addr3 or "unknown"
            sender = dot11.addr2 or "unknown"
            receiver = dot11.addr1 or "unknown"

            if sender == bssid:
                client = receiver
                direction = "AP->Client"
            else:
                client = sender
                direction = "Client->AP"

            key = (bssid, client)
            stat = handshake_stats.setdefault(
                key,
                {"frames": 0, "from_ap": 0, "from_client": 0},
            )
            stat["frames"] += 1
            if direction == "AP->Client":
                stat["from_ap"] += 1
            else:
                stat["from_client"] += 1

            findings.append(
                f"[EAPOL] {direction} | Client {client} | AP {bssid}"
            )

        if pkt.haslayer(Dot11):
            dot11 = pkt[Dot11]
            event_name = DOT11_EVENT_TYPES.get((dot11.type, dot11.subtype))
            if event_name and len(timeline) < max_timeline:
                timeline.append(
                    f"[EVENT {event_name}] t={_format_ts(pkt)} src={dot11.addr2 or 'unknown'} "
                    f"dst={dot11.addr1 or 'unknown'} bssid={dot11.addr3 or 'unknown'}"
                )

    if handshake_stats:
        findings.append("[HANDSHAKE SUMMARY]")
        for (bssid, client), stat in sorted(
            handshake_stats.items(),
            key=lambda item: item[1]["frames"],
            reverse=True,
        ):
            quality = _handshake_quality(stat["frames"], stat["from_ap"], stat["from_client"])
            findings.append(
                f"[HS QUALITY] Client {client} | AP {bssid} | frames={stat['frames']} "
                f"(ap={stat['from_ap']}, client={stat['from_client']}) | {quality}"
            )

    if timeline:
        findings.append(f"[EVENT TIMELINE] showing {len(timeline)} event(s)")
        findings.extend(timeline)

    return findings, ""


def _build_protocol_summary(file_path, sample_limit=15000):
    try:
        from scapy.all import ARP, DNS, Dot11, EAPOL, ICMP, IP, IPv6, TCP, UDP, rdpcap  # type: ignore
    except Exception:
        return ""

    try:
        packets = rdpcap(file_path, count=sample_limit)
    except Exception:
        return ""

    if not packets:
        return ""

    counts = {
        "total": len(packets),
        "dot11": 0,
        "eapol": 0,
        "ip": 0,
        "ipv6": 0,
        "tcp": 0,
        "udp": 0,
        "dns": 0,
        "arp": 0,
        "icmp": 0,
        "tls_like": 0,
    }

    for pkt in packets:
        if pkt.haslayer(Dot11):
            counts["dot11"] += 1
        if pkt.haslayer(EAPOL):
            counts["eapol"] += 1
        if pkt.haslayer(IP):
            counts["ip"] += 1
        if pkt.haslayer(IPv6):
            counts["ipv6"] += 1
        if pkt.haslayer(TCP):
            counts["tcp"] += 1
            tcp = pkt[TCP]
            if tcp.sport in (443, 8443, 9443) or tcp.dport in (443, 8443, 9443):
                counts["tls_like"] += 1
        if pkt.haslayer(UDP):
            counts["udp"] += 1
        if pkt.haslayer(DNS):
            counts["dns"] += 1
        if pkt.haslayer(ARP):
            counts["arp"] += 1
        if pkt.haslayer(ICMP):
            counts["icmp"] += 1

    return (
        "\n\nCapture summary (sampled):"
        f"\n- total packets: {counts['total']}"
        f"\n- 802.11 frames: {counts['dot11']}"
        f"\n- EAPOL frames: {counts['eapol']}"
        f"\n- IP packets: {counts['ip']}"
        f"\n- IPv6 packets: {counts['ipv6']}"
        f"\n- TCP packets: {counts['tcp']}"
        f"\n- UDP packets: {counts['udp']}"
        f"\n- DNS packets: {counts['dns']}"
        f"\n- ARP packets: {counts['arp']}"
        f"\n- ICMP packets: {counts['icmp']}"
        f"\n- likely TLS TCP packets (443/8443/9443): {counts['tls_like']}"
    )


def _looks_like_http_request(text):
    first_line = text.split("\r\n", 1)[0].split("\n", 1)[0].strip()
    if not first_line:
        return False
    return any(first_line.startswith(method + " ") for method in HTTP_METHODS) and " HTTP/" in first_line

def _extract_plain_http_requests(file_path, max_requests):
    try:
        from scapy.all import IP, IPv6, TCP, Raw, rdpcap  # type: ignore
    except Exception:
        return [], SCAPY_INSTALL_HINT

    requests = []
    seen = set()

    try:
        packets = rdpcap(file_path)
    except Exception as exc:
        return [], f"Failed to read PCAP: {exc}"

    for pkt in packets:
        if len(requests) >= max_requests:
            break

        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            continue

        raw_bytes = bytes(pkt[Raw].load)
        if raw_bytes.startswith(OPENSSL_SALT_HEADER):
            salt = raw_bytes[8:16]
            decrypted = try_openssl_decrypt(raw_bytes, "password123")
            if decrypted:
                requests.append(f"[DECRYPTED OPENSSL] {decrypted}")
                continue
            _script_dir = os.path.dirname(os.path.abspath(__file__))
            _default_wordlist = os.path.join(_script_dir, "100k_passwords.txt")
            _wordlist_path = _default_wordlist if os.path.exists(_default_wordlist) else "passwords.txt"
            passwords = load_wordlist(_wordlist_path)
            pwd, decrypted = brute_force_openssl(raw_bytes, passwords)
            if pwd:
                    requests.append(f"[CRACKED] Pwd: {pwd} | Data: {decrypted}")
        try:
            text = raw_bytes.decode("utf-8", errors="ignore")
        except Exception:
            continue

        if not _looks_like_http_request(text):
            continue

        host = ""
        for line in text.splitlines():
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break

        src = ""
        dst = ""
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst

        sig = (src, dst, pkt[TCP].sport, pkt[TCP].dport, text[:220])
        if sig in seen:
            continue
        seen.add(sig)

        cleaned = text.replace("\x00", "").strip()
        if not cleaned:
            continue

        if host and "\nHost:" not in cleaned and "\r\nHost:" not in cleaned:
            cleaned = cleaned + f"\nHost: {host}"

        requests.append(cleaned)

    return requests, ""


def _extract_tls_http_requests_with_keylog(file_path, tls_keylog_path, max_requests):
    if not tls_keylog_path:
        return [], ""

    if not os.path.exists(tls_keylog_path):
        return [], "TLS key log file not found."

    tshark_path = shutil.which("tshark")
    if tshark_path is None:
        return [], "tshark is required for TLS decryption. Install Wireshark/tshark first."

    cmd = [
        tshark_path,
        "-r",
        file_path,
        "-o",
        f"tls.keylog_file:{tls_keylog_path}",
        "-Y",
        "http.request",
        "-T",
        "fields",
        "-E",
        "separator=\\t",
        "-e",
        "ip.src",
        "-e",
        "tcp.srcport",
        "-e",
        "ip.dst",
        "-e",
        "tcp.dstport",
        "-e",
        "http.request.method",
        "-e",
        "http.host",
        "-e",
        "http.request.uri",
        "-e",
        "http.request.version",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except Exception as exc:
        return [], f"Failed to execute tshark: {exc}"

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        if stderr:
            return [], f"TLS decryption failed: {stderr}"
        return [], "TLS decryption failed while processing PCAP."

    requests = []
    seen = set()
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 8:
            continue

        src, sport, dst, dport, method, host, uri, version = [p.strip() for p in parts[:8]]
        if not method or not version:
            continue

        if len(requests) >= max_requests:
            break

        if not uri:
            uri = "/"

        if not host:
            host = dst

        request_text = f"{method} {uri} {version}\nHost: {host}\n"
        sig = (src, sport, dst, dport, request_text)
        if sig in seen:
            continue
        seen.add(sig)
        requests.append(request_text)

    return requests, ""


def extract_http_requests_from_pcap(file_path, max_requests=5000, tls_keylog_path=None):
    if not os.path.exists(file_path):
        return [], "PCAP file not found."

    requests, error_msg = _extract_plain_http_requests(file_path, max_requests)
    if error_msg:
        return [], error_msg

    if requests:
        return requests, ""

    if tls_keylog_path:
        tls_requests, tls_error = _extract_tls_http_requests_with_keylog(
            file_path,
            tls_keylog_path,
            max_requests,
        )
        if tls_error:
            return [], tls_error
        if tls_requests:
            return tls_requests, ""

    summary = _build_protocol_summary(file_path)

    if tls_keylog_path:
        return [], (
            "No HTTP requests found, even after TLS key log decryption."
            + summary
        )

    return [], (
        "No HTTP requests were found in this PCAP. "
        "If capture is HTTPS, retry import with a TLS key log file."
        + summary
    )


# ---------------------------------------------------------------------------
# tshark-powered analysis helpers
# ---------------------------------------------------------------------------

def export_http_objects(file_path, output_dir=None):
    """Extract all HTTP transferred files (images, scripts, downloads, etc.)
    from a PCAP using tshark --export-objects.

    Files are saved into output_dir (defaults to a 'http_objects' folder next
    to the PCAP).  Returns (output_dir, error_message).
    """
    if not os.path.exists(file_path):
        return None, "PCAP file not found."

    tshark_path = shutil.which("tshark")
    if tshark_path is None:
        return None, "tshark is required. Install Wireshark/tshark first."

    if not output_dir:
        output_dir = os.path.join(
            os.path.dirname(os.path.abspath(file_path)), "http_objects"
        )
    os.makedirs(output_dir, exist_ok=True)

    cmd = [tshark_path, "-r", file_path, "--export-objects", f"http,{output_dir}"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except Exception as exc:
        return None, f"tshark export-objects failed: {exc}"

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        return None, f"tshark export-objects error: {stderr}" if stderr else "tshark export-objects failed."

    exported = []
    try:
        exported = os.listdir(output_dir)
    except Exception:
        pass

    if not exported:
        return output_dir, "No HTTP objects found in this PCAP."

    return output_dir, ""


def follow_tcp_stream(file_path, stream_index=0):
    """Reconstruct a full TCP stream conversation from a PCAP using tshark.

    Returns (text, error_message).  text contains the raw ASCII conversation.
    Increment stream_index to step through multiple TCP flows in the capture.
    """
    if not os.path.exists(file_path):
        return "", "PCAP file not found."

    tshark_path = shutil.which("tshark")
    if tshark_path is None:
        return "", "tshark is required. Install Wireshark/tshark first."

    cmd = [
        tshark_path,
        "-r", file_path,
        "-z", f"follow,tcp,ascii,{stream_index}",
        "-q",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except Exception as exc:
        return "", f"tshark follow-stream failed: {exc}"

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        return "", f"tshark follow-stream error: {stderr}" if stderr else "tshark follow-stream failed."

    output = result.stdout.strip()
    if not output:
        return "", f"No data found for TCP stream {stream_index}."

    return output, ""


def get_protocol_stats(file_path):
    """Return protocol hierarchy and TCP conversation statistics for a PCAP.

    Uses tshark -z io,phs and -z conv,tcp.
    Returns (stats_text, error_message).
    """
    if not os.path.exists(file_path):
        return "", "PCAP file not found."

    tshark_path = shutil.which("tshark")
    if tshark_path is None:
        return "", "tshark is required. Install Wireshark/tshark first."

    sections = []

    for label, z_arg in [
        ("Protocol Hierarchy", "io,phs"),
        ("TCP Conversations", "conv,tcp"),
        ("UDP Conversations", "conv,udp"),
    ]:
        cmd = [tshark_path, "-r", file_path, "-z", z_arg, "-q"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
            text = result.stdout.strip()
            if text:
                sections.append(f"=== {label} ===\n{text}")
        except subprocess.TimeoutExpired:
            sections.append(f"=== {label} === [timed out]")
        except Exception as exc:
            sections.append(f"=== {label} === [error: {exc}]")

    if not sections:
        return "", "tshark returned no statistics."

    return "\n\n".join(sections), ""


def export_packets_json(file_path, max_packets=1000):
    """Export up to max_packets packets from a PCAP as a JSON string via tshark.

    The JSON structure matches tshark -T json output and can be parsed for
    building a structured packet inspector.  Returns (json_text, error_message).
    """
    if not os.path.exists(file_path):
        return "", "PCAP file not found."

    tshark_path = shutil.which("tshark")
    if tshark_path is None:
        return "", "tshark is required. Install Wireshark/tshark first."

    cmd = [tshark_path, "-r", file_path, "-T", "json", "-c", str(max_packets)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=120)
    except subprocess.TimeoutExpired:
        return "", "tshark JSON export timed out."
    except Exception as exc:
        return "", f"tshark JSON export failed: {exc}"

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        return "", f"tshark JSON export error: {stderr}" if stderr else "tshark JSON export failed."

    output = result.stdout.strip()
    if not output:
        return "", "tshark returned empty JSON output."

    return output, ""
