import tkinter as tk
from tkinter import ttk
import threading
import re
import os
try:
    from .scanner import WifiScanner
    from .local_bridge import LocalBridge
except ImportError:
    from scanner import WifiScanner
    from local_bridge import LocalBridge

K_BLACK = "#0f0f0f"
K_DARK_GREY = "#1a1c1e"
K_BLUE = "#0087af"
K_TEXT = "#ffffff"
BRIDGE_AUTH_TOKEN = os.environ.get("WICRACK_NETMAN_BRIDGE_TOKEN", "wicrack-netman-local")

class WiCrackGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("WiCrack")
        self.root.geometry("700x500")
        self.root.configure(bg=K_BLACK)
        # Set Custom Window Icon
        icon_path = "/home/kali/WiCrack/wicrack_icon.png"
        if os.path.exists(icon_path):
            try:
                # Load the PNG file
                img = tk.PhotoImage(file=icon_path)
                # Set it as the window icon
                self.root.iconphoto(False, img)
            except Exception as e:
                print(f"[!] Error loading icon: {e}")
        self.scanner = None
        self.scan_thread = None
        self.hop_thread = None
        self.scan_stop_event = None
        self._closing = False
        self.bridge_status_var = tk.StringVar(value="Bridge: Offline")
        self.bridge = LocalBridge(
            "wicrack",
            on_message=self._on_bridge_message,
            on_status=self._on_bridge_status,
            auth_token=BRIDGE_AUTH_TOKEN,
        )
        bridge_ok = self.bridge.start()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self.header = tk.Label(
            root, 
            text="WiCrack :: Wireless Auditor", 
            bg=K_BLACK, 
            fg=K_BLUE, 
            font=("Courier", 16, "bold")
        )
        self.header.pack(pady=20)

        self.output = tk.Text(
            root, 
            height=15, 
            width=80, 
            bg=K_DARK_GREY, 
            fg="#00ff00",
            insertbackground="white",
            relief="flat",
            padx=10,
            pady=10
        )
        self.output.pack(pady=10)

        self.scan_btn = tk.Button(
            root, 
            text="START DISCOVERY", 
            command=self.on_scan_click,
            bg=K_BLUE, 
            fg=K_TEXT,
            activebackground=K_BLACK,
            activeforeground=K_BLUE,
            relief="flat",
            width=20
        )
        self.scan_btn.pack(pady=10)

        self.capture_var = tk.StringVar(value="Capture: not started")
        self.capture_label = tk.Label(
            root,
            textvariable=self.capture_var,
            bg=K_BLACK,
            fg=K_TEXT,
            font=("Courier", 10),
            anchor="w",
        )
        self.capture_label.pack(fill="x", padx=20)

        self.bridge_frame = tk.Frame(root, bg=K_BLACK)
        self.bridge_frame.pack(fill="x", padx=20, pady=(3, 0))

        self.bridge_status_label = tk.Label(
            self.bridge_frame,
            textvariable=self.bridge_status_var,
            bg=K_BLACK,
            fg="#ff5555",
            font=("Courier", 10),
            anchor="w",
        )
        self.bridge_status_label.pack(side=tk.LEFT)

        self.bridge_reconnect_btn = tk.Button(
            self.bridge_frame,
            text="Reconnect Bridge",
            command=self._manual_reconnect,
            bg="#2f5f8f",
            fg=K_TEXT,
            activebackground=K_BLACK,
            activeforeground=K_TEXT,
            relief="flat",
        )
        self.bridge_reconnect_btn.pack(side=tk.RIGHT)

        self.target_rows = {}

        self.target_table = ttk.Treeview(
            root,
            columns=("client", "vendor", "ap", "seen"),
            show="headings",
            height=6,
        )
        self.target_table.heading("client", text="Client MAC")
        self.target_table.heading("vendor", text="Vendor")
        self.target_table.heading("ap", text="AP BSSID")
        self.target_table.heading("seen", text="Seen")
        self.target_table.column("client", width=180, anchor="w")
        self.target_table.column("vendor", width=180, anchor="w")
        self.target_table.column("ap", width=180, anchor="w")
        self.target_table.column("seen", width=70, anchor="center")
        self.target_table.pack(pady=5, fill="x", padx=20)

        self.deauth_btn = tk.Button(
            root, 
            text="DEAUTH TARGET", 
            command=self.on_deauth_click,
            bg="#ff5555", 
            fg=K_TEXT,
            relief="flat"
        )
        self.deauth_btn.pack(pady=10)

        if bridge_ok:
            self.update_terminal("[*] Bridge online. Waiting for NetMan messages...\n")
        else:
            self.update_terminal("[!] Bridge unavailable. Running in standalone mode.\n")

        self.root.after(5000, self._bridge_watchdog)

    def _on_bridge_status(self, status):
        self.root.after(0, self._apply_bridge_status, status)

    def _apply_bridge_status(self, status):
        if status == "connected":
            self.bridge_status_var.set("Bridge: Connected")
            self.bridge_status_label.config(fg="#00ff88")
        elif status == "connecting":
            self.bridge_status_var.set("Bridge: Connecting")
            self.bridge_status_label.config(fg="#f7c948")
        elif status == "listening":
            self.bridge_status_var.set("Bridge: Listening")
            self.bridge_status_label.config(fg="#f7c948")
        elif status == "offline":
            self.bridge_status_var.set("Bridge: Offline")
            self.bridge_status_label.config(fg="#ff5555")
        else:
            self.bridge_status_var.set("Bridge: Disconnected")
            self.bridge_status_label.config(fg="#ff5555")

    def _manual_reconnect(self):
        ok = self.bridge.reconnect()
        if ok:
            self.update_terminal("[*] Bridge reconnected.\n")
        else:
            self.update_terminal("[!] Bridge reconnect failed.\n")

    def _bridge_watchdog(self):
        if self._closing:
            return
        if not self.bridge.connected:
            self.bridge.reconnect()
        self.root.after(5000, self._bridge_watchdog)

    def _on_close(self):
        self._closing = True
        if self.scan_stop_event is not None:
            self.scan_stop_event.set()
        if self.scanner is not None:
            self.scanner.close()
            self.scanner = None
        self.bridge.stop()
        self.root.destroy()

    def _on_bridge_message(self, message):
        self.root.after(0, self._handle_bridge_message, message)

    def _handle_bridge_message(self, message):
        source = message.get("source", "unknown")
        event_type = message.get("type", "")
        payload = message.get("payload", {})

        if source == "wicrack":
            return

        if event_type == "netman.command.deauth":
            client_mac = str(payload.get("client", "")).strip().lower()
            bssid = str(payload.get("bssid", "")).strip().lower()
            if client_mac and bssid:
                self.update_terminal(f"[*] NetMan requested deauth: {client_mac} on {bssid}\n")
                self._start_deauth(client_mac, bssid)
            else:
                self.update_terminal("[!] NetMan deauth command missing client/bssid.\n")
            return

        if event_type == "bridge.hello":
            app_name = payload.get("app", source)
            self.update_terminal(f"[*] Bridge peer online: {app_name}\n")
            return

        self.update_terminal(f"[*] Bridge message from {source}: {event_type}\n")

    def _start_deauth(self, client_mac, bssid):
        try:
            scanner = WifiScanner()
        except RuntimeError as e:
            self.update_terminal(f"[!] {e}\n")
            return

        attack_thread = threading.Thread(
            target=scanner.send_deauth,
            args=(client_mac, bssid),
            daemon=True
        )
        attack_thread.start()

        self.bridge.send(
            "wicrack.deauth.started",
            {
                "client": client_mac,
                "bssid": bssid,
            },
        )

    def on_deauth_click(self):
        selected = self.target_table.selection()
        if not selected:
            self.update_terminal("[!] Select a target row first.\n")
            return

        values = self.target_table.item(selected[0], "values")
        if len(values) < 3:
            self.update_terminal("[!] Invalid target selection.\n")
            return

        client_mac = values[0].lower()
        bssid = values[2].lower()

        self.output.insert(tk.END, f"[*] Attacking {client_mac} on {bssid}...\n")
        self._start_deauth(client_mac, bssid)

    def on_scan_click(self):
        if self.scanner is not None:
            self.output.insert(tk.END, "[*] Stopping scanner...\n")
            if self.scan_stop_event is not None:
                self.scan_stop_event.set()
            if self.scanner is not None:
                self.scanner.close()
            self.scanner = None
            self.scan_btn.config(text="START DISCOVERY", bg=K_BLUE, activeforeground=K_BLUE)
            self.capture_var.set("Capture: stopped")
            self.bridge.send("wicrack.scan.stopped", {})
            return

        self.output.insert(tk.END, "[*] Starting Scanner & Hopper...\n")
        try:
            scanner = WifiScanner(gui_callback=self.update_terminal)
        except RuntimeError as e:
            self.update_terminal(f"[!] {e}\n")
            return

        self.scanner = scanner
        self.scan_stop_event = threading.Event()
        current_capture = os.path.basename(scanner.get_capture_path())
        self.capture_var.set(f"Capture: {current_capture}")
        self.scan_btn.config(text="STOP DISCOVERY", bg="#ff5555", activeforeground=K_TEXT)
        self.bridge.send("wicrack.scan.started", {"capture": current_capture})
        
        self.hop_thread = threading.Thread(
            target=scanner.channel_hopper,
            kwargs={"stop_event": self.scan_stop_event},
            daemon=True,
        )
        self.hop_thread.start()
        
        self.scan_thread = threading.Thread(
            target=scanner.start_scan,
            kwargs={"stop_event": self.scan_stop_event},
            daemon=True,
        )
        self.scan_thread.start()

    def update_terminal(self, message):
        self.root.after(0, self._update_terminal_ui, message)

    def _update_terminal_ui(self, message):
        self.output.insert(tk.END, message)
        self.output.see(tk.END)

        if "[*] Writing capture to:" in message:
            path = message.split("[*] Writing capture to:", 1)[1].strip()
            self.capture_var.set(f"Capture: {os.path.basename(path)}")

        if "[CLIENT]" in message:
            clean_msg = message.replace("[CLIENT] ", "").replace("\n", "")
            if " on " in clean_msg:
                client_part, bssid = clean_msg.rsplit(" on ", 1)
                client_mac = client_part.split(" ")[0]
                vendor = "Unknown"
                vendor_match = re.search(r"\(([^)]+)\)", client_part)
                if vendor_match:
                    vendor = vendor_match.group(1)

                key = (client_mac.lower(), bssid.lower())
                if key in self.target_rows:
                    item_id, seen_count = self.target_rows[key]
                    seen_count += 1
                    self.target_rows[key] = (item_id, seen_count)
                    self.target_table.item(item_id, values=(client_mac, vendor, bssid, seen_count))
                else:
                    item_id = self.target_table.insert(
                        "",
                        tk.END,
                        values=(client_mac, vendor, bssid, 1),
                    )
                    self.target_rows[key] = (item_id, 1)
                    seen_count = 1

                self.bridge.send(
                    "wicrack.client.seen",
                    {
                        "client": client_mac,
                        "vendor": vendor,
                        "bssid": bssid,
                        "seen": seen_count,
                    },
                )

    