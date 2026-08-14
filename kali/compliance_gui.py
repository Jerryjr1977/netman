#compliance_gui
import tkinter as tk
from tkinter import ttk
import threading
import compliance_engine


def build_compliance_tab(notebook: ttk.Notebook) -> ttk.Frame:
    tab = ttk.Frame(notebook)
    notebook.add(tab, text="Compliance")

    # ── URL row ───────────────────────────────────────────────────────────────
    top = ttk.Frame(tab)
    top.pack(fill=tk.X, padx=8, pady=6)

    ttk.Label(top, text="Target URL:").pack(side=tk.LEFT)
    url_var = tk.StringVar()
    ttk.Entry(top, textvariable=url_var, width=60).pack(side=tk.LEFT, padx=6, fill=tk.X, expand=True)

    # ── Check toggles ─────────────────────────────────────────────────────────
    checks_frame = ttk.LabelFrame(tab, text="OWASP Checks to Run")
    checks_frame.pack(fill=tk.X, padx=8, pady=4)

    check_vars = {}
    check_labels = [
        ("injection", "A01 – Injection"),
        ("auth",      "A07 – Broken Authentication"),
        ("sensitive", "A02 – Sensitive Data Exposure"),
        ("headers",   "A05 – Security Misconfiguration"),
        ("files",     "A05 – Exposed Sensitive Files"),
        ("ssrf",      "A10 – SSRF"),
    ]
    for col, (key, label) in enumerate(check_labels):
        var = tk.BooleanVar(value=True)
        check_vars[key] = var
        ttk.Checkbutton(checks_frame, text=label, variable=var).grid(
            row=col // 3, column=col % 3, sticky=tk.W, padx=10, pady=2)

    # ── Buttons ───────────────────────────────────────────────────────────────
    btn_frame = ttk.Frame(tab)
    btn_frame.pack(fill=tk.X, padx=8, pady=4)
    start_btn = ttk.Button(btn_frame, text="Run Compliance Scan")
    start_btn.pack(side=tk.LEFT, padx=4)
    stop_btn = ttk.Button(btn_frame, text="Stop", state=tk.DISABLED)
    stop_btn.pack(side=tk.LEFT, padx=4)
    clear_btn = ttk.Button(btn_frame, text="Clear Results")
    clear_btn.pack(side=tk.LEFT, padx=4)

    # ── Results tree ──────────────────────────────────────────────────────────
    cols = ("Status", "Finding")
    tree = ttk.Treeview(tab, columns=cols, show="headings", height=22)
    tree.heading("Status", text="Status")
    tree.heading("Finding", text="Finding")
    tree.column("Status", width=80, anchor=tk.CENTER)
    tree.column("Finding", width=700)

    vsb = ttk.Scrollbar(tab, orient=tk.VERTICAL, command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=6, side=tk.LEFT)
    vsb.pack(side=tk.RIGHT, fill=tk.Y, pady=6)

    tree.tag_configure("PASS",   background="#e0ffe0")
    tree.tag_configure("FAIL",   background="#ffe0e0")
    tree.tag_configure("WARN",   background="#fff5cc")
    tree.tag_configure("ERROR",  background="#f0d0d0")
    tree.tag_configure("CHECK",  foreground="#1a1aff", font=("", 9, "bold"))
    tree.tag_configure("STATUS", foreground="#444444")

    # ── Poll ──────────────────────────────────────────────────────────────────
    def _poll():
        while not compliance_engine.result_queue.empty():
            status, data = compliance_engine.result_queue.get_nowait()
            tag = status if status in ("PASS", "FAIL", "WARN", "ERROR", "CHECK", "STATUS") else "INFO"
            tree.insert("", tk.END, values=(status, data), tags=(tag,))
            if status == "DONE":
                start_btn.config(state=tk.NORMAL)
                stop_btn.config(state=tk.DISABLED)
        tab.after(120, _poll)

    _poll()

    # ── Button handlers ───────────────────────────────────────────────────────
    def _start():
        url = url_var.get().strip()
        if not url:
            return
        selected = [k for k, v in check_vars.items() if v.get()]
        if not selected:
            return
        tree.delete(*tree.get_children())
        start_btn.config(state=tk.DISABLED)
        stop_btn.config(state=tk.NORMAL)
        compliance_engine.is_running = True
        threading.Thread(
            target=compliance_engine.run_compliance_scan,
            args=(url, selected),
            daemon=True
        ).start()

    def _stop():
        compliance_engine.stop_compliance_scan()
        stop_btn.config(state=tk.DISABLED)

    def _clear():
        tree.delete(*tree.get_children())

    start_btn.config(command=_start)
    stop_btn.config(command=_stop)
    clear_btn.config(command=_clear)

    return tab
