#auth_gui
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import auth_engine


def build_auth_tab(notebook: ttk.Notebook) -> ttk.Frame:
    tab = ttk.Frame(notebook)
    notebook.add(tab, text="Auth Tester")

    # ── Top controls ─────────────────────────────────────────────────────────
    ctrl = ttk.Frame(tab)
    ctrl.pack(fill=tk.X, padx=8, pady=6)

    ttk.Label(ctrl, text="Target URL / JWT Token:").grid(row=0, column=0, sticky=tk.W)
    target_var = tk.StringVar()
    ttk.Entry(ctrl, textvariable=target_var, width=60).grid(row=0, column=1, padx=4, columnspan=3, sticky=tk.EW)

    ttk.Label(ctrl, text="Mode:").grid(row=1, column=0, sticky=tk.W, pady=4)
    mode_var = tk.StringVar(value="session")
    mode_combo = ttk.Combobox(
        ctrl, textvariable=mode_var,
        values=["session", "basic_auth", "jwt", "csrf"],
        state="readonly", width=15
    )
    mode_combo.grid(row=1, column=1, sticky=tk.W, padx=4)

    ttk.Label(ctrl, text="Usernames (csv):").grid(row=2, column=0, sticky=tk.W)
    user_var = tk.StringVar(value="admin,root,user")
    ttk.Entry(ctrl, textvariable=user_var, width=30).grid(row=2, column=1, sticky=tk.W, padx=4)

    ttk.Label(ctrl, text="Passwords (csv):").grid(row=2, column=2, sticky=tk.W, padx=(12, 0))
    pass_var = tk.StringVar(value="admin,password,123456")
    ttk.Entry(ctrl, textvariable=pass_var, width=30).grid(row=2, column=3, sticky=tk.W, padx=4)

    ctrl.columnconfigure(1, weight=1)

    # ── Buttons ───────────────────────────────────────────────────────────────
    btn_frame = ttk.Frame(tab)
    btn_frame.pack(fill=tk.X, padx=8)
    start_btn = ttk.Button(btn_frame, text="Start Scan")
    start_btn.pack(side=tk.LEFT, padx=4)
    stop_btn = ttk.Button(btn_frame, text="Stop", state=tk.DISABLED)
    stop_btn.pack(side=tk.LEFT, padx=4)
    clear_btn = ttk.Button(btn_frame, text="Clear Results")
    clear_btn.pack(side=tk.LEFT, padx=4)

    # ── Results tree ─────────────────────────────────────────────────────────
    cols = ("Type", "Detail")
    tree = ttk.Treeview(tab, columns=cols, show="headings", height=20)
    for c in cols:
        tree.heading(c, text=c)
    tree.column("Type", width=90, anchor=tk.CENTER)
    tree.column("Detail", width=700)

    bar = ttk.Scrollbar(tab, orient=tk.VERTICAL, command=tree.yview)
    tree.configure(yscrollcommand=bar.set)
    tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=6, side=tk.LEFT)
    bar.pack(side=tk.RIGHT, fill=tk.Y, pady=6)

    # Tag colours
    tree.tag_configure("VULN",   background="#ffe0e0")
    tree.tag_configure("OK",     background="#e0ffe0")
    tree.tag_configure("WARN",   background="#fff5cc")
    tree.tag_configure("ERROR",  background="#f0d0d0")
    tree.tag_configure("STATUS", foreground="#555555")

    # ── Poll loop ────────────────────────────────────────────────────────────
    def _poll():
        while not auth_engine.result_queue.empty():
            status, data = auth_engine.result_queue.get_nowait()
            tag = status if status in ("VULN", "OK", "WARN", "ERROR", "STATUS") else "INFO"
            tree.insert("", tk.END, values=(status, data), tags=(tag,))
            if status == "DONE":
                start_btn.config(state=tk.NORMAL)
                stop_btn.config(state=tk.DISABLED)
        tab.after(120, _poll)

    _poll()

    # ── Button handlers ───────────────────────────────────────────────────────
    def _start():
        target = target_var.get().strip()
        if not target:
            return
        tree.delete(*tree.get_children())
        start_btn.config(state=tk.DISABLED)
        stop_btn.config(state=tk.NORMAL)
        auth_engine.is_running = True
        threading.Thread(
            target=auth_engine.run_auth_scan,
            args=(mode_var.get(), target, user_var.get(), pass_var.get()),
            daemon=True
        ).start()

    def _stop():
        auth_engine.stop_auth_scan()
        stop_btn.config(state=tk.DISABLED)

    def _clear():
        tree.delete(*tree.get_children())

    start_btn.config(command=_start)
    stop_btn.config(command=_stop)
    clear_btn.config(command=_clear)

    return tab
