#idor_gui
import tkinter as tk
from tkinter import ttk
import idor_engine
import threading
import queue

def start_scan(url_entry, auth_entry, start_entry, end_entry, tree_widget, start_btn, stop_btn):
    # Clear old results
    for item in tree_widget.get_children():
        tree_widget.delete(item)
        
    target_url = url_entry.get().strip()
    auth_header = auth_entry.get().strip()
    start_id = start_entry.get().strip()
    end_id = end_entry.get().strip()
    
    if not target_url or "[ID]" not in target_url or not start_id or not end_id:
        tree_widget.insert('', 'end', values=("ERROR", "Missing URL, [ID] placeholder, or ID range!"))
        return
        
    # Using your secure fallback logic!
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    start_btn.config(state="disabled")
    stop_btn.config(state="normal")
    
    # Spin up the attack thread
    scan_thread = threading.Thread(
        target=idor_engine.run_idor_scan,
        args=(target_url, auth_header, start_id, end_id),
        daemon=True
    )
    scan_thread.start()

def stop_scan(start_btn, stop_btn):
    idor_engine.stop_idor_scan()
    start_btn.config(state="normal")
    stop_btn.config(state="disabled")

def poll_queue(tree_widget):
    try:
        while True:
            status, data = idor_engine.result_queue.get_nowait()
            tree_widget.insert('', 'end', values=(status, data))
            tree_widget.yview_moveto(1)
    except queue.Empty:
        pass
    tree_widget.after(100, lambda: poll_queue(tree_widget))

def copy_tree_item(event, tree):
    selected = tree.selection()
    if selected:
        item_values = tree.item(selected[0], "values")
        if item_values:
            tree.clipboard_clear()
            tree.clipboard_append(item_values[1])

def build_idor_tab(notebook):
    idor_tab = ttk.Frame(notebook)
    notebook.add(idor_tab, text="IDOR Automator")

    # --- Top Configuration Frame ---
    config_frame = tk.Frame(idor_tab)
    config_frame.pack(pady=10, fill=tk.X, padx=10)

    # Row 0: URL
    tk.Label(config_frame, text="Target URL (use [ID]):", font=("Arial", 10)).grid(row=0, column=0, sticky="e", pady=5)
    url_entry = tk.Entry(config_frame, width=50)
    url_entry.grid(row=0, column=1, columnspan=3, sticky="w", padx=5)
    url_entry.insert(0, "https://target.com/api/user/[ID]")

    # Row 1: Auth Header
    tk.Label(config_frame, text="Auth Header/Cookie:", font=("Arial", 10)).grid(row=1, column=0, sticky="e", pady=5)
    auth_entry = tk.Entry(config_frame, width=50)
    auth_entry.grid(row=1, column=1, columnspan=3, sticky="w", padx=5)

    # Row 2: Range
    tk.Label(config_frame, text="Start ID:", font=("Arial", 10)).grid(row=2, column=0, sticky="e", pady=5)
    start_entry = tk.Entry(config_frame, width=10)
    start_entry.grid(row=2, column=1, sticky="w", padx=5)
    
    tk.Label(config_frame, text="End ID:", font=("Arial", 10)).grid(row=2, column=2, sticky="e", pady=5)
    end_entry = tk.Entry(config_frame, width=10)
    end_entry.grid(row=2, column=3, sticky="w", padx=5)

    # --- Button Frame ---
    btn_frame = tk.Frame(idor_tab)
    btn_frame.pack(pady=5)

    start_btn = tk.Button(btn_frame, text="Start IDOR Attack", bg="darkred", fg="white", font=("Arial", 10, "bold"))
    stop_btn = tk.Button(btn_frame, text="Stop", bg="darkgray", font=("Arial", 10, "bold"), state="disabled")

    # --- Results Table ---
    tree_frame = tk.Frame(idor_tab)
    tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    columns = ('Status', 'Details')
    results_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=15)
    
    results_tree.heading('Status', text='Status')
    results_tree.heading('Details', text='Response Details')
    results_tree.column('Status', width=150, anchor=tk.CENTER)
    results_tree.column('Details', width=550)

    scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=results_tree.yview)
    results_tree.configure(yscroll=scrollbar.set)
    results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # --- Bind Commands ---
    start_btn.config(command=lambda: start_scan(url_entry, auth_entry, start_entry, end_entry, results_tree, start_btn, stop_btn))
    stop_btn.config(command=lambda: stop_scan(start_btn, stop_btn))
    results_tree.bind("<Control-c>", lambda e: copy_tree_item(e, results_tree))

    start_btn.pack(side=tk.LEFT, padx=10)
    stop_btn.pack(side=tk.LEFT)

    poll_queue(results_tree)
    return idor_tab