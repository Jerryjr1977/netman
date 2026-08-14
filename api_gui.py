#api_gui
import tkinter as tk
from tkinter import ttk
import api_engine
import threading
import queue

def start_scan(url_entry, tree_widget, start_btn, stop_btn):
    for item in tree_widget.get_children():
        tree_widget.delete(item)
    target_url = url_entry.get().strip()
    if not target_url:
        return
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
    start_btn.config(state="disabled")
    stop_btn.config(state="normal")

    scan_thread = threading.Thread(
        target=api_engine.run_api_scan,
        args=(target_url,),
        daemon=True
    )
    scan_thread.start()

def stop_scan(start_btn, stop_btn):
    api_engine.stop_api_scan()
    start_btn.config(state="normal")
    stop_btn.config(state="disabled")

def poll_queue(tree_widget):
    try:
        while True:
            status, data = api_engine.result_queue.get_nowait()
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

def build_api_tab(notebook):
    api_tab = ttk.Frame(notebook)
    notebook.add(api_tab, text="API Mapper")

    # --- Top Configuration Frame ---
    config_frame = tk.Frame(api_tab)
    config_frame.pack(pady=10, fill=tk.X, padx=10)

    tk.Label(config_frame, text="API Target URL:", font=("Arial", 10)).grid(row=0, column=0, sticky="e", pady=5)
    url_entry = tk.Entry(config_frame, width=50)
    url_entry.grid(row=0, column=1, sticky="w", padx=5)

    # --- Button Frame ---
    btn_frame = tk.Frame(api_tab)
    btn_frame.pack(pady=5)

    start_btn = tk.Button(btn_frame, text="Discover API", bg="purple", fg="white", font=("Arial", 10, "bold"))
    stop_btn = tk.Button(btn_frame, text="Stop", bg="darkgray", font=("Arial", 10, "bold"), state="disabled")

    # --- Results Table (Treeview) ---
    tree_frame = tk.Frame(api_tab)
    tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    columns = ('Status', 'Endpoint Details')
    results_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=15)
    
    results_tree.heading('Status', text='Result Type')
    results_tree.heading('Endpoint Details', text='Endpoint / Details')

    results_tree.column('Status', width=150, anchor=tk.CENTER)
    results_tree.column('Endpoint Details', width=550)

    scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=results_tree.yview)
    results_tree.configure(yscroll=scrollbar.set)

    results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # --- Bind Commands ---
    start_btn.config(command=lambda: start_scan(url_entry, results_tree, start_btn, stop_btn))
    stop_btn.config(command=lambda: stop_scan(start_btn, stop_btn))
    results_tree.bind("<Control-c>", lambda e: copy_tree_item(e, results_tree))

    start_btn.pack(side=tk.LEFT, padx=10)
    stop_btn.pack(side=tk.LEFT)

    # Start the polling loop
    poll_queue(results_tree)

    return api_tab