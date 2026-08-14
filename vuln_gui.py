#vuln_gui
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import vuln_engine
import threading
import queue

def browse_file(entry_widget):
    file_path = filedialog.askopenfilename(title="Select Lockfile")
    if file_path:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, file_path)

def start_scan(file_entry, ecosystem_combo, tree_widget, start_btn, stop_btn):
    # Clear old results
    for item in tree_widget.get_children():
        tree_widget.delete(item)
        
    file_path = file_entry.get().strip()
    ecosystem = ecosystem_combo.get().strip()
    
    if not file_path or not ecosystem:
        return

    start_btn.config(state="disabled")
    stop_btn.config(state="normal")
    
    # Spin up the background thread
    scan_thread = threading.Thread(
        target=vuln_engine.run_scanner,
        args=(file_path, ecosystem),
        daemon=True
    )
    scan_thread.start()

def stop_scan(start_btn, stop_btn):
    vuln_engine.stop_scanner()
    start_btn.config(state="normal")
    stop_btn.config(state="disabled")

def poll_queue(tree_widget):
    try:
        while True:
            # Grab the tuple sent from the engine: (Status, Data)
            status, data = vuln_engine.result_queue.get_nowait()
            tree_widget.insert('', 'end', values=(status, data))
            
            # Auto-scroll to the bottom
            tree_widget.yview_moveto(1)
    except queue.Empty:
        pass
    
    # Check again in 100 milliseconds
    tree_widget.after(100, lambda: poll_queue(tree_widget))

def copy_tree_item(event, tree):
    selected = tree.selection()
    if selected:
        item_values = tree.item(selected[0], "values")
        if item_values:
            tree.clipboard_clear()
            tree.clipboard_append(item_values[1])

def build_vuln_tab(notebook):
    vuln_tab = ttk.Frame(notebook)
    notebook.add(vuln_tab, text="Vuln Scanner")

    # --- Top Configuration Frame ---
    config_frame = tk.Frame(vuln_tab)
    config_frame.pack(pady=10, fill=tk.X, padx=10)

    tk.Label(config_frame, text="Lockfile Path:", font=("Arial", 10)).grid(row=0, column=0, sticky="e", pady=5)
    file_entry = tk.Entry(config_frame, width=50)
    file_entry.grid(row=0, column=1, sticky="w", padx=5)
    
    browse_btn = tk.Button(config_frame, text="Browse", command=lambda: browse_file(file_entry))
    browse_btn.grid(row=0, column=2, padx=5)

    tk.Label(config_frame, text="Ecosystem:", font=("Arial", 10)).grid(row=0, column=3, sticky="e", pady=5)
    
    # Dropdown menu for the ecosystem
    ecosystem_combo = ttk.Combobox(config_frame, values=["npm", "PyPI", "RubyGems", "Go"], width=10)
    ecosystem_combo.set("npm")
    ecosystem_combo.grid(row=0, column=4, sticky="w", padx=5)

    # --- Button Frame ---
    btn_frame = tk.Frame(vuln_tab)
    btn_frame.pack(pady=5)

    start_btn = tk.Button(btn_frame, text="Scan Lockfile", bg="darkorange", fg="black", font=("Arial", 10, "bold"))
    stop_btn = tk.Button(btn_frame, text="Stop", bg="darkgray", font=("Arial", 10, "bold"), state="disabled")

    # --- Results Table (Treeview) ---
    tree_frame = tk.Frame(vuln_tab)
    tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    columns = ('Status', 'Details')
    results_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=15)
    
    results_tree.heading('Status', text='Status / Type')
    results_tree.heading('Details', text='Vulnerability Details')

    results_tree.column('Status', width=150, anchor=tk.CENTER)
    results_tree.column('Details', width=550)

    scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=results_tree.yview)
    results_tree.configure(yscroll=scrollbar.set)

    results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # --- Bind Commands ---
    start_btn.config(command=lambda: start_scan(file_entry, ecosystem_combo, results_tree, start_btn, stop_btn))
    stop_btn.config(command=lambda: stop_scan(start_btn, stop_btn))
    results_tree.bind("<Control-c>", lambda e: copy_tree_item(e, results_tree))

    start_btn.pack(side=tk.LEFT, padx=10)
    stop_btn.pack(side=tk.LEFT)

    # Start the polling loop
    poll_queue(results_tree)

    return vuln_tab