#discovery_gui
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import discovery_engine
import queue
import threading

def browse_wordlist(entry_widget):
    file_path = filedialog.askopenfilename(title="Select Wordlist")
    if file_path:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, file_path)

def start_scan(url_entry, wordlist_entry, threads_entry, depth_entry, tree_widget, start_btn, stop_btn):
    for item in tree_widget.get_children():
        tree_widget.delete(item)
    target_url = url_entry.get().strip()
    wordlist_path = wordlist_entry.get().strip()
    try:
        threads = int(threads_entry.get().strip())
    except ValueError:
        threads = 10
    try:
        max_depth = int(depth_entry.get().strip())
    except ValueError:
        max_depth = 3
    if not target_url or not wordlist_path:
        return
    if not target_url.startswith("http"):
        target_url = "http://" + target_url
    start_btn.config(state="disabled")
    stop_btn.config(state="normal")
    scan_thread = threading.Thread(
        target=discovery_engine.run_discovery, 
        args=(target_url, wordlist_path, threads, max_depth),
        daemon=True
    )
    scan_thread.start()

def stop_scan(start_btn, stop_btn):
    discovery_engine.stop_discovery()
    start_btn.config(state="normal")
    stop_btn.config(state="disabled")

def poll_queue(tree_widget):
    try:
        while True:
            result = discovery_engine.result_queue.get_nowait()
            tree_widget.insert('', 'end', values=result)
    except queue.Empty:
        pass
    tree_widget.after(100, lambda: poll_queue(tree_widget))

def build_discovery_tab(notebook):
    disc_tab = ttk.Frame(notebook)
    notebook.add(disc_tab, text="Directory Discoverer")

    config_frame = tk.Frame(disc_tab)
    config_frame.pack(pady=10, fill=tk.X, padx=10)

    tk.Label(config_frame, text="Target URL:", font=("Arial", 10)).grid(row=0, column=0, sticky="e", pady=5)
    url_entry = tk.Entry(config_frame, width=50)
    url_entry.grid(row=0, column=1, columnspan=2, sticky="w", padx=5)

    tk.Label(config_frame, text="Wordlist:", font=("Arial", 10)).grid(row=1, column=0, sticky="e", pady=5)
    wordlist_entry = tk.Entry(config_frame, width=40)
    wordlist_entry.grid(row=1, column=1, sticky="w", padx=5)
    
    browse_btn = tk.Button(config_frame, text="Browse...", command=lambda: browse_wordlist(wordlist_entry))
    browse_btn.grid(row=1, column=2, padx=5)

    tk.Label(config_frame, text="Threads:", font=("Arial", 10)).grid(row=2, column=0, sticky="e", pady=5)
    threads_entry = tk.Entry(config_frame, width=10)
    threads_entry.insert(0, "10")
    threads_entry.grid(row=2, column=1, sticky="w", padx=5)

    tk.Label(config_frame, text="Max Depth:", font=("Arial", 10)).grid(row=3, column=0, sticky="e", pady=5)
    depth_entry = tk.Entry(config_frame, width=10)
    depth_entry.insert(0, "3")
    depth_entry.grid(row=3, column=1, sticky="w", padx=5)

    btn_frame = tk.Frame(disc_tab)
    btn_frame.pack(pady=5)

    start_btn = tk.Button(btn_frame, text="Start Discovery", bg="darkred", fg="white", font=("Arial", 10, "bold"))
    stop_btn = tk.Button(btn_frame, text="Stop", bg="darkgray", font=("Arial", 10, "bold"), state="disabled")

    start_btn.config(command=lambda: start_scan(url_entry, wordlist_entry, threads_entry, depth_entry, results_tree, start_btn, stop_btn))
    stop_btn.config(command=lambda: stop_scan(start_btn, stop_btn))

    start_btn.pack(side=tk.LEFT, padx=10)
    stop_btn.pack(side=tk.LEFT)

    tree_frame = tk.Frame(disc_tab)
    tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    columns = ('Path', 'Status', 'Result')
    results_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=15)
    
    results_tree.heading('Path', text='Discovered Path')
    results_tree.heading('Status', text='HTTP Status')
    results_tree.heading('Result', text='Result')

    results_tree.column('Path', width=400)
    results_tree.column('Status', width=100, anchor=tk.CENTER)
    results_tree.column('Result', width=200)

    scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=results_tree.yview)
    results_tree.configure(yscrollcommand=scrollbar.set)

    results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    poll_queue(results_tree)

    return disc_tab