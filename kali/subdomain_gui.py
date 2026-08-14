#subdomain_gui
import tkinter as tk
from tkinter import ttk, filedialog
import subdomain_engine
import threading
import queue

def browse_wordlist(entry_widget):
    path = filedialog.askopenfilename(title="Select Wordlist")
    if path:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, path)

def start_scan(domain_entry, wordlist_entry, threads_entry, tree_widget, start_btn, stop_btn):
    for item in tree_widget.get_children():
        tree_widget.delete(item)
    domain = domain_entry.get().strip()
    if not domain:
        return
    wordlist = wordlist_entry.get().strip()
    try:
        threads = int(threads_entry.get().strip())
    except ValueError:
        threads = 50
    start_btn.config(state="disabled")
    stop_btn.config(state="normal")
    threading.Thread(
        target=subdomain_engine.run_subdomain_scan,
        args=(domain, wordlist, threads),
        daemon=True
    ).start()

def stop_scan(start_btn, stop_btn):
    subdomain_engine.stop_subdomain_scan()
    start_btn.config(state="normal")
    stop_btn.config(state="disabled")

def poll_queue(tree_widget):
    try:
        while True:
            status, data = subdomain_engine.result_queue.get_nowait()
            tree_widget.insert('', 'end', values=(status, data))
            tree_widget.yview_moveto(1)
    except queue.Empty:
        pass
    tree_widget.after(100, lambda: poll_queue(tree_widget))

def copy_tree_item(event, tree):
    selected = tree.selection()
    if selected:
        vals = tree.item(selected[0], "values")
        if vals:
            tree.clipboard_clear()
            tree.clipboard_append(vals[1])

def build_subdomain_tab(notebook):
    sub_tab = ttk.Frame(notebook)
    notebook.add(sub_tab, text="Subdomain Enum")

    config_frame = tk.Frame(sub_tab)
    config_frame.pack(pady=10, fill=tk.X, padx=10)

    tk.Label(config_frame, text="Target Domain:", font=("Arial", 10)).grid(row=0, column=0, sticky="e", pady=5)
    domain_entry = tk.Entry(config_frame, width=40)
    domain_entry.grid(row=0, column=1, sticky="w", padx=5)

    tk.Label(config_frame, text="Wordlist:", font=("Arial", 10)).grid(row=1, column=0, sticky="e", pady=5)
    wordlist_entry = tk.Entry(config_frame, width=35)
    wordlist_entry.insert(0, "(built-in list)")
    wordlist_entry.grid(row=1, column=1, sticky="w", padx=5)
    tk.Button(config_frame, text="Browse...",
              command=lambda: browse_wordlist(wordlist_entry)).grid(row=1, column=2, padx=5)

    tk.Label(config_frame, text="Threads:", font=("Arial", 10)).grid(row=2, column=0, sticky="e", pady=5)
    threads_entry = tk.Entry(config_frame, width=8)
    threads_entry.insert(0, "50")
    threads_entry.grid(row=2, column=1, sticky="w", padx=5)

    btn_frame = tk.Frame(sub_tab)
    btn_frame.pack(pady=5)

    start_btn = tk.Button(btn_frame, text="Start Scan", bg="indigo", fg="white", font=("Arial", 10, "bold"))
    stop_btn = tk.Button(btn_frame, text="Stop", bg="darkgray", font=("Arial", 10, "bold"), state="disabled")

    tree_frame = tk.Frame(sub_tab)
    tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    columns = ('Status', 'Subdomain / Address')
    results_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=15)
    results_tree.heading('Status', text='Status')
    results_tree.heading('Subdomain / Address', text='Subdomain  →  IP')
    results_tree.column('Status', width=120, anchor=tk.CENTER)
    results_tree.column('Subdomain / Address', width=580)

    scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=results_tree.yview)
    results_tree.configure(yscroll=scrollbar.set)
    results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    start_btn.config(command=lambda: start_scan(domain_entry, wordlist_entry, threads_entry, results_tree, start_btn, stop_btn))
    stop_btn.config(command=lambda: stop_scan(start_btn, stop_btn))
    results_tree.bind("<Control-c>", lambda e: copy_tree_item(e, results_tree))

    start_btn.pack(side=tk.LEFT, padx=10)
    stop_btn.pack(side=tk.LEFT)

    poll_queue(results_tree)
    return sub_tab
