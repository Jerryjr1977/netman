#tech_gui
import tkinter as tk
from tkinter import ttk
import tech_engine
import threading
import queue

def start_scan(url_entry, tree_widget, start_btn, stop_btn):
    for item in tree_widget.get_children():
        tree_widget.delete(item)
    url = url_entry.get().strip()
    if not url:
        return
    start_btn.config(state="disabled")
    stop_btn.config(state="normal")
    threading.Thread(target=tech_engine.run_tech_scan, args=(url,), daemon=True).start()

def stop_scan(start_btn, stop_btn):
    tech_engine.stop_tech_scan()
    start_btn.config(state="normal")
    stop_btn.config(state="disabled")

def poll_queue(tree_widget):
    try:
        while True:
            status, data = tech_engine.result_queue.get_nowait()
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

def build_tech_tab(notebook):
    tech_tab = ttk.Frame(notebook)
    notebook.add(tech_tab, text="Tech Detect")

    config_frame = tk.Frame(tech_tab)
    config_frame.pack(pady=10, fill=tk.X, padx=10)

    tk.Label(config_frame, text="Target URL:", font=("Arial", 10)).grid(row=0, column=0, sticky="e", pady=5)
    url_entry = tk.Entry(config_frame, width=55)
    url_entry.grid(row=0, column=1, sticky="w", padx=5)

    btn_frame = tk.Frame(tech_tab)
    btn_frame.pack(pady=5)

    start_btn = tk.Button(btn_frame, text="Start Scan", bg="teal", fg="white", font=("Arial", 10, "bold"))
    stop_btn = tk.Button(btn_frame, text="Stop", bg="darkgray", font=("Arial", 10, "bold"), state="disabled")

    tree_frame = tk.Frame(tech_tab)
    tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    columns = ('Type', 'Technology / Finding')
    results_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=15)
    results_tree.heading('Type', text='Category')
    results_tree.heading('Technology / Finding', text='Technology / Finding')
    results_tree.column('Type', width=150, anchor=tk.CENTER)
    results_tree.column('Technology / Finding', width=550)

    scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=results_tree.yview)
    results_tree.configure(yscroll=scrollbar.set)
    results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    start_btn.config(command=lambda: start_scan(url_entry, results_tree, start_btn, stop_btn))
    stop_btn.config(command=lambda: stop_scan(start_btn, stop_btn))
    results_tree.bind("<Control-c>", lambda e: copy_tree_item(e, results_tree))

    start_btn.pack(side=tk.LEFT, padx=10)
    stop_btn.pack(side=tk.LEFT)

    poll_queue(results_tree)
    return tech_tab
