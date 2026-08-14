#scraper_gui
import tkinter as tk
from tkinter import ttk
import scraper_engine
import threading
import queue

def start_scrape(url_entry, tree_widget, start_btn, stop_btn):
    for item in tree_widget.get_children():
        tree_widget.delete(item)
        
    target_url = url_entry.get().strip()
    if not target_url:
        return
    if not target_url.startswith("http"):
        target_url = "http://" + target_url

    start_btn.config(state="disabled")
    stop_btn.config(state="normal")
    
    scrape_thread = threading.Thread(
        target=scraper_engine.run_scraper,
        args=(target_url,),
        daemon=True
    )
    scrape_thread.start()

def stop_scrape(start_btn, stop_btn):
    scraper_engine.stop_scraper()
    start_btn.config(state="normal")
    stop_btn.config(state="disabled")

def poll_queue(tree_widget):
    try:
        while True:
            finding_type, data = scraper_engine.result_queue.get_nowait()
            tree_widget.insert('', 'end', values=(finding_type, data))
            
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

def build_scraper_tab(notebook):
    scraper_tab = ttk.Frame(notebook)
    notebook.add(scraper_tab, text="Page Scraper")

    config_frame = tk.Frame(scraper_tab)
    config_frame.pack(pady=10, fill=tk.X, padx=10)

    tk.Label(config_frame, text="Target URL:", font=("Arial", 10)).grid(row=0, column=0, sticky="e", pady=5)
    url_entry = tk.Entry(config_frame, width=70)
    url_entry.grid(row=0, column=1, sticky="w", padx=5)

    btn_frame = tk.Frame(scraper_tab)
    btn_frame.pack(pady=5)

    start_btn = tk.Button(btn_frame, text="Scrape Page", bg="darkgreen", fg="white", font=("Arial", 10, "bold"))
    stop_btn = tk.Button(btn_frame, text="Stop", bg="darkgray", font=("Arial", 10, "bold"), state="disabled")

    tree_frame = tk.Frame(scraper_tab)
    tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    columns = ('Type', 'Data')
    results_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=15)
    
    results_tree.heading('Type', text='Finding Type')
    results_tree.heading('Data', text='Extracted Data')

    results_tree.column('Type', width=150, anchor=tk.CENTER)
    results_tree.column('Data', width=550)

    scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=results_tree.yview)
    results_tree.configure(yscroll=scrollbar.set)

    results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    start_btn.config(command=lambda: start_scrape(url_entry, results_tree, start_btn, stop_btn))
    stop_btn.config(command=lambda: stop_scrape(start_btn, stop_btn))

    start_btn.pack(side=tk.LEFT, padx=10)
    stop_btn.pack(side=tk.LEFT)

    results_tree.bind("<Control-c>", lambda e: copy_tree_item(e, results_tree))

    poll_queue(results_tree)

    return scraper_tab