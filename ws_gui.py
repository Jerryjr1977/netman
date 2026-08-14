#ws_gui
import tkinter as tk
from tkinter import ttk
import ws_engine
import threading
import queue

def poll_queue(tree_widget):
    try:
        while True:
            status, data = ws_engine.message_queue.get_nowait()
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

def build_ws_tab(notebook):
    ws_tab = ttk.Frame(notebook)
    notebook.add(ws_tab, text="WebSocket")

    # --- Connection Frame ---
    conn_frame = tk.Frame(ws_tab)
    conn_frame.pack(pady=10, fill=tk.X, padx=10)

    tk.Label(conn_frame, text="WebSocket URL:", font=("Arial", 10)).grid(row=0, column=0, sticky="e", pady=5)
    url_entry = tk.Entry(conn_frame, width=50)
    url_entry.insert(0, "wss://")
    url_entry.grid(row=0, column=1, sticky="w", padx=5)

    # --- Buttons ---
    btn_frame = tk.Frame(ws_tab)
    btn_frame.pack(pady=5)

    connect_btn = tk.Button(btn_frame, text="Connect", bg="darkgreen", fg="white", font=("Arial", 10, "bold"))
    disconnect_btn = tk.Button(btn_frame, text="Disconnect", bg="darkgray", font=("Arial", 10, "bold"), state="disabled")

    connect_btn.pack(side=tk.LEFT, padx=10)
    disconnect_btn.pack(side=tk.LEFT)

    # --- Message Log ---
    tree_frame = tk.Frame(ws_tab)
    tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    columns = ('Direction', 'Message')
    message_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=12)
    message_tree.heading('Direction', text='Direction')
    message_tree.heading('Message', text='Message / Event')
    message_tree.column('Direction', width=130, anchor=tk.CENTER)
    message_tree.column('Message', width=570)

    scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=message_tree.yview)
    message_tree.configure(yscroll=scrollbar.set)
    message_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # --- Send Frame ---
    send_frame = tk.Frame(ws_tab)
    send_frame.pack(fill=tk.X, padx=10, pady=5)

    tk.Label(send_frame, text="Message:", font=("Arial", 10)).pack(side=tk.LEFT)
    msg_entry = tk.Entry(send_frame, width=55)
    msg_entry.pack(side=tk.LEFT, padx=5)

    def do_connect():
        url = url_entry.get().strip()
        if not url:
            return
        connect_btn.config(state="disabled")
        disconnect_btn.config(state="normal")
        threading.Thread(target=ws_engine.connect, args=(url,), daemon=True).start()

    def do_disconnect():
        ws_engine.disconnect()
        connect_btn.config(state="normal")
        disconnect_btn.config(state="disabled")

    def do_send(event=None):
        msg = msg_entry.get().strip()
        if msg:
            ws_engine.send_message(msg)
            msg_entry.delete(0, tk.END)

    send_btn = tk.Button(send_frame, text="Send", bg="purple", fg="white",
                         font=("Arial", 10, "bold"), command=do_send)
    send_btn.pack(side=tk.LEFT)
    msg_entry.bind("<Return>", do_send)

    connect_btn.config(command=do_connect)
    disconnect_btn.config(command=do_disconnect)
    message_tree.bind("<Control-c>", lambda e: copy_tree_item(e, message_tree))

    poll_queue(message_tree)
    return ws_tab
