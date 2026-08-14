#jwt_gui
import tkinter as tk
from tkinter import ttk
import jwt_engine

def trigger_decode(input_widget, header_widget, payload_widget, sig_widget):
    raw_token = input_widget.get("1.0", tk.END).strip()
    if not raw_token:
        return
    header, payload, signature = jwt_engine.parse_token(raw_token)
    header_widget.delete("1.0", tk.END)
    header_widget.insert("1.0", header)
    
    payload_widget.delete("1.0", tk.END)
    payload_widget.insert("1.0", payload)
    
    sig_widget.delete("1.0", tk.END)
    sig_widget.insert("1.0", signature)

def trigger_forge(input_widget, header_widget, payload_widget):
    header_json = header_widget.get("1.0", tk.END).strip()
    payload_json = payload_widget.get("1.0", tk.END).strip()
    
    forged_token = jwt_engine.forge_token(header_json, payload_json)
    
    input_widget.delete("1.0", tk.END)
    input_widget.insert("1.0", forged_token)

def build_jwt_tab(notebook):
    jwt_tab = ttk.Frame(notebook)
    notebook.add(jwt_tab, text="JWT Tamperer")

    input_frame = tk.Frame(jwt_tab)
    input_frame.pack(pady=10, fill=tk.X, padx=10)
    
    tk.Label(input_frame, text="Raw JWT Token:", font=("Arial", 10, "bold")).pack(anchor="w")
    input_text = tk.Text(input_frame, height=4, width=85)
    input_text.pack()

    btn_frame = tk.Frame(jwt_tab)
    btn_frame.pack(pady=5)

    output_frame = tk.Frame(jwt_tab)
    output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    tk.Label(output_frame, text="Header (JSON):", font=("Arial", 10)).grid(row=0, column=0, sticky="w")
    header_text = tk.Text(output_frame, height=8, width=40)
    header_text.grid(row=1, column=0, padx=5, pady=5)

    tk.Label(output_frame, text="Payload (JSON):", font=("Arial", 10)).grid(row=0, column=1, sticky="w")
    payload_text = tk.Text(output_frame, height=8, width=40)
    payload_text.grid(row=1, column=1, padx=5, pady=5)

    tk.Label(output_frame, text="Signature:", font=("Arial", 10)).grid(row=2, column=0, columnspan=2, sticky="w")
    sig_text = tk.Text(output_frame, height=3, width=85)
    sig_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

    decode_btn = tk.Button(btn_frame, text="Decode Token", bg="darkblue", fg="white", font=("Arial", 10, "bold"),
                           command=lambda: trigger_decode(input_text, header_text, payload_text, sig_text))
    decode_btn.pack()

    forge_btn = tk.Button(btn_frame, text="Forge Token", bg="darkred", fg="white", font=("Arial", 10, "bold"),
                          command=lambda: trigger_forge(input_text, header_text, payload_text))
    forge_btn.pack(side=tk.LEFT, padx=10)
    decode_btn.pack(side=tk.LEFT)

    return jwt_tab