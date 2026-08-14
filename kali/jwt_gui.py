#jwt_gui
import tkinter as tk
from tkinter import filedialog, ttk
import jwt_engine

def trigger_decode(input_widget, header_widget, payload_widget, sig_widget, hint_label, key_label):
    raw_token = input_widget.get("1.0", tk.END).strip()
    if not raw_token:
        return
    header, payload, signature = jwt_engine.parse_token(raw_token)
    hint_text, key_label_text = jwt_engine.get_verification_hint(raw_token)
    header_widget.delete("1.0", tk.END)
    header_widget.insert("1.0", header)
    
    payload_widget.delete("1.0", tk.END)
    payload_widget.insert("1.0", payload)
    
    sig_widget.delete("1.0", tk.END)
    sig_widget.insert("1.0", signature)
    hint_label.config(text=hint_text)
    key_label.config(text=key_label_text + ":")

def trigger_forge(input_widget, header_widget, payload_widget):
    header_json = header_widget.get("1.0", tk.END).strip()
    payload_json = payload_widget.get("1.0", tk.END).strip()
    
    forged_token = jwt_engine.forge_token(header_json, payload_json)
    
    input_widget.delete("1.0", tk.END)
    input_widget.insert("1.0", forged_token)


def trigger_verify(input_widget, secret_entry, result_label):
    raw_token = input_widget.get("1.0", tk.END).strip()
    verification_key = secret_entry.get("1.0", tk.END).strip()
    if not raw_token:
        result_label.config(text="Verification: missing token", fg="red")
        return

    ok, message = jwt_engine.verify_token(raw_token, verification_key)
    result_label.config(
        text=f"Verification: {message}",
        fg="green" if ok else "red",
    )


def browse_verification_key(secret_entry):
    file_path = filedialog.askopenfilename(
        title="Select JWT Verification Key",
        filetypes=[("PEM Files", "*.pem *.crt *.pub *.key"), ("All Files", "*.*")],
    )
    if not file_path:
        return

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            secret_entry.delete("1.0", tk.END)
            secret_entry.insert("1.0", f.read())
    except Exception:
        secret_entry.delete("1.0", tk.END)
        secret_entry.insert("1.0", file_path)

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

    verify_frame = tk.Frame(jwt_tab)
    verify_frame.pack(fill=tk.X, padx=10, pady=(0, 5))

    key_label = tk.Label(verify_frame, text="Verification Secret / Public Key:", font=("Arial", 10, "bold"))
    key_label.pack(anchor="w")
    secret_entry = tk.Text(verify_frame, height=4, width=85)
    secret_entry.pack(fill=tk.X, pady=(3, 0))

    verify_btn_row = tk.Frame(verify_frame)
    verify_btn_row.pack(fill=tk.X, pady=(4, 0))

    browse_key_btn = tk.Button(
        verify_btn_row,
        text="Load Key File",
        bg="#3b4a5a",
        fg="white",
        font=("Arial", 9, "bold"),
        command=lambda: browse_verification_key(secret_entry),
    )
    browse_key_btn.pack(side=tk.LEFT)

    hint_label = tk.Label(verify_btn_row, text="Hint: decode a token to see required key type", font=("Arial", 9, "bold"), fg="#5a6b7d")
    hint_label.pack(side=tk.LEFT, padx=10)

    verify_result = tk.Label(verify_frame, text="Verification: not run", font=("Arial", 10, "bold"), fg="gray")
    verify_result.pack(side=tk.LEFT, padx=8)

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
                           command=lambda: trigger_decode(input_text, header_text, payload_text, sig_text, hint_label, key_label))

    forge_btn = tk.Button(btn_frame, text="Forge Token", bg="darkred", fg="white", font=("Arial", 10, "bold"),
                          command=lambda: trigger_forge(input_text, header_text, payload_text))
    verify_btn = tk.Button(btn_frame, text="Verify Signature", bg="#2f7d32", fg="white", font=("Arial", 10, "bold"),
                           command=lambda: trigger_verify(input_text, secret_entry, verify_result))
    forge_btn.pack(side=tk.LEFT, padx=10)
    decode_btn.pack(side=tk.LEFT)
    verify_btn.pack(side=tk.LEFT, padx=10)

    return jwt_tab