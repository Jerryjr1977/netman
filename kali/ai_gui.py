#ai_gui
import tkinter as tk
from tkinter import ttk
import queue
import ai_engine

# Global variables so our functions can access the text boxes
ai_output = None
ai_manual_entry = None
model_var = None

def poll_ai_queue():
    """Safely pulls text from the AI engine and prints it to the screen."""
    if ai_output is None:
        return
    try:
        while True:
            # Grab the text from the engine
            result_text = ai_engine.result_queue.get_nowait()
            
            # Insert it at the bottom, and auto-scroll down
            ai_output.insert(tk.END, result_text)
            ai_output.see(tk.END)
    except queue.Empty:
        pass
    
    # Check again in 100ms
    if ai_output:
        ai_output.after(100, poll_ai_queue)

def on_model_change(event):
    if model_var is None:
        return
    selected_model = model_var.get()
    ai_engine.event_queue.put({"event": "change_model", "model": selected_model})

def submit_chat_message(event=None):
    """Grabs the text from the entry box and sends it to the AI Engine."""
    if ai_output is None or ai_manual_entry is None:
        return
    user_text = ai_manual_entry.get().strip()
    if not user_text:
        return
        
    # Print the user's question to the screen so they can see what they asked
    ai_output.insert(tk.END, f"[YOU]: {user_text}\n\n")
    ai_output.see(tk.END)
    
    # Clear the entry box
    ai_manual_entry.delete(0, tk.END)
    
    # Drop the text onto the bulletin board for the engine to pick up
    ai_engine.event_queue.put({"event": "chat_message", "text": user_text})

def build_ai_tab(notebook):
    global ai_output, ai_manual_entry, model_var
    
    ai_tab = ttk.Frame(notebook)
    notebook.add(ai_tab, text="AI Co-Pilot")

    # --- Header ---
    tk.Label(ai_tab, text="AI Vulnerability Analysis Console", font=("Arial", 12, "bold")).pack(pady=10)

    control_frame = tk.Frame(ai_tab)
    control_frame.pack(fill=tk.X, padx=20, pady=5)
    
    tk.Label(control_frame, text="Active AI Model:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
    
    default_model = ai_engine.active_model if ai_engine.active_model in {"claude-3-5-sonnet-20241022", "gpt-4o"} else "claude-3-5-sonnet-20241022"

    model_var = tk.StringVar(value=default_model)
    model_dropdown = ttk.Combobox(control_frame, textvariable=model_var, state="readonly", width=30)
    model_values = ["claude-3-5-sonnet-20241022", "gpt-4o"]
    model_dropdown['values'] = tuple(model_values)
    model_dropdown.pack(side=tk.LEFT, padx=10)
    
    # Bind the dropdown so it triggers our function when clicked
    model_dropdown.bind("<<ComboboxSelected>>", on_model_change)
    
    info_label_text = "(Auto-fallback chain: Claude → GPT-4o)"
    info_label = tk.Label(control_frame, text=info_label_text, font=("Arial", 9, "italic"), fg="gray")
    info_label.pack(side=tk.LEFT, padx=5)

    # --- Main Text Display Area ---
    text_frame = tk.Frame(ai_tab)
    # Using expand=True ensures the text box takes up the majority of the screen
    text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)

    scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL)
    
    ai_output = tk.Text(text_frame, height=20, width=90, bg="black", fg="lightgreen", font=("Consolas", 10), yscrollcommand=scrollbar.set)
    ai_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    scrollbar.config(command=ai_output.yview)

    # --- The Input Area (The Missing Frame!) ---
    ai_input_frame = tk.Frame(ai_tab)
    # Pack this at the bottom, without expand=True, so it stays a fixed size
    ai_input_frame.pack(fill=tk.X, padx=20, pady=15)

    tk.Label(ai_input_frame, text="Ask a follow-up:", font=("Arial", 10)).pack(side=tk.LEFT)
    
    ai_manual_entry = tk.Entry(ai_input_frame, width=70)
    ai_manual_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
    
    # Allow the user to just hit the 'Enter' key to send
    ai_manual_entry.bind("<Return>", submit_chat_message)

    # Wire the button click to the function
    ai_ask_btn = tk.Button(ai_input_frame, text="Send", bg="darkblue", fg="white", command=submit_chat_message)
    ai_ask_btn.pack(side=tk.LEFT, padx=5)

    def clear_ai_console():
        if ai_output is None:
            return
        ai_output.delete("1.0", tk.END)
        ai_output.insert(tk.END, "[*] Console cleared. Engine still running...\n\n")

    ai_clear_btn = tk.Button(ai_input_frame, text="Clear Console", bg="darkgray", command=clear_ai_console)
    ai_clear_btn.pack(side=tk.RIGHT, padx=5)

    # Add initial startup text
    ai_output.insert(tk.END, "[*] AI Co-Pilot Initialized. Engine running in background...\n\n")

    # Start the polling loop!
    poll_ai_queue()

    return ai_tab