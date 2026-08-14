#idor_engine
import urllib.request
import urllib.error
import queue
import threading

result_queue = queue.Queue()
is_running = False

def run_idor_scan(target_url, auth_header, start_id, end_id):
    global is_running
    is_running = True
    
    result_queue.put(("STATUS", f"Starting IDOR scan from ID {start_id} to {end_id}"))
    
    for current_id in range(int(start_id), int(end_id) + 1):
        if not is_running:
            break
            
        # Replace the [ID] placeholder with the current test number
        test_url = target_url.replace("[ID]", str(current_id))
        result_queue.put(("SCANNING", f"Testing ID: {current_id}"))
        
        try:
            req = urllib.request.Request(test_url)
            
            # Attach the user's session token to prove we are logged in
            if auth_header:
                req.add_header("Authorization", auth_header)
                req.add_header("Cookie", auth_header) # Catch-all for basic testing
                
            with urllib.request.urlopen(req, timeout=5) as response:
                # If we get a 200 OK, the server let us read the object!
                if response.getcode() == 200:
                    data_length = len(response.read())
                    result_queue.put(("VULNERABLE", f"ID {current_id} accessed! (Data Size: {data_length} bytes)"))
                    
        except urllib.error.HTTPError as e:
            # 401 Unauthorized or 403 Forbidden means the server properly blocked us
            result_queue.put(("FAILED", f"ID {current_id} blocked (HTTP {e.code})"))
        except Exception as e:
            result_queue.put(("ERROR", f"ID {current_id} failed: {str(e)}"))

    if is_running:
        result_queue.put(("DONE", "IDOR Scan Complete."))
    else:
        result_queue.put(("DONE", "Scan aborted by user."))
        
    is_running = False

def stop_idor_scan():
    global is_running
    is_running = False