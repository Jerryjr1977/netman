#discovery_engine
import urllib.request
import urllib.error
import concurrent.futures
import queue
import random
import string
import time

result_queue = queue.Queue()
is_running = False

def check_path(base_url, path, baseline_length):
    if not base_url.endswith('/'):
        base_url += '/'
        
    target_url = base_url + path
    req = urllib.request.Request(target_url, method="GET", headers={'Connection': 'close', 'User-Agent': 'Mozilla/5.0'})
    
    try:
        # FIX 2: Use 'with' to force Python to dump the object from RAM instantly
        with urllib.request.urlopen(req, timeout=3) as response:
            content_length = response.headers.get('Content-Length')
            
            if response.status == 200 and baseline_length is not None:
                if content_length == baseline_length:
                    return
                    
            result_queue.put((path, response.status, f"Size: {content_length}"))
            
    except urllib.error.HTTPError as e:
        if e.code != 404:
            result_queue.put((path, e.code, e.reason))
    except Exception:
        pass
    finally:
        # With sockets closing properly, a 50ms to 100ms throttle is plenty safe
        time.sleep(0.05) 

def run_discovery(target_url, wordlist_path, threads=10):
    global is_running
    is_running = True
    
    baseline_length = None
    try:
        garbage_path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=15))
        test_url = target_url if target_url.endswith('/') else target_url + '/'
        
        req = urllib.request.Request(test_url + garbage_path, method="GET", headers={'Connection': 'close', 'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                baseline_length = resp.headers.get('Content-Length')
                print(f"[*] Catch-all detected. Filtering false positive size: {baseline_length}")
    except Exception:
        pass

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            words = f.read().splitlines()
    except Exception:
        return
        
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        for word in words:
            if not is_running:
                break
            if word.strip():
                executor.submit(check_path, target_url, word.strip(), baseline_length)

def stop_discovery():
    global is_running
    is_running = False