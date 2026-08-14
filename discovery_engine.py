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

# Codes that suggest a real directory worth recursing into:
# 200 = found, 301/302 = redirect (path exists), 403 = forbidden (path exists, no access)
# 401 = auth required (path exists, locked), 405 = method not allowed (path exists)
# 500/503 = server error on valid path (e.g. Juice Shop, DVWA quirks)
RECURSE_CODES = {200, 301, 302, 401, 403, 405, 500, 503}

def check_path(base_url, path, baseline_length):
    """Probe base_url+path and return the full URL if it looks like a directory, else None."""
    if not base_url.endswith('/'):
        base_url += '/'

    target_url = base_url + path
    req = urllib.request.Request(
        target_url, method="GET",
        headers={'Connection': 'close', 'User-Agent': 'Mozilla/5.0'}
    )

    found_dir = None
    try:
        with urllib.request.urlopen(req, timeout=3) as response:
            content_length = response.headers.get('Content-Length')

            if response.status == 200 and baseline_length is not None:
                if content_length == baseline_length:
                    return None

            result_queue.put((target_url, response.status, f"Size: {content_length}"))

            if response.status in RECURSE_CODES:
                found_dir = target_url

    except urllib.error.HTTPError as e:
        if e.code != 404:
            result_queue.put((target_url, e.code, e.reason))
            if e.code in RECURSE_CODES:
                found_dir = target_url
    except Exception:
        pass
    finally:
        time.sleep(0.05)

    return found_dir


def get_baseline(base_url):
    """Return the Content-Length of a random junk path, or None if no catch-all."""
    try:
        garbage = ''.join(random.choices(string.ascii_lowercase + string.digits, k=15))
        test_url = base_url if base_url.endswith('/') else base_url + '/'
        req = urllib.request.Request(
            test_url + garbage, method="GET",
            headers={'Connection': 'close', 'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                length = resp.headers.get('Content-Length')
                print(f"[*] Catch-all at {base_url}. Filtering size: {length}")
                return length
    except Exception:
        pass
    return None


def run_discovery(target_url, wordlist_path, threads=10, max_depth=None):
    global is_running
    is_running = True

    if max_depth is None:
        max_depth = 3

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            words = [w.strip() for w in f.read().splitlines() if w.strip()]
    except Exception:
        return

    visited = set()
    base = target_url if target_url.endswith('/') else target_url + '/'
    visited.add(base.rstrip('/'))

    # BFS: process one level at a time.
    # current_level = all base URLs to probe at this depth.
    # After probing, found directories become next_level.
    current_level = [base]

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        for _ in range(max_depth):
            if not is_running or not current_level:
                break

            next_level = []

            for base_url in current_level:
                if not is_running:
                    break

                baseline = get_baseline(base_url)
                futures = [
                    executor.submit(check_path, base_url, word, baseline)
                    for word in words
                    if is_running
                ]

                for future in concurrent.futures.as_completed(futures):
                    if not is_running:
                        break
                    found_dir = future.result()
                    if found_dir:
                        norm = found_dir.rstrip('/')
                        if norm not in visited:
                            visited.add(norm)
                            next_level.append(norm + '/')

            current_level = next_level


def stop_discovery():
    global is_running
    is_running = False