#vuln_engine
import json
import urllib.request
import queue
import threading

result_queue = queue.Queue()
is_running = False

def parse_lockfile(file_path):
    packages = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Check for modern Lockfile Version 3 (uses "packages")
        if 'packages' in data:
            for path, info in data['packages'].items():
                if not path: # Skip the empty string (which represents the root app itself)
                    continue
                # Extract the real package name from paths like "node_modules/express"
                pkg_name = path.split('node_modules/')[-1]
                version = info.get('version', '')
                if version:
                    packages.append((pkg_name, version))
        
        # Fallback for older Lockfile Version 1/2 (uses "dependencies")
        elif 'dependencies' in data:
            for pkg_name, info in data['dependencies'].items():
                version = info.get('version', '')
                if version:
                    packages.append((pkg_name, version))

        # Use a set to automatically remove any duplicates, then return as a list
        return list(set(packages))
        
    except Exception as e:
        result_queue.put(("ERROR", f"Failed to parse lockfile: {e}"))
        return []
    
def check_osv_api(pkg_name, version, ecosystem):
    url = "https://api.osv.dev/v1/query"
    payload = {
        "version": version,
        "package": {
            "name": pkg_name,
            "ecosystem": ecosystem
        }
    }

    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            resp_data = json.loads(response.read().decode('utf-8'))
            if 'vulns' in resp_data:
                vuln_list = []
                for vuln in resp_data['vulns']:
                    vuln_id = vuln.get('id', 'Unknown ID')
                    aliases = vuln.get('aliases', [])
                    if aliases:
                        vuln_id += f" ({', '.join(aliases[:2])})"
                    vuln_list.append(vuln_id)
                return vuln_list
    except Exception as e:
        return [f"API Error"]
    return []

def run_scanner(file_path, ecosystem):
    global is_running
    is_running = True
    result_queue.put(("STATUS", f"Parsing lockfile..."))
    packages = parse_lockfile(file_path)
    if not packages:
        result_queue.put(("DONE", "No packages found or file unreadable."))
        is_running = False
        return
    result_queue.put(("STATUS", f"Found {len(packages)} packages. Starting scan..."))
    vulns_found = 0
    for pkg_name, version in packages:
        if not is_running:
            break
        result_queue.put(("SCANNING", f"Checking {pkg_name} v{version}"))
        vulns = check_osv_api(pkg_name, version, ecosystem)
        for vuln in vulns:
            vulns_found += 1
            result_queue.put(("VULNERABLE", f"[{pkg_name} v{version}] - {vuln}"))
    if is_running:
        result_queue.put(("DONE", f"Scan complete. Found {vulns_found} vulnerabilities."))
    else:
        result_queue.put(("DONE", "Scan aborted by user."))
    
    is_running = False

def stop_scanner():
    global is_running
    is_running = False