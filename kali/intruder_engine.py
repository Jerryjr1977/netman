#intruder_engine
import socket
import re
import ssl
import time
import os
import concurrent.futures
import http_utils
import hashlib
import base64
from urllib import parse
import html
import queue
import json
import logging
import skimmer_engine

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

result_queue = queue.Queue()

def create_ssl_context():
    """Factory for SSL context creation with consistent settings."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context

def connect_socket(host, port, use_ssl=False, timeout=5.0):
    """Create and return a connected socket with optional SSL wrapping."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    if use_ssl:
        s = create_ssl_context().wrap_socket(s, server_hostname=host)
    s.connect((host, int(port)))
    return s

def fetch_macro_token(host, port, macro_request, macro_regex):
    """Extract macro tokens from a template request using regex."""
    macro_request = macro_request.replace('\r\n', '\n').replace('\n', '\r\n')
    if not macro_request.endswith('\r\n\r\n'):
        macro_request += '\r\n\r\n'
        
    try:
        s = connect_socket(host, port, use_ssl=(str(port) == "443"), timeout=5.0)
        s.sendall(macro_request.encode('utf-8', errors='ignore'))
        
        response_data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                response_data += chunk
        except socket.timeout:
            logger.debug("Macro fetch timeout (expected)")
        finally:
            s.close()
        
        if not response_data:
            logger.warning(f"Macro fetch returned empty response from {host}:{port}")
            return None
            
        resp_text = http_utils.decode_response(response_data)
        match = re.search(macro_regex, resp_text, re.DOTALL)
        if match:
            logger.debug(f"Macro tokens extracted: {len(match.groups())} groups")
            return match.groups()
        else:
            logger.warning(f"Macro regex did not match response")
            
    except Exception as e:
        logger.error(f"Macro fetch failed: {e}")
        
    return None

def process_payload_pipeline(payload, rules):
    processed_value = payload
    for rule in rules:
        if rule != "None":
            processed_value = apply_rule(processed_value, rule)
    return processed_value

def apply_rule(payload, rule):
    if rule == "Base64 Encode":
        return base64.b64encode(payload.encode('utf-8')).decode('utf-8')
    elif rule == "Base64 Decode":
        try:
            return base64.b64decode(payload.encode('utf-8')).decode('utf-8')
        except Exception:
            return payload
    elif rule == "MD5 Hash":
        return hashlib.md5(payload.encode('utf-8')).hexdigest()
    elif rule == "SHA-1 Hash":
        return hashlib.sha1(payload.encode('utf-8')).hexdigest()
    elif rule == "SHA-256 Hash":
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()
    elif rule == "URL Encode":
        return parse.quote(payload)
    elif rule == "URL Decode":
        return parse.unquote(payload)
    elif rule == "HTML Encode":
        return html.escape(payload)
    elif rule == "HTML Decode":
        return html.unescape(payload)
    elif rule == "ASCII Encode":
        return str(ord(payload))
    elif rule == "SQL Hex":
        hex_val = "".join([hex(ord(c))[2:] for c in payload])
        return "0x" + hex_val
    elif rule == "JSON Encode":
        return json.dumps(payload)
    elif rule == "Double URL Encode":
        first_pass = parse.quote(payload)
        return parse.quote(first_pass)
    elif rule == "URL Encode All":
        return "".join(f"%{ord(c):02x}" for c in payload)
    return payload


def run_attack_loop(host, port, template, attack_type, wordlist_path, wordlist2_path, match_str, progress_var=None, rule1=[], rule2=[], delay_ms=0, macro_req="", macro_reg="", max_threads=10):
    try:
        if os.path.exists("debug_response.html"):
            os.remove("debug_response.html")
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            words1 = f.read().splitlines()
        words2 =[]
        if attack_type in ["Pitchfork", "Cluster Bomb"]:
            with open(wordlist2_path, 'r', encoding='utf-8', errors='ignore') as f:
                words2 =f.read().splitlines()
    except Exception as e:
        logger.error(f"Could not load wordlist: {e}")
        result_queue.put(("ERROR", "Wordlist Load Failed", 0, 0, "N/A", "N/A", str(e), "N/A"))
        return
    logger.info(f"Starting {attack_type} attack with {max_threads} threads...")
    futures = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        if attack_type == "Sniper":
            if "^1^" not in template:
                logger.error("Sniper requires a ^1^ marker in template")
                return
            for word in words1:
                processed_word = process_payload_pipeline(word, rule1)
                attack_request = template.replace("^1^", processed_word)
                if delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)
                futures.append(executor.submit(fire_payload, host, port, attack_request, processed_word, match_str, macro_req, macro_reg))

        elif attack_type == "Pitchfork":
            if "^1^" not in template or "^2^" not in template:
                logger.error("Pitchfork requires ^1^ and ^2^ markers in template")
                return
            for w1, w2 in zip(words1, words2):
                processed_w1 = process_payload_pipeline(w1, rule1)
                processed_w2 = process_payload_pipeline(w2, rule2)
                attack_request = template.replace("^1^", processed_w1).replace("^2^", processed_w2)
                combined_payload_name = f"{processed_w1} : {processed_w2}"
                if delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)
                futures.append(executor.submit(fire_payload, host, port, attack_request, combined_payload_name, match_str, macro_req, macro_reg))

        elif attack_type == "Cluster Bomb":
            if "^1^" not in template or "^2^" not in template:
                logger.error("Cluster Bomb requires ^1^ and ^2^ markers in template")
                return
            for w1 in words1:
                processed_w1 = process_payload_pipeline(w1, rule1)
                for w2 in words2:
                    processed_w2 = process_payload_pipeline(w2, rule2)
                    attack_request = template.replace("^1^", processed_w1).replace("^2^", processed_w2)
                    combined_payload_name = f"{processed_w1} : {processed_w2}"
                    if delay_ms > 0:
                        time.sleep(delay_ms / 1000.0)
                    futures.append(executor.submit(fire_payload, host, port, attack_request, combined_payload_name, match_str, macro_req, macro_reg))
        total_tasks = len(futures)
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            if progress_var:
                progress_var.set((completed / total_tasks) * 100)
        logger.info(f"Intruder attack complete: {total_tasks} payloads sent")

def fire_payload(host, port, attack_request, table_label, match_str, macro_req="", macro_reg=""):
    if macro_req != "" and macro_reg != "":
        fresh_tokens = fetch_macro_token(host, port, macro_req, macro_reg)
        if fresh_tokens:
            logger.debug(f"Macro extracted: {len(fresh_tokens)} tokens")
            for i, token in enumerate(fresh_tokens):
                marker = f"^MACRO{i+1}^"
                attack_request = attack_request.replace(marker, token)
        else:
            logger.error(f"Macro extraction failed for payload {table_label}")
            result_queue.put((table_label, "Macro Error", 0, 0, "N/A", "N/A", "Failed to extract Macro tokens"))
            return
    attack_request = attack_request.replace('\r\n', '\n').replace('\n', '\r\n')
    
    if '\r\n\r\n' in attack_request:
        headers, body = attack_request.split('\r\n\r\n', 1)
        body_bytes = body.encode('utf-8', errors='ignore')
        headers = re.sub(r"Content-Length: \d+", f"Content-Length: {len(body_bytes)}", headers, flags=re.IGNORECASE)
        attack_request = headers + "\r\n\r\n" + body + "\r\n\r\n"
    else:
        attack_request += "\r\n\r\n"

    payload_bytes = attack_request.encode('utf-8', errors='ignore')
    for attempt in range(3):
        try:
            s = connect_socket(host, port, use_ssl=(str(port) == "443"), timeout=5.0)
            start_time = time.time()
            s.sendall(payload_bytes)

            response_chunk = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    else:
                        response_chunk += chunk
            except socket.timeout:
                logger.debug(f"Timeout receiving response (attempt {attempt+1}/3)")
            finally:
                s.close()
            end_time = time.time()
            response_time = int((end_time - start_time) * 1000)
        
            status_code = "Unknown"
            location = "None"
            response_len = 0
            match_found = ""
            resp_text = ""
            if response_chunk:
                resp_text = http_utils.decode_response(response_chunk)
                response_len = len(resp_text)
                skimmer_hits = skimmer_engine.scan_payload(resp_text)
                skimmer_summary = ", ".join(skimmer_hits) if skimmer_hits else "None"
                if match_str != "":
                    match_found = "True" if match_str in resp_text else "False" 
                
                if not os.path.exists("debug_response.html"):
                    with open("debug_response.html", "w", encoding="utf-8") as f:
                        f.write(resp_text)
                first_line = resp_text.split('\n')[0]
                if len(first_line.split(' ')) > 1:
                    status_code = first_line.split(' ', 1)[1]
                    
                for line in resp_text.split('\n'):
                    if line.lower().startswith("location:"):
                        location = line.split(':', 1)[1].strip()
                        break
                if not skimmer_summary or skimmer_summary == "":
                    skimmer_summary = "None"
                    
            result_queue.put((table_label, status_code, response_len, response_time, location, match_found, resp_text, skimmer_summary))
            break
        except Exception as e:
            if attempt == 2:
                logger.error(f"Payload {table_label} failed after 3 attempts: {e}")
                result_queue.put((table_label, "Error", 0, 0, "N/A", "N/A", "Connection Failed - No Response data", "N/A"))
            else:
                logger.debug(f"Payload {table_label} retry {attempt+1}/3 after: {e}")
                time.sleep(1)