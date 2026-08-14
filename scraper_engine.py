#scraper_engine
import urllib.request
import urllib.parse
from html.parser import HTMLParser
import re
import queue
import threading

result_queue = queue.Queue()
is_running = False

regex_rules = {
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "Possible API Key": r"(?i)(?:key|api|token|secret)[\"'\s:=]+([A-Za-z0-9_-]{20,})"
}

class ScraperExtractor(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.hidden_inputs =[]
        self.js_files = set()

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        if tag == 'input':
            if attr_dict.get('type', '').lower() == 'hidden':
                name = attr_dict.get('name', 'Unknown')
                value = attr_dict.get('value', 'Empty')
                self.hidden_inputs.append((name, value))
        elif tag == 'script':
            if 'src' in attr_dict:
               raw_src = attr_dict['src']
               full_js_url = urllib.parse.urljoin(self.base_url, raw_src)
               self.js_files.add(full_js_url)

def run_scraper(target_url):
    global is_running
    is_running = True
    result_queue.put(("STATUS", f"Scraping {target_url}..."))
    try:
        req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            html_bytes = response.read()
            html_text = html_bytes.decode('utf-8', errors='ignore')
            extractor = ScraperExtractor(target_url)
            extractor.feed(html_text)
            for name, value in extractor.hidden_inputs:
                result_queue.put(("HIDDEN INPUT", f"Name: {name} | Value: {value}"))
            for js_file in extractor.js_files:
                result_queue.put(("JS FILE", js_file))
            for label, pattern in regex_rules.items():
                matches = re.findall(pattern, html_text)
                for match in set(matches):
                    result_queue.put((label, match))
        result_queue.put(("DONE", "Scraping complete"))
    except Exception as e:
        result_queue.put(("ERROR", str(e)))
    is_running = False

def stop_scraper():
    global is_running
    is_running = False