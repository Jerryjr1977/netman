#crawler_engine
import urllib.request
import urllib.parse
from html.parser import HTMLParser
import queue
import threading

result_queue = queue.Queue()
is_running = False
visited_urls = set()

class LinkExtractor(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.found_links = set()

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for name, value in attrs:
                if name == 'href':
                    full_url = urllib.parse.urljoin(self.base_url, value)
                    parsed = urllib.parse.urlparse(full_url)
                    if parsed.scheme in ['http', 'https']:
                        clean_url = parsed._replace(fragment="").geturl()
                        self.found_links.add(clean_url)

def run_crawler(start_url, max_pages=100):
    global is_running, visited_urls
    is_running = True
    visited_urls.clear()
    url_queue = queue.Queue()
    url_queue.put(start_url)
    pages_crawled = 0
    while not url_queue.empty() and is_running and pages_crawled < max_pages:
        current_url = url_queue.get()
        if current_url in visited_urls:
            continue
        visited_urls.add(current_url)
        pages_crawled += 1
        result_queue.put(("SCANNING", current_url))
        try:
            req = urllib.request.Request(current_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' not in content_type:
                    continue
                html_bytes = response.read()
                html_text = html_bytes.decode('utf-8', errors='ignore')                
                extractor = LinkExtractor(current_url)
                extractor.feed(html_text)
                for link in extractor.found_links:
                    if link not in visited_urls:
                        url_queue.put(link)
                        result_queue.put(("FOUND", link))
        except Exception as e:
            result_queue.put(("ERROR", f"{current_url} - {str(e)}"))

    is_running = False
    result_queue.put(("DONE", f"Finished crawling {pages_crawled} pages."))

def stop_crawler():
    global is_running
    is_running = False