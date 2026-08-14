#api_engine
import urllib.request
import urllib.error
import urllib.parse
import json
import queue
import threading

result_queue = queue.Queue()
is_running = False

OPENAPI_ENDPOINTS = ['/openapi.json', '/swagger.json', '/api-docs', '/v2/api-docs']


def fetch_json(url, headers=None, timeout=10):
    headers = headers or {'Accept': 'application/json'}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        content_type = response.headers.get('Content-Type', '')
        if 'application/json' not in content_type and 'application/vnd.oai' not in content_type:
            raise ValueError(f'Unexpected Content-Type: {content_type}')
        return json.loads(response.read().decode('utf-8'))


def scan_graphql(target_url):
    global is_running
    is_running = True
    result_queue.put(("STATUS", f"Probing GraphQL at {target_url}"))
    query = {"query": "{ __schema { types { name kind fields { name } } } }"}
    data = json.dumps(query).encode('utf-8')
    try:
        req = urllib.request.Request(target_url, data=data, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=10) as response:
            resp_data = json.loads(response.read().decode('utf-8'))
            if 'data' in resp_data and '__schema' in resp_data['data']:
                result_queue.put(("VULNERABLE", 'GraphQL Introspection is ENABLED!'))
                return resp_data['data']['__schema']
            result_queue.put(("FAILED", "Endpoint reached, but Introspection is disabled."))
    except urllib.error.HTTPError as e:
        result_queue.put(("ERROR", f"HTTP Error: {e.code}"))
    except ValueError as e:
        result_queue.put(("ERROR", f"Response Error: {str(e)}"))
    except Exception as e:
        result_queue.put(("ERROR", f"Network Failure: {str(e)}"))

    return None


def parse_graphql_schema(schema_data):
    endpoints = []
    if not schema_data or 'types' not in schema_data:
        return endpoints
    for gql_type in schema_data['types']:
        name = gql_type.get('name', '')
        if name in ['Query', 'Mutation', 'Subscription']:
            fields = gql_type.get('fields')
            if fields:
                for field in fields:
                    field_name = field.get('name', 'Unknown')
                    endpoints.append(f"[{name}] {field_name}")
    return endpoints


def parse_openapi_paths(spec):
    endpoints = []
    paths = spec.get('paths', {})
    for path, methods in paths.items():
        if isinstance(methods, dict):
            for method in methods.keys():
                endpoints.append(f"[{method.upper()}] {path}")
    return endpoints


def scan_openapi(target_url):
    for candidate in OPENAPI_ENDPOINTS:
        try:
            spec_url = urllib.parse.urljoin(target_url, candidate)
            result_queue.put(("STATUS", f"Checking OpenAPI/Swagger at {spec_url}"))
            spec = fetch_json(spec_url)
            if spec and 'paths' in spec:
                result_queue.put(("VULNERABLE", f"OpenAPI schema found at {spec_url}"))
                return parse_openapi_paths(spec)
        except Exception:
            continue
    return []


def scan_rest(target_url):
    try:
        result_queue.put(("STATUS", f"Probing REST/JSON at {target_url}"))
        data = fetch_json(target_url, headers={'Accept': 'application/json'}, timeout=10)
        endpoints = []
        if isinstance(data, dict):
            if '_links' in data and isinstance(data['_links'], dict):
                for rel, info in data['_links'].items():
                    if isinstance(info, dict) and 'href' in info:
                        endpoints.append(f"[LINK] {info['href']}")
                    elif isinstance(info, list):
                        for item in info:
                            if isinstance(item, dict) and 'href' in item:
                                endpoints.append(f"[LINK] {item['href']}")
            else:
                for key in data.keys():
                    endpoints.append(f"[KEY] {key}")
        elif isinstance(data, list):
            endpoints.append(f"[JSON] array({len(data)})")
        return endpoints
    except Exception:
        return []

def run_api_scan(target_url):
    global is_running
    is_running = True
    result_queue.put(("STATUS", "Starting API discovery..."))

    endpoints = []
    schema = scan_graphql(target_url)
    if schema:
        result_queue.put(("STATUS", "Extracting GraphQL endpoints from schema..."))
        endpoints += parse_graphql_schema(schema)

    if is_running:
        openapi_endpoints = scan_openapi(target_url)
        endpoints += openapi_endpoints

    if is_running:
        rest_endpoints = scan_rest(target_url)
        endpoints += rest_endpoints

    unique_endpoints = []
    for ep in endpoints:
        if ep not in unique_endpoints:
            unique_endpoints.append(ep)

    if unique_endpoints:
        result_queue.put(("STATUS", f"Success! Found {len(unique_endpoints)} API endpoints."))
        for ep in unique_endpoints:
            if not is_running:
                break
            result_queue.put(("MAPPED", ep))
    else:
        result_queue.put(("FAILED", "No API endpoints discovered."))

    if is_running:
        result_queue.put(("DONE", "API Mapping Complete."))
    else:
        result_queue.put(("DONE", "Scan aborted by user"))

    is_running = False

def stop_api_scan():
    global is_running
    is_running = False
