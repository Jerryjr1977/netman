# scanner_engine
import asyncio
import re
import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

COMMON_SERVICES = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP",
    631: "IPP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Proxy",
}

PORT_RANGE_RE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")


def resolve_target(target):
    """Resolve a hostname or IP address to usable socket addresses."""
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        logger.error(f"DNS resolution failed for '{target}': {exc}")
        raise ValueError(f"Unable to resolve target '{target}': {exc}") from exc

    addresses = []
    seen = set()
    for family, _, _, _, sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        if sockaddr in seen:
            continue
        seen.add(sockaddr)
        addresses.append((family, sockaddr))

    if not addresses:
        logger.error(f"No usable addresses resolved for '{target}'")
        raise ValueError(f"No usable address found for '{target}'")

    logger.debug(f"Resolved {target} to {len(addresses)} address(es)")
    return addresses


def guess_service(port):
    return COMMON_SERVICES.get(port, "unknown")


def clean_banner(data):
    if not data:
        return ""
    try:
        banner = data.decode('utf-8', errors='ignore').strip()
    except Exception:
        banner = str(data)
    return re.sub(r"\s+", " ", banner)


def scan_port(address_family, sockaddr, port, timeout):
    """Scan a single port over a specific address family and capture a banner."""
    try:
        with socket.socket(address_family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if address_family == socket.AF_INET6:
                sock.connect((sockaddr[0], port, sockaddr[2], sockaddr[3]))
            else:
                sock.connect((sockaddr[0], port))

            banner = b""
            try:
                sock.settimeout(min(1.0, timeout))
                banner = sock.recv(2048)
            except (socket.timeout, OSError):
                banner = b""

            logger.debug(f"Port {port}/{sockaddr[0]} open")
            return {
                "port": port,
                "address": sockaddr[0],
                "family": "IPv6" if address_family == socket.AF_INET6 else "IPv4",
                "status": "open",
                "service": guess_service(port),
                "banner": clean_banner(banner),
            }
    except OSError as e:
        logger.debug(f"Port {port}/{sockaddr[0]} closed or filtered: {e}")
        return None


def parse_ports(port_string):
    """Parse port strings like '22,80,443,1000-1010'."""
    clean_ports = set()
    for token in port_string.split(','):
        token = token.strip()
        if not token:
            continue

        match = PORT_RANGE_RE.match(token)
        if not match:
            logger.debug(f"Skipping invalid port token: {token}")
            continue

        start = int(match.group(1))
        end = int(match.group(2)) if match.group(2) else start
        if start < 1 or end > 65535 or start > end:
            logger.warning(f"Port range out of bounds: {start}-{end}")
            continue

        for port in range(start, end + 1):
            clean_ports.add(port)

    logger.debug(f"Parsed {len(clean_ports)} port(s) from: {port_string}")
    return sorted(clean_ports)


async def _scan_port_async(target, port, timeout):
    """Async scan of a single port, with banner capture."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=timeout)
        banner = b""
        try:
            banner = await asyncio.wait_for(reader.read(2048), timeout=min(1.0, timeout))
        except asyncio.TimeoutError:
            banner = b""
        writer.close()
        await writer.wait_closed()
        logger.debug(f"Port {port}/{target} open (async)")
        return {
            "port": port,
            "address": target,
            "family": "IPv6" if ':' in target else "IPv4",
            "status": "open",
            "service": guess_service(port),
            "banner": clean_banner(banner),
        }
    except (OSError, asyncio.TimeoutError) as e:
        logger.debug(f"Port {port}/{target} closed: {e}")
        return {"port": port, "status": "closed"}


def run_scan_async(target, raw_ports, timeout, workers=100):
    """Scan ports asynchronously using asyncio."""
    port_list = parse_ports(raw_ports)
    if not port_list:
        logger.warning("No valid ports to scan")
        return []

    logger.info(f"Starting async scan of {target} ({len(port_list)} port(s))")

    async def _runner():
        semaphore = asyncio.Semaphore(min(workers, len(port_list)))

        async def sem_scan(port):
            async with semaphore:
                return await _scan_port_async(target, port, timeout)

        tasks = [asyncio.create_task(sem_scan(port)) for port in port_list]
        results = await asyncio.gather(*tasks)
        return [result for result in results if result.get("status") == "open"]

    try:
        open_ports = asyncio.run(_runner())
        logger.info(f"Async scan complete: {len(open_ports)} open port(s) found")
        return open_ports
    except Exception as e:
        logger.error(f"Async scan failed: {e}")
        return []


def run_scan(target, raw_ports, timeout, workers=100, use_async=True):
    """Scan ports on a target and return open port metadata."""
    if use_async:
        return run_scan_async(target, raw_ports, timeout, workers)

    try:
        target_addresses = resolve_target(target)
    except ValueError as e:
        logger.error(f"Target resolution failed: {e}")
        return []

    port_list = parse_ports(raw_ports)
    if not port_list:
        logger.warning("No valid ports to scan")
        return []

    logger.info(f"Starting thread-pool scan of {target} ({len(port_list)} port(s), {len(target_addresses)} address(es))")
    open_ports = []
    workers = min(workers, len(port_list), 200)
    
    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_port = {}
            for port in port_list:
                for family, sockaddr in target_addresses:
                    future = executor.submit(scan_port, family, sockaddr, port, timeout)
                    future_to_port[future] = port

            scanned = {}
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result and port not in scanned:
                        scanned[port] = result
                except Exception as e:
                    logger.debug(f"Scan task failed for port {port}: {e}")
                    continue

        open_ports = [scanned[port] for port in sorted(scanned)]
        logger.info(f"Thread-pool scan complete: {len(open_ports)} open port(s) found")
        return open_ports
        
    except Exception as e:
        logger.error(f"Thread-pool scan failed: {e}")
        return []
