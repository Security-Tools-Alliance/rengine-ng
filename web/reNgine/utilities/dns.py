from concurrent.futures import ThreadPoolExecutor, as_completed
import contextlib
import socket
import subprocess
import threading

import validators

from reNgine.settings import DEFAULT_THREADS
from reNgine.utilities.logger import get_module_logger


# Thread-local storage for geolocalization collection
_thread_local = threading.local()


try:
    import dns.resolver
    import dns.reversename

    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

PREFIX_DNS = "[DNS]"
logger = get_module_logger(__name__)


def resolve_subdomain_ips(subdomain_name):
    """Simple DNS resolution to get IP addresses for a subdomain.

    Args:
        subdomain_name (str): Subdomain name to resolve

    Returns:
        list: List of IP addresses
    """
    ips = []
    try:
        # Get all IPs for the subdomain
        hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(subdomain_name)

        for ip in ipaddrlist:
            # Validate IP before adding
            if validators.ipv4(ip) or validators.ipv6(ip):
                ips.append(ip)
                logger.log_line(
                    PREFIX_DNS,
                    "RESOLVE",
                    "Resolved %s -> %s" % (subdomain_name, ip),
                    level="debug",
                )

    except socket.gaierror as e:
        logger.log_line(
            PREFIX_DNS,
            "RESOLVE",
            "DNS resolution failed for %s: %s" % (subdomain_name, e),
            level="debug",
        )
    except Exception as e:
        logger.log_line(
            PREFIX_DNS,
            "RESOLVE",
            "Unexpected error resolving %s: %s" % (subdomain_name, e),
            level="warning",
        )

    return ips


def collect_ip_for_geolocalization(ip_address):
    """Collect IP address for batch geolocalization.

    This function adds the IP to a thread-local collection that will be
    processed in batch at the end of the current task.

    Args:
        ip_address (str): IP address to collect
    """
    from reNgine.core.data import get_ip_info

    # Check if this is a private/internal IP address
    ip_info = get_ip_info(ip_address)
    if ip_info and ip_info.is_private:
        logger.log_line(
            PREFIX_DNS,
            "GEO",
            "Skipping geolocalization for private IP: %s" % (ip_address,),
            level="debug",
        )
        return

    # Get or create thread-local storage
    if not hasattr(_thread_local, "geo_ip_collection"):
        _thread_local.geo_ip_collection = set()

    # Add IP to collection (set automatically handles duplicates)
    _thread_local.geo_ip_collection.add(ip_address)
    logger.log_line(
        PREFIX_DNS,
        "GEO",
        "Collected IP %s for batch geolocalization" % (ip_address,),
        level="debug",
    )


def trigger_batch_geolocalization():
    """Trigger batch geolocalization for collected IP addresses.

    This function should be called at the end of tasks that collect IPs
    to process them in a single batch operation.

    Returns:
        dict | None: Result with key "count" (number of IPs processed), or None if no IPs collected.
    """
    from reNgine.tasks.geo import geo_localize_batch

    if not hasattr(_thread_local, "geo_ip_collection"):
        logger.log_line(PREFIX_DNS, "GEO", "No IPs collected for geolocalization", level="debug")
        return None

    collected_ips = list(_thread_local.geo_ip_collection)

    if not collected_ips:
        logger.log_line(PREFIX_DNS, "GEO", "No IPs collected for geolocalization", level="debug")
        return None

    _thread_local.geo_ip_collection.clear()

    logger.log_line(
        PREFIX_DNS,
        "GEO",
        "Triggering batch geolocalization for %s IP addresses" % (len(collected_ips),),
        level="info",
    )
    # Runs synchronously (Celery removed); callers must tolerate blocking.
    geo_localize_batch(collected_ips)

    return {"count": len(collected_ips)}


def with_batch_geolocalization(func):
    """Decorator to automatically trigger batch geolocalization at the end of tasks.

    This decorator wraps a function and automatically triggers batch geolocalization
    after the function completes, processing all IPs collected during execution.

    Args:
        func: Function to wrap

    Returns:
        Wrapped function
    """

    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            # Always trigger batch geolocalization, even if function fails
            trigger_batch_geolocalization()

    return wrapper


def get_reverse_dns(ip_address):
    """Perform reverse DNS lookup to get the hostname for an IP address.

    Args:
        ip_address (str): IP address to perform reverse lookup on

    Returns:
        str or None: Hostname if successful, None if lookup fails
    """
    try:
        reverse_pointer = socket.gethostbyaddr(ip_address)[0]
        logger.log_line(
            PREFIX_DNS,
            "REVERSE_DNS",
            "Reverse DNS lookup for %s: %s" % (ip_address, reverse_pointer),
            level="debug",
        )
        return reverse_pointer
    except (socket.herror, socket.gaierror, socket.timeout) as e:
        logger.log_line(
            PREFIX_DNS,
            "REVERSE_DNS",
            "Reverse DNS lookup failed for %s: %s" % (ip_address, e),
            level="debug",
        )
        return None


def get_current_dns_servers():
    """Get current system DNS servers"""
    dns_servers = []
    try:
        with contextlib.suppress(Exception):
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.strip().startswith("nameserver"):
                        dns_server = line.strip().split()[1]
                        dns_servers.append(dns_server)

        # Fallback to common DNS servers if none found
        if not dns_servers:
            dns_servers = ["8.8.8.8", "1.1.1.1"]

    except Exception as e:
        logger.log_line(
            PREFIX_DNS,
            "GET_SERVERS",
            "Error getting DNS servers: %s" % (e,),
            level="debug",
        )
        dns_servers = ["8.8.8.8", "1.1.1.1"]

    return dns_servers


def check_host_alive(ip):
    """Quick ping check to see if host is alive"""
    try:
        cmd = ["ping", "-c", "1", "-W", "2", ip]

        result = subprocess.run(cmd, capture_output=True, timeout=5)
        is_alive = result.returncode == 0
        logger.log_line(
            PREFIX_DNS,
            "PING",
            "Ping %s: %s" % (ip, "alive" if is_alive else "dead"),
            level="debug",
        )
        return is_alive
    except Exception as e:
        logger.log_line(
            PREFIX_DNS,
            "PING",
            "Ping %s failed: %s" % (ip, e),
            level="debug",
        )
        return False


def _create_dns_resolver(dns_server):
    """Create DNS resolver with specific server (Single Responsibility)"""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server]
    resolver.timeout = 2
    resolver.lifetime = 5
    return resolver


def _resolve_with_custom_dns(ip_str, dns_servers):
    """Resolve IP using custom DNS servers (Single Responsibility)"""
    if not DNS_AVAILABLE or not dns_servers:
        return None, None

    for dns_server in dns_servers:
        try:
            resolver = _create_dns_resolver(dns_server)
            reverse_name = dns.reversename.from_address(ip_str)
            answers = resolver.resolve(reverse_name, "PTR")

            for answer in answers:
                hostname = str(answer).rstrip(".")
                if hostname != ip_str:
                    logger.log_line(
                        PREFIX_DNS,
                        "RESOLVE_CUSTOM",
                        "Resolved %s to %s using %s" % (ip_str, hostname, dns_server),
                        level="debug",
                    )
                    return hostname, dns_server

        except Exception as e:
            logger.log_line(
                PREFIX_DNS,
                "RESOLVE_CUSTOM",
                "DNS resolution failed for %s using %s: %s" % (ip_str, dns_server, e),
                level="debug",
            )
            continue

    return None, None


def _resolve_with_system_dns(ip_str):
    """Resolve IP using system DNS (Single Responsibility)"""
    try:
        (domain, domains, ips) = socket.gethostbyaddr(ip_str)
        if domain != ip_str:
            return domain, domains or [domain]
    except socket.herror:
        logger.log_line(
            PREFIX_DNS,
            "RESOLVE_SYSTEM",
            "No PTR record for %s" % (ip_str,),
            level="debug",
        )

    return None, []


def resolve_ip_with_dns(ip_str, dns_servers, use_system_fallback=False):
    """
    Resolve an IP address using specific DNS servers (Open/Closed Principle)

    Args:
        ip_str (str): IP address to resolve
        dns_servers (list): List of DNS servers to use
        use_system_fallback (bool): Use system DNS as fallback

    Returns:
        dict: Resolved IP information
    """
    domain_info = {
        "ip": ip_str,
        "domain": ip_str,
        "domains": [],
        "ips": [],
        "resolved_by": None,
        "is_alive": False,  # Will be updated by ping task
    }

    # Try custom DNS first
    hostname, dns_server = _resolve_with_custom_dns(ip_str, dns_servers)
    if hostname:
        domain_info["domain"] = hostname
        domain_info["domains"].append(hostname)
        domain_info["resolved_by"] = dns_server
        return domain_info

    # Fallback to system DNS if needed
    if use_system_fallback:
        hostname, domains = _resolve_with_system_dns(ip_str)
        if hostname:
            domain_info["domain"] = hostname
            domain_info["domains"] = domains
            domain_info["resolved_by"] = "system"

    return domain_info


def _create_failed_resolution_result(ip):
    """Create result for failed IP resolution"""
    return {
        "ip": str(ip),
        "domain": str(ip),
        "domains": [],
        "ips": [],
        "resolved_by": None,
        "is_alive": check_host_alive(str(ip)),
    }


def resolve_ip_chunk(ip_chunk, dns_servers, use_system_fallback=False, dns_resolution_timeout=10):
    """
    Resolve a chunk of IPs in parallel (Interface Segregation)

    Args:
        ip_chunk (list): List of IPs to resolve
        dns_servers (list): DNS servers to use
        use_system_fallback (bool): Use system DNS as fallback
        dns_resolution_timeout (int, optional): Timeout in seconds for DNS resolution. Defaults to 10.

    Returns:
        list: List of resolved IP information
    """
    results = []

    # Use ThreadPoolExecutor for chunk-level parallelization
    with ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
        future_to_ip = {
            executor.submit(resolve_ip_with_dns, str(ip), dns_servers, use_system_fallback): ip for ip in ip_chunk
        }

        for future in as_completed(future_to_ip):
            try:
                result = future.result(timeout=dns_resolution_timeout)
                results.append(result)
            except TimeoutError as e:
                ip = future_to_ip[future]
                logger.log_line(
                    PREFIX_DNS,
                    "RESOLVE_CHUNK",
                    "DNS resolution timeout for %s after %ss: %s" % (ip, dns_resolution_timeout, e),
                    level="debug",
                )
                results.append(_create_failed_resolution_result(ip))
            except Exception as e:
                ip = future_to_ip[future]
                logger.log_line(
                    PREFIX_DNS,
                    "RESOLVE_CHUNK",
                    "Error resolving %s: %s" % (ip, e),
                    level="debug",
                )
                results.append(_create_failed_resolution_result(ip))

    return results
