from concurrent.futures import ThreadPoolExecutor, as_completed
import contextlib
import socket
import subprocess

from celery.utils.log import get_task_logger
import validators

from reNgine.settings import DEFAULT_THREADS


try:
    import dns.resolver
    import dns.reversename

    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

logger = get_task_logger(__name__)


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
                logger.debug(f"Resolved {subdomain_name} -> {ip}")

    except socket.gaierror as e:
        logger.debug(f"DNS resolution failed for {subdomain_name}: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error resolving {subdomain_name}: {e}")

    return ips


def get_reverse_dns(ip_address):
    """Perform reverse DNS lookup to get the hostname for an IP address.

    Args:
        ip_address (str): IP address to perform reverse lookup on

    Returns:
        str or None: Hostname if successful, None if lookup fails
    """
    try:
        reverse_pointer = socket.gethostbyaddr(ip_address)[0]
        logger.debug(f"Reverse DNS lookup for {ip_address}: {reverse_pointer}")
        return reverse_pointer
    except (socket.herror, socket.gaierror, socket.timeout) as e:
        logger.debug(f"Reverse DNS lookup failed for {ip_address}: {str(e)}")
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
        logger.debug(f"Error getting DNS servers: {e}")
        dns_servers = ["8.8.8.8", "1.1.1.1"]

    return dns_servers


def check_host_alive(ip):
    """Quick ping check to see if host is alive"""
    try:
        cmd = ["ping", "-c", "1", "-W", "2", ip]

        result = subprocess.run(cmd, capture_output=True, timeout=5)
        is_alive = result.returncode == 0
        logger.debug(f"Ping {ip}: {'alive' if is_alive else 'dead'}")
        return is_alive
    except Exception as e:
        logger.debug(f"Ping {ip} failed: {e}")
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
                    logger.debug(f"Resolved {ip_str} to {hostname} using {dns_server}")
                    return hostname, dns_server

        except Exception as e:
            logger.debug(f"DNS resolution failed for {ip_str} using {dns_server}: {e}")
            continue

    return None, None


def _resolve_with_system_dns(ip_str):
    """Resolve IP using system DNS (Single Responsibility)"""
    try:
        (domain, domains, ips) = socket.gethostbyaddr(ip_str)
        if domain != ip_str:
            return domain, domains or [domain]
    except socket.herror:
        logger.debug(f"No PTR record for {ip_str}")

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
                logger.debug(f"DNS resolution timeout for {ip} after {dns_resolution_timeout}s: {e}")
                # Add IP even if resolution times out
                results.append(_create_failed_resolution_result(ip))
            except Exception as e:
                ip = future_to_ip[future]
                logger.debug(f"Error resolving {ip}: {e}")
                # Add IP even if resolution fails
                results.append(_create_failed_resolution_result(ip))

    return results
