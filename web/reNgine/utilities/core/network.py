"""
Core network utilities.

This module provides pure network functions with no external dependencies
beyond standard Python libraries. These functions form the foundation of the
modular utilities architecture.

Key principles:
1. Pure functions with no side effects
2. No external dependencies beyond standard library
3. No imports from other reNgine modules
4. Stateless and thread-safe
5. Easy to test and reuse
"""

import ipaddress
import socket
import urllib.parse
from typing import List, Optional, Tuple, Union


class ParsedURL:
    """Simple class to represent parsed URL components."""
    
    def __init__(self, scheme: str = "", netloc: str = "", path: str = "", 
                 params: str = "", query: str = "", fragment: str = "",
                 hostname: Optional[str] = None, port: Optional[int] = None,
                 username: Optional[str] = None, password: Optional[str] = None):
        self.scheme = scheme
        self.netloc = netloc
        self.path = path
        self.params = params
        self.query = query
        self.fragment = fragment
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password


def parse_url(url: str) -> Optional[ParsedURL]:
    """
    Parse URL into components.
    
    Args:
        url: URL to parse
        
    Returns:
        ParsedURL object with URL components or None if invalid
    """
    try:
        parsed = urllib.parse.urlparse(url)
        
        # Consider URL invalid if it doesn't have a scheme or netloc and is not a simple domain
        if not parsed.scheme and not parsed.netloc and not (parsed.path and '.' in parsed.path):
            return None
            
        return ParsedURL(
            scheme=parsed.scheme,
            netloc=parsed.netloc,
            path=parsed.path,
            params=parsed.params,
            query=parsed.query,
            fragment=parsed.fragment,
            hostname=parsed.hostname,
            port=parsed.port,
            username=parsed.username,
            password=parsed.password
        )
    except Exception:
        return None


def build_url(scheme: str, hostname: str, port: Optional[int] = None, 
              path: str = "", query: str = "", fragment: str = "") -> str:
    """
    Build URL from components.
    
    Args:
        scheme: URL scheme (http, https, etc.)
        hostname: Hostname
        port: Port number
        path: URL path
        query: Query string
        fragment: URL fragment
        
    Returns:
        Built URL string
    """
    netloc = f"{hostname}:{port}" if port and port not in (80, 443) else hostname
    return urllib.parse.urlunparse((scheme, netloc, path, "", query, fragment))


def extract_domain_from_url(url: str) -> Optional[str]:
    """
    Extract domain from URL.
    
    Args:
        url: URL to extract domain from
        
    Returns:
        Domain name or None if invalid
    """
    if parsed := parse_url(url):
        if parsed.hostname:
            return parsed.hostname
        elif parsed.path and '.' in parsed.path and not parsed.scheme:
            # Handle case where URL is just a domain (e.g., "example.com")
            return parsed.path
    return None


def extract_port_from_url(url: str) -> Optional[int]:
    """
    Extract port from URL.
    
    Args:
        url: URL to extract port from
        
    Returns:
        Port number or None if not specified
    """
    parsed = parse_url(url)
    if not parsed:
        return None
    
    if parsed['port']:
        return parsed['port']
    
    # Default ports
    if parsed['scheme'] == 'http':
        return 80
    elif parsed['scheme'] == 'https':
        return 443
    
    return None


def extract_path_from_url(url: str) -> str:
    """
    Extract path from URL.
    
    Args:
        url: URL to extract path from
        
    Returns:
        URL path
    """
    parsed = parse_url(url)
    return parsed['path'] if parsed else ""


def extract_query_from_url(url: str) -> str:
    """
    Extract query string from URL.
    
    Args:
        url: URL to extract query from
        
    Returns:
        Query string
    """
    parsed = parse_url(url)
    return parsed['query'] if parsed else ""


def parse_query_string(query: str) -> dict:
    """
    Parse query string into dictionary.
    
    Args:
        query: Query string to parse
        
    Returns:
        Dictionary of query parameters
    """
    return urllib.parse.parse_qs(query)


def build_query_string(params: dict) -> str:
    """
    Build query string from dictionary.
    
    Args:
        params: Dictionary of parameters
        
    Returns:
        Query string
    """
    return urllib.parse.urlencode(params, doseq=True)


def normalize_url(url: str) -> str:
    """
    Normalize URL by removing unnecessary components.
    
    Args:
        url: URL to normalize
        
    Returns:
        Normalized URL
    """
    if parsed := parse_url(url):
        return build_url(
            parsed['scheme'],
            parsed['hostname'],
            parsed['port'],
            parsed['path'],
            parsed['query'],
        )
    else:
        return url


def resolve_hostname(hostname: str) -> List[str]:
    """
    Resolve hostname to IP addresses.
    
    Args:
        hostname: Hostname to resolve
        
    Returns:
        List of IP addresses
    """
    try:
        # Get all IPs for the hostname
        hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(hostname)
        return ipaddrlist
    except socket.gaierror:
        return []


def reverse_dns_lookup(ip: str) -> Optional[str]:
    """
    Perform reverse DNS lookup.
    
    Args:
        ip: IP address to lookup
        
    Returns:
        Hostname or None if not found
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None


def is_private_ip(ip: str) -> bool:
    """
    Check if IP address is private.
    
    Args:
        ip: IP address to check
        
    Returns:
        True if IP is private
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def is_loopback_ip(ip: str) -> bool:
    """
    Check if IP address is loopback.
    
    Args:
        ip: IP address to check
        
    Returns:
        True if IP is loopback
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_loopback
    except ValueError:
        return False


def is_multicast_ip(ip: str) -> bool:
    """
    Check if IP address is multicast.
    
    Args:
        ip: IP address to check
        
    Returns:
        True if IP is multicast
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_multicast
    except ValueError:
        return False


def is_reserved_ip(ip: str) -> bool:
    """
    Check if IP address is reserved.
    
    Args:
        ip: IP address to check
        
    Returns:
        True if IP is reserved
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_reserved
    except ValueError:
        return False


def get_ip_version(ip: str) -> Optional[int]:
    """
    Get IP version (4 or 6).
    
    Args:
        ip: IP address to check
        
    Returns:
        IP version (4 or 6) or None if invalid
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.version
    except ValueError:
        return None


def ip_to_int(ip: str) -> Optional[int]:
    """
    Convert IP address to integer.
    
    Args:
        ip: IP address to convert
        
    Returns:
        Integer representation or None if invalid
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return int(ip_obj)
    except ValueError:
        return None


def int_to_ip(ip_int: int, version: int = 4) -> Optional[str]:
    """
    Convert integer to IP address.
    
    Args:
        ip_int: Integer representation
        version: IP version (4 or 6)
        
    Returns:
        IP address string or None if invalid
    """
    try:
        ip_obj = ipaddress.ip_address(ip_int)
        return str(ip_obj) if ip_obj.version == version else None
    except ValueError:
        return None


def get_network_info(ip: str, prefixlen: int) -> Optional[dict]:
    """
    Get network information for IP and prefix length.
    
    Args:
        ip: IP address
        prefixlen: Prefix length
        
    Returns:
        Dictionary with network information or None if invalid
    """
    try:
        network = ipaddress.ip_network(f"{ip}/{prefixlen}", strict=False)
        return {
            'network': str(network.network_address),
            'broadcast': str(network.broadcast_address),
            'netmask': str(network.netmask),
            'hostmask': str(network.hostmask),
            'num_addresses': network.num_addresses,
            'num_hosts': network.num_addresses - 2 if network.num_addresses > 2 else network.num_addresses
        }
    except ValueError:
        return None


def is_ip_in_network(ip: str, network: str) -> bool:
    """
    Check if IP address is in network.
    
    Args:
        ip: IP address to check
        network: Network in CIDR notation
        
    Returns:
        True if IP is in network
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        network_obj = ipaddress.ip_network(network, strict=False)
        return ip_obj in network_obj
    except ValueError:
        return False


def get_common_ports(count: Optional[int] = None) -> List[int]:
    """
    Get list of common ports.
    
    Args:
        count: Number of ports to return (optional)
    
    Returns:
        List of common port numbers
    """
    ports = [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306, 6379, 27017
    ]
    return ports[:count] if count is not None else ports


def get_web_ports() -> List[int]:
    """
    Get list of common web ports.
    
    Returns:
        List of web port numbers
    """
    return [80, 443, 8080, 8443, 8000, 8008, 8888, 9000, 9080, 9443]


def get_database_ports() -> List[int]:
    """
    Get list of common database ports.
    
    Returns:
        List of database port numbers
    """
    return [3306, 5432, 6379, 27017, 1433, 1521, 5984, 9200]


def get_ssh_ports() -> List[int]:
    """
    Get list of common SSH ports.
    
    Returns:
        List of SSH port numbers
    """
    return [22, 2222, 2200]


def get_ftp_ports() -> List[int]:
    """
    Get list of common FTP ports.
    
    Returns:
        List of FTP port numbers
    """
    return [21, 2121, 990]


def get_smtp_ports() -> List[int]:
    """
    Get list of common SMTP ports.
    
    Returns:
        List of SMTP port numbers
    """
    return [25, 587, 465, 2525]


def get_pop3_ports() -> List[int]:
    """
    Get list of common POP3 ports.
    
    Returns:
        List of POP3 port numbers
    """
    return [110, 995]


def get_imap_ports() -> List[int]:
    """
    Get list of common IMAP ports.
    
    Returns:
        List of IMAP port numbers
    """
    return [143, 993]


def get_dns_ports() -> List[int]:
    """
    Get list of common DNS ports.
    
    Returns:
        List of DNS port numbers
    """
    return [53, 5353]


def get_ntp_ports() -> List[int]:
    """
    Get list of common NTP ports.
    
    Returns:
        List of NTP port numbers
    """
    return [123]


def get_snmp_ports() -> List[int]:
    """
    Get list of common SNMP ports.
    
    Returns:
        List of SNMP port numbers
    """
    return [161, 162]


def get_ldap_ports() -> List[int]:
    """
    Get list of common LDAP ports.
    
    Returns:
        List of LDAP port numbers
    """
    return [389, 636]


def get_rdp_ports() -> List[int]:
    """
    Get list of common RDP ports.
    
    Returns:
        List of RDP port numbers
    """
    return [3389]


def get_vnc_ports() -> List[int]:
    """
    Get list of common VNC ports.
    
    Returns:
        List of VNC port numbers
    """
    return [5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909]


def get_telnet_ports() -> List[int]:
    """
    Get list of common Telnet ports.
    
    Returns:
        List of Telnet port numbers
    """
    return [23, 2323]


def get_http_ports() -> List[int]:
    """
    Get list of common HTTP ports.
    
    Returns:
        List of HTTP port numbers
    """
    return [80, 8080, 8000, 8008, 8888, 9000, 9080]


def get_https_ports() -> List[int]:
    """
    Get list of common HTTPS ports.
    
    Returns:
        List of HTTPS port numbers
    """
    return [443, 8443, 9443]


def get_well_known_ports() -> List[int]:
    """
    Get list of well-known ports (0-1023).
    
    Returns:
        List of well-known port numbers
    """
    return list(range(1, 1024))


def get_registered_ports() -> List[int]:
    """
    Get list of registered ports (1024-49151).
    
    Returns:
        List of registered port numbers
    """
    return list(range(1024, 49152))


def get_dynamic_ports() -> List[int]:
    """
    Get list of dynamic ports (49152-65535).
    
    Returns:
        List of dynamic port numbers
    """
    return list(range(49152, 65536))


def get_port_range(start: int, end: int) -> List[int]:
    """
    Get list of ports in range.
    
    Args:
        start: Start port number
        end: End port number
        
    Returns:
        List of port numbers in range
    """
    if start < 1 or end > 65535 or start > end:
        return []
    
    return list(range(start, end + 1))


def is_well_known_port(port: int) -> bool:
    """
    Check if port is well-known (0-1023).
    
    Args:
        port: Port number to check
        
    Returns:
        True if port is well-known
    """
    return 1 <= port <= 1023


def is_registered_port(port: int) -> bool:
    """
    Check if port is registered (1024-49151).
    
    Args:
        port: Port number to check
        
    Returns:
        True if port is registered
    """
    return 1024 <= port <= 49151


def is_dynamic_port(port: int) -> bool:
    """
    Check if port is dynamic (49152-65535).
    
    Args:
        port: Port number to check
        
    Returns:
        True if port is dynamic
    """
    return 49152 <= port <= 65535


def get_port_type(port: int) -> str:
    """
    Get port type category.
    
    Args:
        port: Port number to check
        
    Returns:
        Port type category
    """
    if is_well_known_port(port):
        return "well-known"
    elif is_registered_port(port):
        return "registered"
    elif is_dynamic_port(port):
        return "dynamic"
    else:
        return "invalid"


def url_encode(text: str) -> str:
    """
    URL encode text.
    
    Args:
        text: Text to encode
        
    Returns:
        URL encoded text
    """
    return urllib.parse.quote(text)


def url_decode(text: str) -> str:
    """
    URL decode text.
    
    Args:
        text: Text to decode
        
    Returns:
        URL decoded text
    """
    return urllib.parse.unquote(text)


def parse_host_port(hostport: str, default_port: Optional[int] = None) -> Tuple[str, Optional[int]]:
    """
    Parse host:port string.
    
    Args:
        hostport: Host:port string
        default_port: Default port if not specified
        
    Returns:
        Tuple of (host, port)
    """
    if ':' not in hostport:
        return hostport, default_port
    host, port_str = hostport.rsplit(':', 1)
    try:
        return host, int(port_str)
    except ValueError:
        return hostport, default_port


def build_host_port(host: str, port: Optional[int] = None) -> str:
    """
    Build host:port string.
    
    Args:
        host: Hostname
        port: Port number
        
    Returns:
        Host:port string
    """
    return f"{host}:{port}" if port else host
