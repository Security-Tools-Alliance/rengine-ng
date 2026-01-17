"""
DNS Wrapper for reNgine-ng - Smart DNS arguments injection.

This module automatically injects custom DNS server arguments into reconnaissance
tools that support native DNS configuration.

Supported tools:
- Subdomain discovery: subfinder, amass
- DNS tools: dnsx, massdns, puredns, shuffledns
- Port scanning: nmap, naabu
- HTTP tools: httpx, nuclei, katana, tlsx
- OSINT: theHarvester

Key features:
- Automatic DNS argument injection based on tool
- Per-scan DNS isolation (scan-specific configuration)
- Fallback to system DNS when no custom DNS configured
- Zero configuration required - automatically applied in run_command/stream_command

Usage:
    from reNgine.utilities.dns_wrapper import build_command_with_dns

    # Automatically adds DNS args if domain has custom DNS
    command = build_command_with_dns('subfinder', ['-d', 'example.com'], domain_obj)
    subprocess.run(command)

Note:
    For tools without native DNS support (EyeWitness, gospider, ffuf), use
    alternatives like httpx with -screenshot flag.
"""

import re

from celery.utils.log import get_task_logger


logger = get_task_logger(__name__)


# Tool DNS argument mapping
# Format: 'tool_name': (arg_format, supports_multiple)
# arg_format can be:
#   - 'flag_comma': -r 8.8.8.8,1.1.1.1
#   - 'flag_space': -r 8.8.8.8 -r 1.1.1.1
#   - 'flag_first': @8.8.8.8 (only first DNS)
#   - 'positional': 8.8.8.8 (positional argument)
DNS_ARGS_MAP = {
    # Subdomain discovery tools
    "subfinder": ("flag_comma", "-r"),
    "amass": ("flag_comma", "-r"),
    "assetfinder": (None, None),  # No DNS support - use alternatives
    # OSINT
    "theHarvester": ("flag_comma", "-e"),
    # DNS tools
    "dnsx": ("flag_comma", "-r"),
    "massdns": ("flag_space", "-r"),
    "puredns": ("flag_comma", "-r"),
    "shuffledns": ("flag_comma", "-r"),
    # Port scanning
    "nmap": ("flag_comma", "--dns-servers"),
    "naabu": ("flag_comma", "-r"),
    "masscan": (None, None),  # No DNS support
    # HTTP tools
    "httpx": ("flag_comma", "-r"),
    "nuclei": ("flag_comma", "-dns-resolver"),
    "katana": ("flag_comma", "-r"),
    "tlsx": ("flag_comma", "-r"),
    # Crawlers (no DNS support - use httpx instead)
    "gospider": (None, None),
    "hakrawler": (None, None),
    # Web tools (no DNS support)
    "ffuf": (None, None),
    "gobuster": (None, None),
    "feroxbuster": (None, None),
    # Screenshots (no DNS support - use httpx -screenshot instead)
    "EyeWitness": (None, None),
    "gowitness": (None, None),
}


def get_dns_args(tool_name, dns_servers):
    """
    Get DNS arguments for a specific tool.

    Args:
        tool_name (str): Name of the reconnaissance tool
        dns_servers (list): List of DNS server IPs

    Returns:
        list: Command-line arguments to add, or empty list if tool doesn't support DNS

    Examples:
        >>> get_dns_args("subfinder", ["8.8.8.8", "1.1.1.1"])
        ['-r', '8.8.8.8,1.1.1.1']

        >>> get_dns_args("dig", ["8.8.8.8"])
        ['@8.8.8.8']

        >>> get_dns_args("nmap", ["8.8.8.8", "1.1.1.1"])
        ['--dns-servers', '8.8.8.8,1.1.1.1']
    """
    if not dns_servers:
        return []

    # Get tool's DNS argument format
    tool_config = DNS_ARGS_MAP.get(tool_name, (None, None))
    arg_format, flag = tool_config

    if arg_format is None:
        # Tool doesn't support custom DNS
        logger.debug(f"Tool '{tool_name}' does not support custom DNS arguments")
        return []

    # Build arguments based on format
    if arg_format == "flag_comma":
        return [flag, ",".join(dns_servers)]

    elif arg_format == "flag_first":
        # Format: @8.8.8.8 (only first DNS)
        return [f"{flag}{dns_servers[0]}"]

    elif arg_format == "flag_space":
        # Format: -r 8.8.8.8 -r 1.1.1.1
        args = []
        for dns in dns_servers:
            args.extend([flag, dns])
        return args

    elif arg_format == "positional":
        # Format: command domain 8.8.8.8 (positional argument)
        return [dns_servers[0]]

    return []


def build_command_with_dns(tool_name, base_args, domain=None, dns_servers=None):
    """
    Build command with DNS arguments if custom DNS is configured.

    This function intelligently adds DNS arguments to tool commands based on:
    1. Domain object's custom DNS configuration
    2. Explicitly provided DNS servers
    3. Tool's native DNS support

    Args:
        tool_name (str): Name of the tool (e.g., 'subfinder', 'nmap')
        base_args (list): Base command arguments
        domain (Domain, optional): Domain object with potential custom DNS
        dns_servers (list, optional): Explicit DNS servers to use

    Returns:
        list: Complete command with DNS arguments injected

    Examples:
        >>> # Domain with custom DNS
        >>> domain = Domain.objects.get(name="internal.local")
        >>> domain.set_dns_servers(["172.16.0.1"])
        >>> cmd = build_command_with_dns("subfinder", ["-d", "internal.local"], domain)
        >>> # Returns: ['subfinder', '-r', '172.16.0.1', '-d', 'internal.local']

        >>> # Explicit DNS servers
        >>> cmd = build_command_with_dns(
        ...     "nmap", ["-sS", "192.168.1.1"], dns_servers=["172.16.0.1"]
        ... )
        >>> # Returns: ['nmap', '--dns-servers', '172.16.0.1', '-sS', '192.168.1.1']
    """
    # Determine DNS servers to use
    dns_list = []

    if dns_servers:
        # Explicit DNS servers provided
        dns_list = dns_servers if isinstance(dns_servers, list) else [dns_servers]
    elif domain and hasattr(domain, "get_dns_servers"):
        # Get from domain object
        dns_list = domain.get_dns_servers() or []

    # Filter out None, empty strings, and ensure all values are strings
    dns_list = [str(dns) for dns in dns_list if dns is not None and str(dns).strip()]

    # Check if DNS arguments already exist in base_args
    tool_config = DNS_ARGS_MAP.get(tool_name, (None, None))
    arg_format, flag = tool_config

    has_existing_dns = False
    if arg_format and flag:
        # Convert base_args to list if it's not already
        base_args_list = list(base_args or [])

        # Use regex to check for existing DNS flags
        if arg_format == "flag_first":
            # Match @server or @<anything>
            dns_flag_pattern = re.compile(rf"^{re.escape(flag)}\S*")
        else:
            # Match flags like -r, --dns-servers, --dns-servers=8.8.8.8, etc.
            dns_flag_pattern = re.compile(rf"^(?:{re.escape(flag)})(?:[ =].+)?$")
        has_existing_dns = any(dns_flag_pattern.match(arg) for arg in base_args_list)
    if has_existing_dns:
        logger.debug(f"DNS arguments already present in command for {tool_name}, skipping injection")
        return [tool_name] + list(base_args or [])

    # Build command
    command = [tool_name]

    # Add DNS arguments if we have DNS servers
    if dns_list:
        if dns_args := get_dns_args(tool_name, dns_list):
            command.extend(dns_args)
            logger.info(f"Added custom DNS to {tool_name}: {', '.join(dns_list)}")
        else:
            logger.debug(f"Tool {tool_name} does not support custom DNS, will use system DNS")

    # Add base arguments
    command.extend(base_args or [])

    return command


def tool_supports_custom_dns(tool_name):
    """
    Check if a tool supports custom DNS arguments natively.

    Args:
        tool_name (str): Name of the tool

    Returns:
        bool: True if tool supports custom DNS arguments
    """
    tool_config = DNS_ARGS_MAP.get(tool_name, (None, None))
    return tool_config[0] is not None


def get_domain_dns_servers(domain_obj):
    """
    Helper function to get DNS servers for a domain.

    Args:
        domain_obj: Domain object

    Returns:
        list: List of DNS server IPs, or empty list if none configured
    """
    if domain_obj and hasattr(domain_obj, "get_dns_servers"):
        return domain_obj.get_dns_servers()
    return []
