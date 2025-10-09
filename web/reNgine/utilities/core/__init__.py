"""
Core utilities package.

This package contains pure utility functions with no external dependencies.
These are the foundational "leaf modules" of the utilities architecture.
"""

import ipaddress
import subprocess
import re
import validators
import logging

from .data import *
from .file import *
from .formatting import *
from .network import *
from .validation import *

logger = logging.getLogger(__name__)

__all__ = [
    # Data utilities
    'is_iterable',
    'chunk_list',
    'remove_duplicates',
    'replace_nulls',
    'deep_merge_dicts',
    'filter_dict',
    'sort_dict_by_key',
    'sort_dict_by_value',
    'extract_columns',
    'extract_numbers',
    'extract_emails',
    'extract_urls',
    'extract_ips',
    'normalize_whitespace',
    'truncate_string',
    'convert_to_string',
    'convert_to_int',
    'convert_to_float',
    'convert_to_bool',
    'remove_control_characters',
    'remove_ansi_sequences',
    'safe_get',
    'safe_set',
    'exclude_dict_keys',
    'generate_hash',
    
    # File utilities
    'read_file_content',
    'write_file_content',
    'ensure_directory_exists',
    'get_file_size',
    'get_file_extension',
    'read_file_lines',
    'write_file_binary',
    'copy_file',
    'delete_file',
    'list_files',
    'find_files',
    'remove_file_or_pattern',
    'file_exists',
    'join_path',
    'get_filename_without_extension',
    'read_json_file',
    'write_json_file',
    
    # Formatting utilities
    'format_duration',
    'format_bytes',
    'format_number',
    'format_percentage',
    'format_timestamp',
    'format_file_size',
    'format_memory_usage',
    'format_cpu_usage',
    'format_network_speed',
    'format_uptime',
    
    # Network utilities
    'parse_url',
    'extract_domain_from_url',
    'extract_path_from_url',
    'is_private_ip',
    'is_loopback_ip',
    'is_multicast_ip',
    'is_reserved_ip',
    'get_ip_version',
    'get_common_ports',
    'resolve_hostname',
    'reverse_dns_lookup',
    
    # Validation utilities
    'is_valid_url',
    'is_valid_domain',
    'is_valid_email',
    'is_valid_port',
    'is_valid_ip',
    'is_valid_ipv4',
    'is_valid_ipv6',
    'is_valid_json',
    'is_valid_xml',
    'is_valid_filename',
    'is_valid_path',
    'is_valid_cidr',
    'is_valid_mac_address',
    
    # IP utilities
    'get_ip_info',
    'get_ips_from_cidr_range',
    'geoiplookup',
    
    # Data utilities
    'get_data_from_post_request',
    'safe_int_cast'
]


def get_ip_info(ip_address):
    """
    get_ip_info retrieves information about a given IP address, determining whether it is an IPv4 or IPv6 address. It returns an appropriate IP address object if the input is valid, or None if the input is not a valid IP address.

    Args:
        ip_address (str): The IP address to validate and retrieve information for.

    Returns:
        IPv4Address or IPv6Address or None: An IP address object if the input is valid, otherwise None.
    """
    is_ipv4 = bool(validators.ipv4(ip_address))
    is_ipv6 = bool(validators.ipv6(ip_address))
    ip_data = None
    if is_ipv4:
        ip_data = ipaddress.IPv4Address(ip_address)
    elif is_ipv6:
        ip_data = ipaddress.IPv6Address(ip_address)
    else:
        return None
    return ip_data


def geoiplookup(ip_address):
    """
    Execute geoiplookup command with proper input validation and robust output parsing.

    Args:
        ip_address (str): IP address to geolocalize

    Returns:
        tuple: (success: bool, country_iso: str, country_name: str, error: str)
    """
    # Validate IP address format to prevent injection
    if not (validators.ipv4(ip_address) or validators.ipv6(ip_address)):
        logger.warning(f"Invalid IP address format: {ip_address}")
        return False, None, None, "Invalid IP address format"

    try:
        # Use subprocess with argument list to prevent shell injection
        result = subprocess.run(
            ["geoiplookup", ip_address],
            capture_output=True,
            text=True,
            timeout=30,  # 30 second timeout
            check=False,
        )

        if result.returncode != 0:
            logger.warning(f"geoiplookup failed for {ip_address}: {result.stderr}")
            return False, None, None, result.stderr or "geoiplookup failed"

        # Parse output with robust regex instead of fragile string splitting
        output = result.stdout.strip()

        # Check for error conditions
        if "IP Address not found" in output or "can't resolve hostname" in output:
            logger.debug(f"IP address not found in geoiplookup database: {ip_address}")
            return False, None, None, "IP address not found"

        # Use regex to parse geoiplookup output more safely
        # Expected format: "GeoIP Country Edition: US, United States"
        geo_pattern = r"GeoIP\s+Country\s+Edition:\s*([A-Z]{2}),\s*(.+)"
        match = re.search(geo_pattern, output)

        if match:
            country_iso = match.group(1).strip()
            country_name = match.group(2).strip()
            logger.debug(f"Successfully parsed geolocalization for {ip_address}: {country_iso}, {country_name}")
            return True, country_iso, country_name, None
        else:
            logger.warning(f"Unexpected geoiplookup output format for {ip_address}: {output}")
            return False, None, None, f"Unexpected output format: {output}"

    except subprocess.TimeoutExpired:
        logger.error(f"geoiplookup timeout for {ip_address}")
        return False, None, None, "geoiplookup timeout"
    except Exception as e:
        logger.error(f"geoiplookup error for {ip_address}: {e}")
        return False, None, None, str(e)


def get_ips_from_cidr_range(target):
    """
    get_ips_from_cidr_range generates a list of IP addresses from a given CIDR range. It returns the list of valid IPv4 addresses or logs an error if the provided CIDR range is invalid.

    Args:
        target (str): The CIDR range from which to generate IP addresses.

    Returns:
        list of str: A list of IP addresses as strings if the CIDR range is valid; otherwise, an empty list is returned.

    Raises:
        ValueError: If the target is not a valid CIDR range, an error is logged.
    """
    try:
        return [str(ip) for ip in ipaddress.IPv4Network(target)]
    except ValueError:
        logger.error(f"{target} is not a valid CIDR range. Skipping.")
        return []


def get_data_from_post_request(request, field):
    """
    Get data from a POST request.

    Args:
        request (HttpRequest): The request object.
        field (str): The field to get data from.
    Returns:
        list: The data from the specified field.
    """
    if hasattr(request.data, "getlist"):
        return request.data.getlist(field)
    else:
        return request.data.get(field, [])


def safe_int_cast(value, default=None):
    """
    Convert a value to an integer if possible, otherwise return a default value.

    Args:
        value: The value or the array of values to convert to an integer.
        default: The default value to return if conversion fails.

    Returns:
        int or default: The integer value if conversion is successful, otherwise the default value.
    """
    if isinstance(value, list):
        return [safe_int_cast(item) for item in value]
    try:
        return int(value)
    except (ValueError, TypeError):
        return default
