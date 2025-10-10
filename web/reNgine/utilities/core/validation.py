"""
Core validation utilities.

This module provides pure validation functions with no external dependencies
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
import re
from typing import List, Union
from urllib.parse import urlparse


def is_valid_ipv4(ip: str) -> bool:
    """
    Check if string is a valid IPv4 address.

    Args:
        ip: IP address string to validate

    Returns:
        bool: True if valid IPv4 address
    """
    try:
        ipaddress.IPv4Address(ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ipv6(ip: str) -> bool:
    """
    Check if string is a valid IPv6 address.

    Args:
        ip: IP address string to validate

    Returns:
        bool: True if valid IPv6 address
    """
    try:
        ipaddress.IPv6Address(ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ip(ip: str) -> bool:
    """
    Check if string is a valid IP address (IPv4 or IPv6).

    Args:
        ip: IP address string to validate

    Returns:
        bool: True if valid IP address
    """
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)


def is_valid_domain(domain: str) -> bool:
    """
    Check if string is a valid domain name.

    Args:
        domain: Domain name to validate

    Returns:
        bool: True if valid domain name
    """
    if not domain or len(domain) > 253:
        return False

    # Check for valid characters
    if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
        return False

    # Check for valid structure
    parts = domain.split(".")
    if len(parts) < 2:
        return False

    # Check each part
    for part in parts:
        if not part or len(part) > 63:
            return False
        if part.startswith("-") or part.endswith("-"):
            return False
        if not re.match(r"^[a-zA-Z0-9-]+$", part):
            return False

    return True


def is_valid_subdomain(subdomain: str) -> bool:
    """
    Check if string is a valid subdomain.

    Args:
        subdomain: Subdomain to validate

    Returns:
        bool: True if valid subdomain
    """
    if not subdomain or len(subdomain) > 253:
        return False

    # Check for valid characters
    if not re.match(r"^[a-zA-Z0-9.-]+$", subdomain):
        return False

    # Check for valid structure
    parts = subdomain.split(".")
    if len(parts) < 2:
        return False

    # Check each part
    for part in parts:
        if not part or len(part) > 63:
            return False
        if part.startswith("-") or part.endswith("-"):
            return False
        if not re.match(r"^[a-zA-Z0-9-]+$", part):
            return False

    return True


def is_valid_url(url: str) -> bool:
    """
    Check if string is a valid URL.

    Args:
        url: URL to validate

    Returns:
        bool: True if valid URL
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def is_valid_http_url(url: str) -> bool:
    """
    Check if string is a valid HTTP/HTTPS URL.

    Args:
        url: URL to validate

    Returns:
        bool: True if valid HTTP/HTTPS URL
    """
    try:
        result = urlparse(url)
        return result.scheme in ["http", "https"] and result.netloc and is_valid_domain(result.netloc)
    except Exception:
        return False


def is_valid_port(port: Union[str, int]) -> bool:
    """
    Check if value is a valid port number.

    Args:
        port: Port number to validate

    Returns:
        bool: True if valid port number
    """
    # Only accept integers, not strings
    if not isinstance(port, int):
        return False

    return 1 <= port <= 65535


def is_valid_email(email: str) -> bool:
    """
    Check if string is a valid email address.

    Args:
        email: Email address to validate

    Returns:
        bool: True if valid email address
    """
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def is_valid_md5(hash_str: str) -> bool:
    """
    Check if string is a valid MD5 hash.

    Args:
        hash_str: Hash string to validate

    Returns:
        bool: True if valid MD5 hash
    """
    pattern = r"^[a-fA-F0-9]{32}$"
    return bool(re.match(pattern, hash_str))


def is_valid_sha1(hash_str: str) -> bool:
    """
    Check if string is a valid SHA1 hash.

    Args:
        hash_str: Hash string to validate

    Returns:
        bool: True if valid SHA1 hash
    """
    pattern = r"^[a-fA-F0-9]{40}$"
    return bool(re.match(pattern, hash_str))


def is_valid_sha256(hash_str: str) -> bool:
    """
    Check if string is a valid SHA256 hash.

    Args:
        hash_str: Hash string to validate

    Returns:
        bool: True if valid SHA256 hash
    """
    pattern = r"^[a-fA-F0-9]{64}$"
    return bool(re.match(pattern, hash_str))


def is_valid_uuid(uuid_str: str) -> bool:
    """
    Check if string is a valid UUID.

    Args:
        uuid_str: UUID string to validate

    Returns:
        bool: True if valid UUID
    """
    pattern = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    return bool(re.match(pattern, uuid_str))


def is_valid_json(json_str: str) -> bool:
    """
    Check if string is valid JSON.

    Args:
        json_str: JSON string to validate

    Returns:
        bool: True if valid JSON
    """
    try:
        import json

        json.loads(json_str)
        return True
    except (json.JSONDecodeError, TypeError):
        return False


def is_valid_xml(xml_str: str) -> bool:
    """
    Check if string is valid XML.

    Args:
        xml_str: XML string to validate

    Returns:
        bool: True if valid XML
    """
    try:
        import xml.etree.ElementTree as ET

        ET.fromstring(xml_str)
        return True
    except ET.ParseError:
        return False


def is_valid_base64(base64_str: str) -> bool:
    """
    Check if string is valid base64.

    Args:
        base64_str: Base64 string to validate

    Returns:
        bool: True if valid base64
    """
    try:
        import base64

        base64.b64decode(base64_str, validate=True)
        return True
    except Exception:
        return False


def is_valid_hex(hex_str: str) -> bool:
    """
    Check if string is valid hexadecimal.

    Args:
        hex_str: Hexadecimal string to validate

    Returns:
        bool: True if valid hexadecimal
    """
    pattern = r"^[0-9a-fA-F]+$"
    return bool(re.match(pattern, hex_str))


def is_valid_filename(filename: str) -> bool:
    """
    Check if string is a valid filename.

    Args:
        filename: Filename to validate

    Returns:
        bool: True if valid filename
    """
    if not filename or len(filename) > 255:
        return False

    # Check for invalid characters
    invalid_chars = r'[<>:"/\\|?*]'
    if re.search(invalid_chars, filename):
        return False

    # Check for reserved names (Windows)
    reserved_names = [
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
    ]

    name_without_ext = filename.split(".")[0].upper()
    return name_without_ext not in reserved_names


def is_valid_path(path: str) -> bool:
    """
    Check if string is a valid file path.

    Args:
        path: File path to validate

    Returns:
        bool: True if valid file path
    """
    return not re.search(r'[<>"|?*]', path) if path else False


def is_valid_regex(pattern: str) -> bool:
    """
    Check if string is a valid regular expression.

    Args:
        pattern: Regular expression pattern to validate

    Returns:
        bool: True if valid regular expression
    """
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def is_valid_cidr(cidr: str) -> bool:
    """
    Check if string is a valid CIDR notation.

    Args:
        cidr: CIDR notation to validate

    Returns:
        bool: True if valid CIDR notation
    """
    if not cidr or "/" not in cidr:
        return False

    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_mac_address(mac: str) -> bool:
    """
    Check if string is a valid MAC address.

    Args:
        mac: MAC address to validate

    Returns:
        bool: True if valid MAC address
    """
    # Common MAC address patterns
    patterns = [
        r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$",  # XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
        r"^([0-9A-Fa-f]{4}[:-]){2}([0-9A-Fa-f]{4})$",  # XXXX:XXXX:XXXX or XXXX-XXXX-XXXX
        r"^([0-9A-Fa-f]{12})$",  # XXXXXXXXXXXX
    ]

    return any(re.match(pattern, mac) for pattern in patterns)


def is_valid_phone_number(phone: str) -> bool:
    """
    Check if string is a valid phone number.

    Args:
        phone: Phone number to validate

    Returns:
        bool: True if valid phone number
    """
    # Remove common separators
    cleaned = re.sub(r"[\s\-\(\)\.]", "", phone)

    # Check if it's all digits and reasonable length
    return 7 <= len(cleaned) <= 15 if re.match(r"^\d+$", cleaned) else False


def is_valid_credit_card(card_number: str) -> bool:
    """
    Check if string is a valid credit card number using Luhn algorithm.

    Args:
        card_number: Credit card number to validate

    Returns:
        bool: True if valid credit card number
    """
    # Remove spaces and dashes
    cleaned = re.sub(r"[\s\-]", "", card_number)

    # Check if it's all digits
    if not re.match(r"^\d+$", cleaned):
        return False

    # Check length (13-19 digits)
    if not (13 <= len(cleaned) <= 19):
        return False

    # Luhn algorithm
    def luhn_checksum(card_num):
        def digits_of(n):
            return [int(d) for d in str(n)]

        digits = digits_of(card_num)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d * 2))
        return checksum % 10

    return luhn_checksum(cleaned) == 0


def validate_list_of_ips(ip_list: List[str]) -> List[str]:
    """
    Validate a list of IP addresses and return invalid ones.

    Args:
        ip_list: List of IP addresses to validate

    Returns:
        List of invalid IP addresses
    """
    invalid_ips = []
    invalid_ips.extend(ip for ip in ip_list if not is_valid_ip(ip))
    return invalid_ips


def validate_list_of_domains(domain_list: List[str]) -> List[str]:
    """
    Validate a list of domains and return invalid ones.

    Args:
        domain_list: List of domains to validate

    Returns:
        List of invalid domains
    """
    invalid_domains = []
    invalid_domains.extend(domain for domain in domain_list if not is_valid_domain(domain))
    return invalid_domains


def validate_list_of_urls(url_list: List[str]) -> List[str]:
    """
    Validate a list of URLs and return invalid ones.

    Args:
        url_list: List of URLs to validate

    Returns:
        List of invalid URLs
    """
    invalid_urls = []
    invalid_urls.extend(url for url in url_list if not is_valid_url(url))
    return invalid_urls


def sanitize_filename(filename: str, replacement: str = "_") -> str:
    """
    Sanitize filename by removing invalid characters.

    Args:
        filename: Filename to sanitize
        replacement: Character to replace invalid characters with

    Returns:
        Sanitized filename
    """
    # Remove invalid characters
    invalid_chars = r'[<>:"/\\|?*]'
    sanitized = re.sub(invalid_chars, replacement, filename)

    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip(". ") or "unnamed"

    return sanitized


def sanitize_path(path: str, replacement: str = "_") -> str:
    """
    Sanitize file path by removing invalid characters.

    Args:
        path: File path to sanitize
        replacement: Character to replace invalid characters with

    Returns:
        Sanitized file path
    """
    # Remove invalid characters
    invalid_chars = r'[<>"|?*]'
    sanitized = re.sub(invalid_chars, replacement, path)

    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip(". ")

    return sanitized
