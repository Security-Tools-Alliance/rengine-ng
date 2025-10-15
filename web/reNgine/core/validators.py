"""
Validation utilities - Leaf layer.
Pure validation functions with no Django dependencies.
"""

import ipaddress
import re
from typing import Any, Optional

from celery.utils.log import get_task_logger
import validators


logger = get_task_logger(__name__)


def is_valid_domain(domain: str) -> bool:
    """
    Validate if a string is a valid domain name.

    Args:
        domain: Domain name to validate

    Returns:
        bool: True if valid domain, False otherwise
    """
    if not domain:
        return False
    return bool(validators.domain(domain))


def is_valid_url(url: str) -> bool:
    """
    Validate if a string is a valid URL.

    Args:
        url: URL to validate

    Returns:
        bool: True if valid URL, False otherwise
    """
    if not url:
        return False

    # Use validators library for standard schemes
    if validators.url(url):
        return True

    # Check for custom schemes manually
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        return True

    return False


def is_valid_ip(ip_address: str) -> bool:
    """
    Validate if a string is a valid IP address (IPv4 or IPv6).
    Uses ipaddress module for robust validation.

    Args:
        ip_address: IP address to validate

    Returns:
        bool: True if valid IP, False otherwise
    """
    if not ip_address:
        return False

    try:
        # Try to parse as either IPv4 or IPv6 address
        ipaddress.ip_address(ip_address)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_email(email: str) -> bool:
    """
    Validate if a string is a valid email address.

    Args:
        email: Email address to validate

    Returns:
        bool: True if valid email, False otherwise
    """
    if not email:
        return False

    # Reject emails with leading/trailing spaces
    if email != email.strip():
        return False

    return bool(validators.email(email))


def is_valid_port(port: Any) -> bool:
    """
    Validate if a value is a valid port number (1-65535).

    Args:
        port: Port number to validate

    Returns:
        bool: True if valid port, False otherwise
    """
    try:
        # Reject float values
        if isinstance(port, float):
            return False

        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def is_valid_cidr(cidr: str) -> bool:
    """
    Validate if a string is a valid CIDR notation (IPv4 or IPv6).

    Args:
        cidr: CIDR notation to validate

    Returns:
        bool: True if valid CIDR, False otherwise
    """
    if not cidr:
        return False

    # Check if CIDR notation contains a slash
    if "/" not in cidr:
        return False

    try:
        # Try to parse as IPv4 network
        ipaddress.IPv4Network(cidr, strict=False)
        return True
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        try:
            # Try to parse as IPv6 network
            ipaddress.IPv6Network(cidr, strict=False)
            return True
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            return False


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal and invalid characters.

    Args:
        filename: Filename to sanitize

    Returns:
        str: Sanitized filename
    """
    if not filename:
        return "unnamed"

    # Strip leading/trailing whitespace first
    filename = filename.strip()

    if not filename:
        return "unnamed"

    sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", filename)
    sanitized = sanitized.strip(". ")

    if not sanitized:
        return "unnamed"

    return sanitized[:255]


def validate_severity(severity: str) -> Optional[str]:
    """
    Validate and normalize severity level.

    Args:
        severity: Severity string to validate

    Returns:
        str or None: Normalized severity or None if invalid
    """
    if not severity:
        return None

    valid_severities = {"critical", "high", "medium", "low", "info", "unknown"}
    normalized = severity.lower().strip()

    if normalized in valid_severities:
        return normalized

    return None
