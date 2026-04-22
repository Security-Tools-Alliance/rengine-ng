"""
Validation utilities - Leaf layer.
Pure validation functions with no Django dependencies.
"""

import ipaddress
import re
from typing import Any, Optional

import validators

from reNgine.core.ip_literal import normalize_ip_address_text
from reNgine.utilities.logger import get_module_logger


logger = get_module_logger(__name__)


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
    Leading/trailing whitespace is ignored (same rules as normalize_ip_address_text).
    """
    if not ip_address or not isinstance(ip_address, str):
        return False
    return normalize_ip_address_text(ip_address) is not None


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


def sanitize_path_component(component: str) -> str:
    """
    Sanitize a path component (directory or folder name) for safe filesystem usage.
    More permissive than sanitize_filename, allows more characters typical in paths.

    Args:
        component: Path component to sanitize

    Returns:
        str: Sanitized path component
    """
    if not component:
        return "unnamed"

    # Strip leading/trailing whitespace
    component = component.strip()

    if not component:
        return "unnamed"

    # Replace forbidden characters and path separators with underscore
    # Keep: alphanumeric, dash, underscore, dot
    sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", component)

    # Remove leading/trailing dots and spaces to avoid issues
    sanitized = sanitized.strip(". ")

    # Replace multiple consecutive underscores with single underscore
    sanitized = re.sub(r"_{2,}", "_", sanitized)

    if not sanitized:
        return "unnamed"

    # Limit length to 100 characters for path components
    return sanitized[:100]


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


def validate_confidence(confidence: str) -> Optional[str]:
    """
    Validate and normalize confidence level.

    Args:
        confidence: Confidence string to validate (low, medium, high)

    Returns:
        str or None: Normalized confidence or None if invalid
    """
    if not confidence:
        return None

    from reNgine.definitions import CONFIDENCE_LEVELS

    normalized = confidence.lower().strip()
    if normalized in CONFIDENCE_LEVELS:
        return normalized

    return None


def validate_ip_protocol(protocol: str) -> Optional[str]:
    """
    Validate and normalize IP protocol.

    Args:
        protocol: Protocol string to validate (IPv4 or IPv6)

    Returns:
        str or None: Normalized protocol or None if invalid
    """
    if not protocol:
        return None

    from reNgine.definitions import IP_PROTOCOLS

    # Normalize common variations
    normalized = protocol.strip()
    if normalized.upper() == "IPV4":
        normalized = "IPv4"
    elif normalized.upper() == "IPV6":
        normalized = "IPv6"

    if normalized in IP_PROTOCOLS:
        return normalized

    return None
