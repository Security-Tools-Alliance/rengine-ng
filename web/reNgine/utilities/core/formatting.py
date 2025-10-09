"""
Core formatting utilities.

This module provides pure formatting functions with no external dependencies
beyond standard Python libraries. These functions form the foundation of the
modular utilities architecture.

Key principles:
1. Pure functions with no side effects
2. No external dependencies beyond standard library
3. No imports from other reNgine modules
4. Stateless and thread-safe
5. Easy to test and reuse
"""

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union


def format_bytes(bytes_value: int, precision: int = 1) -> str:
    """
    Format bytes into human readable format.
    
    Args:
        bytes_value: Number of bytes
        precision: Decimal precision
        
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    if bytes_value == 0:
        return "0 B"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    size = float(bytes_value)
    unit_index = 0
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    # Format with precision
    return f"{size:.{precision}f} {units[unit_index]}"


def format_duration(seconds: Union[int, float], precision: int = 0) -> str:
    """
    Format duration in seconds to human readable format.
    
    Args:
        seconds: Duration in seconds
        precision: Decimal precision for seconds
        
    Returns:
        Formatted string (e.g., "1d 2h 30m 45s")
    """
    if seconds < 0:
        return "0s"
    
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = seconds % 60
    
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or not parts:
        if secs == int(secs):
            parts.append(f"{int(secs)}s")
        else:
            parts.append(f"{secs:.{precision}f}s")
    
    return " ".join(parts)


def format_number(number: Union[int, float], precision: int = 2) -> str:
    """
    Format number with thousand separators.
    
    Args:
        number: Number to format
        precision: Decimal precision
        
    Returns:
        Formatted string (e.g., "1,234.56")
    """
    if isinstance(number, int):
        return f"{number:,}"
    else:
        return f"{number:,.{precision}f}"


def format_percentage(value: float, total: float, precision: int = 1) -> str:
    """
    Format percentage.
    
    Args:
        value: Value to calculate percentage from
        total: Total value
        precision: Decimal precision
        
    Returns:
        Formatted percentage string
    """
    if total == 0:
        return "0%"
    
    percentage = (value / total) * 100
    return f"{percentage:.{precision}f}%"


def format_timestamp(timestamp: Union[int, float, datetime], 
                    format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Format timestamp to string.
    
    Args:
        timestamp: Timestamp (Unix timestamp or datetime object)
        format_str: Format string
        
    Returns:
        Formatted timestamp string
    """
    if isinstance(timestamp, datetime):
        dt = timestamp
    else:
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    
    return dt.strftime(format_str)


def format_iso_timestamp(timestamp: Union[int, float, datetime]) -> str:
    """
    Format timestamp to ISO format.
    
    Args:
        timestamp: Timestamp (Unix timestamp or datetime object)
        
    Returns:
        ISO formatted timestamp string
    """
    if isinstance(timestamp, datetime):
        dt = timestamp
    else:
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    
    return dt.isoformat()


def format_json(data: Any, indent: int = 2, ensure_ascii: bool = False) -> str:
    """
    Format data as JSON string.
    
    Args:
        data: Data to format
        indent: Indentation level
        ensure_ascii: Ensure ASCII output
        
    Returns:
        JSON formatted string
    """
    return json.dumps(data, indent=indent, ensure_ascii=ensure_ascii, default=str)


def format_xml(data: Dict[str, Any], root_name: str = "root") -> str:
    """
    Format data as XML string.
    
    Args:
        data: Data to format
        root_name: Root element name
        
    Returns:
        XML formatted string
    """
    def dict_to_xml(d, root):
        xml = f"<{root}>"
        for key, value in d.items():
            if isinstance(value, dict):
                xml += dict_to_xml(value, key)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        xml += dict_to_xml(item, key)
                    else:
                        xml += f"<{key}>{item}</{key}>"
            else:
                xml += f"<{key}>{value}</{key}>"
        xml += f"</{root}>"
        return xml
    
    return dict_to_xml(data, root_name)


def format_csv(data: List[Dict[str, Any]], headers: Optional[List[str]] = None) -> str:
    """
    Format data as CSV string.
    
    Args:
        data: List of dictionaries to format
        headers: Column headers (if None, use keys from first row)
        
    Returns:
        CSV formatted string
    """
    if not data:
        return ""
    
    if headers is None:
        headers = list(data[0].keys())
    
    # Escape CSV values
    def escape_csv_value(value):
        if value is None:
            return ""
        value_str = str(value)
        if ',' in value_str or '"' in value_str or '\n' in value_str:
            return f'"{value_str.replace('"', '""')}"'
        return value_str
    
    # Build CSV
    csv_lines = [','.join(escape_csv_value(header) for header in headers)]
    
    for row in data:
        csv_lines.append(','.join(escape_csv_value(row.get(header, "")) for header in headers))
    
    return '\n'.join(csv_lines)


def format_table(data: List[Dict[str, Any]], 
                headers: Optional[List[str]] = None,
                max_width: int = 80) -> str:
    """
    Format data as ASCII table.
    
    Args:
        data: List of dictionaries to format
        headers: Column headers (if None, use keys from first row)
        max_width: Maximum table width
        
    Returns:
        ASCII table formatted string
    """
    if not data:
        return ""
    
    if headers is None:
        headers = list(data[0].keys())
    
    # Calculate column widths
    col_widths = {}
    for header in headers:
        col_widths[header] = len(str(header))
    
    for row in data:
        for header in headers:
            value = str(row.get(header, ""))
            col_widths[header] = max(col_widths[header], len(value))
    
    # Adjust column widths to fit max_width
    total_width = sum(col_widths.values()) + (len(headers) - 1) * 3  # 3 for separators
    if total_width > max_width:
        # Proportionally reduce column widths
        ratio = max_width / total_width
        for header in headers:
            col_widths[header] = max(1, int(col_widths[header] * ratio))
    
    # Build table
    lines = []
    
    # Header
    header_line = " | ".join(str(header).ljust(col_widths[header]) for header in headers)
    lines.append(header_line)
    lines.append("-" * len(header_line))
    
    # Data rows
    for row in data:
        data_line = " | ".join(str(row.get(header, "")).ljust(col_widths[header]) for header in headers)
        lines.append(data_line)
    
    return '\n'.join(lines)


def format_list(items: List[Any], 
               separator: str = ", ",
               max_items: Optional[int] = None,
               truncate_suffix: str = "...") -> str:
    """
    Format list as string.
    
    Args:
        items: List of items to format
        separator: Separator between items
        max_items: Maximum number of items to show
        truncate_suffix: Suffix when truncating
        
    Returns:
        Formatted list string
    """
    if not items:
        return ""
    
    if max_items and len(items) > max_items:
        visible_items = items[:max_items]
        return separator.join(str(item) for item in visible_items) + truncate_suffix
    
    return separator.join(str(item) for item in items)


def format_dict(data: Dict[str, Any], 
               key_value_separator: str = ": ",
               item_separator: str = ", ",
               max_items: Optional[int] = None) -> str:
    """
    Format dictionary as string.
    
    Args:
        data: Dictionary to format
        key_value_separator: Separator between key and value
        item_separator: Separator between items
        max_items: Maximum number of items to show
        
    Returns:
        Formatted dictionary string
    """
    if not data:
        return "{}"
    
    items = []
    count = 0
    
    for key, value in data.items():
        if max_items and count >= max_items:
            break
        items.append(f"{key}{key_value_separator}{value}")
        count += 1
    
    result = item_separator.join(items)
    
    if max_items and len(data) > max_items:
        result += "..."
    
    return result


def format_url(url: str, max_length: int = 50) -> str:
    """
    Format URL for display.
    
    Args:
        url: URL to format
        max_length: Maximum length
        
    Returns:
        Formatted URL string
    """
    if len(url) <= max_length:
        return url
    
    # Try to keep the domain visible
    if '://' in url:
        protocol, rest = url.split('://', 1)
        if len(rest) > max_length - len(protocol) - 3:
            return f"{protocol}://{rest[:max_length - len(protocol) - 6]}..."
        else:
            return url
    else:
        return url[:max_length - 3] + "..."


def format_domain(domain: str, max_length: int = 30) -> str:
    """
    Format domain for display.
    
    Args:
        domain: Domain to format
        max_length: Maximum length
        
    Returns:
        Formatted domain string
    """
    if len(domain) <= max_length:
        return domain
    
    # Try to keep the TLD visible
    parts = domain.split('.')
    if len(parts) >= 2:
        tld = parts[-1]
        domain_part = '.'.join(parts[:-1])
        if len(domain_part) > max_length - len(tld) - 1:
            return f"{domain_part[:max_length - len(tld) - 4]}...{tld}"
    
    return domain[:max_length - 3] + "..."


def format_ip(ip: str, max_length: int = 15) -> str:
    """
    Format IP address for display.
    
    Args:
        ip: IP address to format
        max_length: Maximum length
        
    Returns:
        Formatted IP string
    """
    if len(ip) <= max_length:
        return ip
    
    return ip[:max_length - 3] + "..."


def format_status_code(status_code: int) -> str:
    """
    Format HTTP status code with description.
    
    Args:
        status_code: HTTP status code
        
    Returns:
        Formatted status code string
    """
    status_descriptions = {
        200: "OK",
        201: "Created",
        204: "No Content",
        301: "Moved Permanently",
        302: "Found",
        304: "Not Modified",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout"
    }
    
    description = status_descriptions.get(status_code, "Unknown")
    return f"{status_code} {description}"


def format_severity(severity: str) -> str:
    """
    Format severity level.
    
    Args:
        severity: Severity level
        
    Returns:
        Formatted severity string
    """
    severity_map = {
        'critical': '🔴 Critical',
        'high': '🟠 High',
        'medium': '🟡 Medium',
        'low': '🟢 Low',
        'info': 'ℹ️ Info'
    }
    
    return severity_map.get(severity.lower(), f"❓ {severity.title()}")


def format_progress(current: int, total: int, width: int = 20) -> str:
    """
    Format progress bar.
    
    Args:
        current: Current progress
        total: Total progress
        width: Width of progress bar
        
    Returns:
        Formatted progress bar string
    """
    if total == 0:
        return "[" + " " * width + "] 0%"
    
    percentage = (current / total) * 100
    filled = int((current / total) * width)
    
    bar = "█" * filled + "░" * (width - filled)
    return f"[{bar}] {percentage:.1f}%"


def format_elapsed_time(start_time: Union[int, float, datetime], 
                       end_time: Optional[Union[int, float, datetime]] = None) -> str:
    """
    Format elapsed time between two timestamps.
    
    Args:
        start_time: Start timestamp
        end_time: End timestamp (if None, use current time)
        
    Returns:
        Formatted elapsed time string
    """
    if isinstance(start_time, datetime):
        start_dt = start_time
    else:
        start_dt = datetime.fromtimestamp(start_time, tz=timezone.utc)
    
    if end_time is None:
        end_dt = datetime.now(timezone.utc)
    elif isinstance(end_time, datetime):
        end_dt = end_time
    else:
        end_dt = datetime.fromtimestamp(end_time, tz=timezone.utc)
    
    elapsed = end_dt - start_dt
    return format_duration(elapsed.total_seconds())


def format_file_size(size: int) -> str:
    """
    Format file size in human readable format.
    
    Args:
        size: File size in bytes
        
    Returns:
        Formatted file size string
    """
    return format_bytes(size)


def format_memory_usage(usage: int, total: int) -> str:
    """
    Format memory usage.
    
    Args:
        usage: Memory usage in bytes
        total: Total memory in bytes
        
    Returns:
        Formatted memory usage string
    """
    usage_str = format_bytes(usage)
    total_str = format_bytes(total)
    percentage = format_percentage(usage, total)
    
    return f"{usage_str} / {total_str} ({percentage})"


def format_cpu_usage(usage: float) -> str:
    """
    Format CPU usage.
    
    Args:
        usage: CPU usage percentage
        
    Returns:
        Formatted CPU usage string
    """
    return f"{usage:.1f}%"


def format_network_speed(bytes_per_second: int) -> str:
    """
    Format network speed.
    
    Args:
        bytes_per_second: Bytes per second
        
    Returns:
        Formatted network speed string
    """
    return f"{format_bytes(bytes_per_second)}/s"


def format_uptime(seconds: Union[int, float]) -> str:
    """
    Format uptime.
    
    Args:
        seconds: Uptime in seconds
        
    Returns:
        Formatted uptime string
    """
    return format_duration(seconds)


def format_version(version: str) -> str:
    """
    Format version string.
    
    Args:
        version: Version string
        
    Returns:
        Formatted version string
    """
    # Remove leading 'v' if present
    if version.startswith('v'):
        version = version[1:]
    
    return f"v{version}"


def format_boolean(value: bool, true_text: str = "Yes", false_text: str = "No") -> str:
    """
    Format boolean value.
    
    Args:
        value: Boolean value
        true_text: Text for True
        false_text: Text for False
        
    Returns:
        Formatted boolean string
    """
    return true_text if value else false_text


def format_nullable(value: Any, null_text: str = "N/A") -> str:
    """
    Format nullable value.
    
    Args:
        value: Value to format
        null_text: Text for None values
        
    Returns:
        Formatted value string
    """
    return str(value) if value is not None else null_text
