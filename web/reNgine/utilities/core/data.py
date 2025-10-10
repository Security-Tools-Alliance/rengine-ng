"""
Core data manipulation utilities.

This module provides pure data manipulation functions with no external dependencies
beyond standard Python libraries. These functions form the foundation of the
modular utilities architecture.

Key principles:
1. Pure functions with no side effects
2. No external dependencies beyond standard library
3. No imports from other reNgine modules
4. Stateless and thread-safe
5. Easy to test and reuse
"""

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Union


def is_iterable(obj: Any) -> bool:
    """
    Check if an object is iterable.

    Args:
        obj: Object to check

    Returns:
        bool: True if object is iterable
    """
    try:
        iter(obj)
        return True
    except TypeError:
        return False


def replace_nulls(data: Any, replacement: str = "") -> Any:
    """
    Replace None values and empty strings in data structure with replacement value.

    Args:
        data: Data structure to process
        replacement: Value to replace None and empty strings with

    Returns:
        Processed data structure
    """
    if data is None or data == "":
        return replacement
    elif isinstance(data, dict):
        return {key: replace_nulls(value, replacement) for key, value in data.items()}
    elif isinstance(data, list):
        return [replace_nulls(item, replacement) for item in data]
    else:
        return data


def flatten_dict(data: Dict[str, Any], separator: str = ".") -> Dict[str, Any]:
    """
    Flatten a nested dictionary.

    Args:
        data: Dictionary to flatten
        separator: Separator for nested keys

    Returns:
        Flattened dictionary
    """

    def _flatten(obj: Any, parent_key: str = "") -> Dict[str, Any]:
        items = []

        if isinstance(obj, dict):
            for key, value in obj.items():
                new_key = f"{parent_key}{separator}{key}" if parent_key else key
                items.extend(_flatten(value, new_key).items())
        elif isinstance(obj, list):
            for i, value in enumerate(obj):
                new_key = f"{parent_key}{separator}{i}" if parent_key else str(i)
                items.extend(_flatten(value, new_key).items())
        else:
            items.append((parent_key, obj))

        return dict(items)

    return _flatten(data)


def deep_merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two dictionaries.

    Args:
        dict1: First dictionary
        dict2: Second dictionary

    Returns:
        Merged dictionary
    """
    result = dict1.copy()

    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value

    return result


def generate_hash(data: Union[str, bytes, Dict, List], algorithm: str = "md5") -> str:
    """
    Generate hash for data.

    Args:
        data: Data to hash
        algorithm: Hash algorithm to use

    Returns:
        Hash string
    """
    if isinstance(data, (dict, list)):
        data = json.dumps(data, sort_keys=True)

    if isinstance(data, str):
        data = data.encode("utf-8")

    if algorithm == "md5":
        return hashlib.md5(data).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(data).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(data).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def chunk_list(data: List[Any], chunk_size: int) -> List[List[Any]]:
    """
    Split a list into chunks of specified size.

    Args:
        data: List to chunk
        chunk_size: Size of each chunk

    Returns:
        List of chunks
    """
    if chunk_size <= 0:
        raise ValueError("Chunk size must be positive")

    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]


def remove_duplicates(data: List[Any], key_func: Optional[callable] = None) -> List[Any]:
    """
    Remove duplicates from a list while preserving order.

    Args:
        data: List to deduplicate
        key_func: Function to extract key for comparison

    Returns:
        Deduplicated list
    """
    seen = set()
    result = []

    for item in data:
        key = key_func(item) if key_func else item
        if key not in seen:
            seen.add(key)
            result.append(item)

    return result


def safe_get(data: Dict[str, Any], key_path: str, default: Any = None) -> Any:
    """
    Safely get value from nested dictionary using dot notation.

    Args:
        data: Dictionary to search
        key_path: Dot-separated key path (e.g., "user.profile.name")
        default: Default value if key not found

    Returns:
        Value at key path or default
    """
    keys = key_path.split(".")
    current = data

    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default

    return current


def safe_set(data: Dict[str, Any], key_path: str, value: Any) -> Dict[str, Any]:
    """
    Safely set value in nested dictionary using dot notation.

    Args:
        data: Dictionary to modify
        key_path: Dot-separated key path (e.g., "user.profile.name")
        value: Value to set

    Returns:
        Modified dictionary
    """
    keys = key_path.split(".")
    current = data

    for key in keys[:-1]:
        if key not in current or not isinstance(current[key], dict):
            current[key] = {}
        current = current[key]

    current[keys[-1]] = value
    return data


def extract_columns(row: List[Any], columns: List[int]) -> List[Any]:
    """
    Extract specific columns from a row based on column indices.

    Args:
        row: The CSV row as a list of values
        columns: List of column indices to extract

    Returns:
        list: Extracted values from the specified columns

    Example:
        >>> extract_columns(["a", "b", "c", "d"], [0, 2])
        ['a', 'c']
    """
    return [row[i] for i in columns if i < len(row)]


def extract_numbers(text: str) -> List[Union[int, float]]:
    """
    Extract all numbers from text.

    Args:
        text: Text to extract numbers from

    Returns:
        List of numbers found
    """
    pattern = r"-?\d+\.?\d*"
    matches = re.findall(pattern, text)

    numbers = []
    for match in matches:
        try:
            if "." in match:
                numbers.append(float(match))
            else:
                numbers.append(int(match))
        except ValueError:
            continue

    return numbers


def extract_emails(text: str) -> List[str]:
    """
    Extract email addresses from text.

    Args:
        text: Text to extract emails from

    Returns:
        List of email addresses found
    """
    pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    return re.findall(pattern, text)


def extract_urls(text: str) -> List[str]:
    """
    Extract URLs from text.

    Args:
        text: Text to extract URLs from

    Returns:
        List of URLs found
    """
    pattern = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
    return re.findall(pattern, text)


def extract_ips(text: str) -> List[str]:
    """
    Extract IP addresses from text.

    Args:
        text: Text to extract IPs from

    Returns:
        List of IP addresses found
    """
    # IPv4 pattern
    ipv4_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    ipv4_matches = re.findall(ipv4_pattern, text)

    # IPv6 pattern (simplified)
    ipv6_pattern = r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    ipv6_matches = re.findall(ipv6_pattern, text)

    return ipv4_matches + ipv6_matches


def normalize_whitespace(text: str) -> str:
    """
    Normalize whitespace in text.

    Args:
        text: Text to normalize

    Returns:
        Normalized text
    """
    return re.sub(r"\s+", " ", text.strip())


def truncate_string(text: str, max_length: int, suffix: str = "...") -> str:
    """
    Truncate string to maximum length.

    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated

    Returns:
        Truncated text
    """
    if len(text) <= max_length:
        return text

    return text[: max_length - len(suffix)] + suffix


def convert_to_string(value: Any, encoding: str = "utf-8") -> str:
    """
    Convert value to string safely.

    Args:
        value: Value to convert
        encoding: Encoding to use for bytes

    Returns:
        String representation
    """
    if isinstance(value, str):
        return value
    elif isinstance(value, bytes):
        return value.decode(encoding)
    elif isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    else:
        return str(value)


def convert_to_int(value: Any, default: int = 0) -> int:
    """
    Convert value to integer safely.

    Args:
        value: Value to convert
        default: Default value if conversion fails

    Returns:
        Integer value
    """
    try:
        if isinstance(value, (int, float)):
            return int(value)
        elif isinstance(value, str):
            # Extract first number from string
            numbers = extract_numbers(value)
            return int(numbers[0]) if numbers else default
        else:
            return default
    except (ValueError, TypeError, IndexError):
        return default


def convert_to_float(value: Any, default: float = 0.0) -> float:
    """
    Convert value to float safely.

    Args:
        value: Value to convert
        default: Default value if conversion fails

    Returns:
        Float value
    """
    try:
        if isinstance(value, (int, float)):
            return float(value)
        elif isinstance(value, str):
            # Extract first number from string
            numbers = extract_numbers(value)
            return float(numbers[0]) if numbers else default
        else:
            return default
    except (ValueError, TypeError, IndexError):
        return default


def convert_to_bool(value: Any, default: bool = False) -> bool:
    """
    Convert value to boolean safely.

    Args:
        value: Value to convert
        default: Default value if conversion fails

    Returns:
        Boolean value
    """
    if isinstance(value, bool):
        return value
    elif isinstance(value, str):
        return value.lower() in ("true", "1", "yes", "on", "enabled")
    elif isinstance(value, (int, float)):
        return bool(value)
    else:
        return default


def sort_dict_by_key(data: Dict[str, Any], reverse: bool = False) -> Dict[str, Any]:
    """
    Sort dictionary by keys.

    Args:
        data: Dictionary to sort
        reverse: Sort in reverse order

    Returns:
        Sorted dictionary
    """
    return dict(sorted(data.items(), reverse=reverse))


def sort_dict_by_value(data: Dict[str, Any], reverse: bool = False) -> Dict[str, Any]:
    """
    Sort dictionary by values.

    Args:
        data: Dictionary to sort
        reverse: Sort in reverse order

    Returns:
        Sorted dictionary
    """
    return dict(sorted(data.items(), key=lambda x: x[1], reverse=reverse))


def filter_dict(data: Dict[str, Any], keys: List[str]) -> Dict[str, Any]:
    """
    Filter dictionary to include only specified keys.

    Args:
        data: Dictionary to filter
        keys: Keys to include

    Returns:
        Filtered dictionary
    """
    return {key: data[key] for key in keys if key in data}


def remove_control_characters(text: str) -> str:
    """
    Remove control characters from text.

    Args:
        text: Text to clean

    Returns:
        Text without control characters
    """
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", "", text)


def remove_ansi_sequences(text: str) -> str:
    """
    Remove ANSI escape sequences from text.

    Args:
        text: Text to clean

    Returns:
        Text without ANSI sequences
    """
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)


def exclude_dict_keys(data: Dict[str, Any], keys: List[str]) -> Dict[str, Any]:
    """
    Filter dictionary to exclude specified keys.

    Args:
        data: Dictionary to filter
        keys: Keys to exclude

    Returns:
        Filtered dictionary
    """
    return {key: value for key, value in data.items() if key not in keys}
