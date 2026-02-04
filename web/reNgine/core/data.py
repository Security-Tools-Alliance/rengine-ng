"""
Data utilities - Leaf layer.
Pure data manipulation functions with no Django dependencies.
"""

import contextlib
import ipaddress
import re
import subprocess

import validators

from reNgine.utilities.logger import get_module_logger


logger = get_module_logger(__name__)


def return_iterable(string):
    """
    Check if value is a simple string, a string with commas, a list [], a tuple (),
    a set {} and return an iterable.

    Args:
        string: Value to convert to iterable

    Returns:
        list: Iterable version of the input
    """
    if not isinstance(string, (list, tuple)):
        string = [string]
    return string


def replace_nulls(obj):
    """
    Replace null characters in strings, recursively for lists and dicts.

    For dictionaries, this function processes both keys and values. If processing keys
    would result in key collisions (multiple keys becoming identical after null removal),
    a ValueError is raised to prevent data loss.

    Args:
        obj: Object to clean (str, list, or dict)

    Returns:
        Cleaned object with null characters removed

    Raises:
        ValueError: If dictionary key processing would result in collisions
    """
    if isinstance(obj, str):
        return obj.replace("\x00", "")
    elif isinstance(obj, list):
        return [replace_nulls(item) for item in obj]
    elif isinstance(obj, dict):
        # Process keys and values
        cleaned_items = [(replace_nulls(key), replace_nulls(value)) for key, value in obj.items()]

        # Check for key collisions
        cleaned_keys = [key for key, _ in cleaned_items]
        if len(cleaned_keys) != len(set(cleaned_keys)):
            # Find and report the colliding keys
            from collections import Counter

            key_counts = Counter(cleaned_keys)
            colliding_keys = [key for key, count in key_counts.items() if count > 1]
            raise ValueError(
                f"Key collision detected after null removal. "
                f"Multiple keys would become identical: {colliding_keys}. "
                f"This would result in data loss. Please check your data source."
            )

        return dict(cleaned_items)
    else:
        return obj


def extract_between(text, pattern):
    """
    Extract text between pattern match.

    Args:
        text: Text to search
        pattern: Compiled regex pattern

    Returns:
        str: Extracted text or empty string
    """
    match = pattern.search(text)
    return match.group(1).strip() if match else ""


def is_iterable(variable):
    """
    Check if a variable is iterable.

    Args:
        variable: Variable to check

    Returns:
        bool: True if iterable, False otherwise
    """
    try:
        iter(variable)
        return True
    except TypeError:
        return False


def extract_columns(row, columns):
    """
    Extract specific columns from a row based on column indices.

    Args:
        row (list): The CSV row as a list of values.
        columns (list): List of column indices to extract.

    Returns:
        list: Extracted values from the specified columns.
    """
    return [row[i] for i in columns]


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


def safe_bool_cast(value, default=False):
    """
    Convert a value to a boolean if possible, otherwise return a default value.

    Handles common boolean representations from POST requests:
    - String "true", "on", "1", "yes" -> True
    - Boolean True -> True
    - Integer: non-zero values -> True, 0 -> False
    - Float: non-zero values -> True, 0.0 -> False
    - String "false", "off", "0", "no", empty string -> False
    - Boolean False -> False
    - None -> default
    - Other types or unrecognized string values -> default

    Args:
        value: The value to convert to a boolean.
        default: The default value to return if conversion fails (default: False).

    Returns:
        bool: The boolean value if conversion is successful, otherwise the default value.
    """
    if value is None:
        return default

    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        value_lower = value.lower().strip()
        if value_lower in ("true", "on", "1", "yes"):
            return True
        if value_lower in ("false", "off", "0", "no", ""):
            return False
        return default

    if isinstance(value, int):
        return bool(value)

    if isinstance(value, float):
        return bool(value)

    return default


def get_ip_info(ip_address):
    """
    Get IP information, determining whether it is an IPv4 or IPv6 address.

    Args:
        ip_address (str): The IP address to validate and retrieve information for.

    Returns:
        IPv4Address or IPv6Address or None: An IP address object if the input is valid, otherwise None.
    """
    # Handle None or empty input
    if not ip_address:
        return None

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


def get_ips_from_cidr_range(target):
    """
    Generate a list of IP addresses from a given CIDR range.

    Args:
        target (str): The CIDR range from which to generate IP addresses.

    Returns:
        list of str: A list of IP addresses as strings if the CIDR range is valid;
                     otherwise, an empty list is returned.
    """
    try:
        return [str(ip) for ip in ipaddress.IPv4Network(target)]
    except ValueError:
        logger.error(f"{target} is not a valid CIDR range. Skipping.")
        return []


def parse_curl_output(response):
    """
    Parse cURL output to extract HTTP status.

    Args:
        response: cURL response text

    Returns:
        dict: Dictionary with http_status key
    """
    http_status = 0
    if response:
        curl_regex_http_status = r"HTTP\/(?:(?:\d\.?)+)\s(\d+)\s(?:\w+)"
        regex = re.compile(curl_regex_http_status, re.MULTILINE)
        with contextlib.suppress(KeyError, TypeError, IndexError):
            http_status = int(regex.findall(response)[0])
    return {
        "http_status": http_status,
    }


def geoiplookup(ip_address):
    """
    Execute geoiplookup command with proper input validation and robust output parsing.

    Args:
        ip_address (str): IP address to geolocalize

    Returns:
        tuple: (success: bool, country_iso: str, country_name: str, error: str)
    """
    if not (validators.ipv4(ip_address) or validators.ipv6(ip_address)):
        logger.warning(f"Invalid IP address format: {ip_address}")
        return False, None, None, "Invalid IP address format"

    try:
        result = subprocess.run(
            ["geoiplookup", ip_address],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        if result.returncode != 0:
            logger.warning(f"geoiplookup failed for {ip_address}: {result.stderr}")
            return False, None, None, result.stderr or "geoiplookup failed"

        output = result.stdout.strip()

        if "IP Address not found" in output or "can't resolve hostname" in output:
            logger.debug(f"IP address not found in geoiplookup database: {ip_address}")
            return False, None, None, "IP address not found"

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
        return False, None, None, f"geoiplookup error: {e}"
