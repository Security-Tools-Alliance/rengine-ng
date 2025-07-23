import contextlib
import re
import ipaddress
import validators
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


#--------------#
# Data utils   #
#--------------#

def return_iterable(string):
    """Check if value is a simple string, a string with commas, a list [], a tuple (), a set {} and return an iterable"""
    if not isinstance(string, (list, tuple)):
        string = [string]
    return string


def replace_nulls(obj):
    """Replace null characters in strings, recursively for lists and dicts"""
    if isinstance(obj, str):
        return obj.replace("\x00", "")
    elif isinstance(obj, list):
        return [replace_nulls(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: replace_nulls(value) for key, value in obj.items()}
    else:
        return obj


def extract_between(text, pattern):
    match = pattern.search(text)
    return match.group(1).strip() if match else ""


def is_iterable(variable):
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
    if hasattr(request.data, 'getlist'):
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
        logger.error(f'{target} is not a valid CIDR range. Skipping.')
        return []


def parse_curl_output(response):
    http_status = 0
    if response:
        # TODO: Enrich from other cURL fields.
        CURL_REGEX_HTTP_STATUS = 'HTTP\/(?:(?:\d\.?)+)\s(\d+)\s(?:\w+)'
        regex = re.compile(CURL_REGEX_HTTP_STATUS, re.MULTILINE)
        with contextlib.suppress(KeyError, TypeError, IndexError):
            http_status = int(regex.findall(response)[0])
    return {
        'http_status': http_status,
    } 