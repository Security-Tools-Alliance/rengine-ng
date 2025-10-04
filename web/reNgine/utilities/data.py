import contextlib
import ipaddress
import re
import subprocess

from celery.utils.log import get_task_logger
import validators


logger = get_task_logger(__name__)


# --------------#
# Data utils   #
# --------------#


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
        logger.error(f"{target} is not a valid CIDR range. Skipping.")
        return []


def parse_curl_output(response):
    http_status = 0
    if response:
        # TODO: Enrich from other cURL fields.
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
        return False, None, None, f"geoiplookup error: {e}"
