import ast
import json
import re
from urllib.parse import urlparse

from django import template

from dashboard.utils import get_user_groups
from reNgine.utilities.logger import get_module_logger


logger = get_module_logger(__name__)
register = template.Library()


@register.filter(name="split")
def split(value, key):
    return [x.strip() for x in value.split(key)]


@register.filter(name="map")
def map_filter(value, arg):
    return [getattr(item, arg) for item in value]


@register.filter(name="count")
def count(value):
    return len(value.split(","))


@register.filter(name="get_item")
def get_item(dictionary, key):
    """Get item from dictionary by key"""
    if dictionary is None:
        return None
    return dictionary.get(key)


@register.filter(name="getpath")
def getpath(value):
    parsed_url = urlparse(value)
    if parsed_url.query:
        return f"{parsed_url.path}?{parsed_url.query}"
    else:
        return parsed_url.path


@register.filter(name="none_or_never")
def none_or_never(value):
    return "Never" if value is None else value


# https://stackoverflow.com/a/32801096
@register.filter
def next(some_list, current_index):
    """
    Returns the next element of the list using the current index if it exists.
    Otherwise returns an empty string.
    """
    try:
        return some_list[int(current_index) + 1]  # access the next element
    except (IndexError, ValueError):
        return ""


@register.filter
def previous(some_list, current_index):
    """
    Returns the previous element of the list using the current index if it exists.
    Otherwise returns an empty string.
    """
    try:
        return some_list[int(current_index) - 1]  # access the previous element
    except (IndexError, ValueError):
        return ""


@register.filter(name="get_user_role")
def get_user_role(user):
    return get_user_groups(user)


@register.filter(name="parse_references")
def parse_references(value):
    """
    Parse references field from various formats into a list of URLs.

    Args:
        value: The references field value (string)

    Returns:
        list: List of reference URLs
    """
    if not value:
        return []

    # Clean the value
    value = str(value).strip()

    if not value:
        return []

    try:
        # Try to parse as array (JSON or Python list)
        if value.startswith("[") and value.endswith("]"):
            # Try Python list literal first (more common in this context)
            try:
                return ast.literal_eval(value)
            except (ValueError, SyntaxError):
                pass

            # Try JSON format as fallback
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                pass

            # Log error only if both parsing methods failed
            logger.error(f"Failed to parse array format for value: {value}")
            logger.debug("Both AST literal_eval and JSON parsing failed", exc_info=True)

        # Try to parse as JSON (value may be plain text/markdown from AI reports)
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return parsed
            elif isinstance(parsed, str):
                return [parsed]
        except json.JSONDecodeError:
            pass

        # Split by common separators and filter URLs
        # Look for URLs in the text
        url_pattern = r'https?://[^\s\],\'"]+|www\.[^\s\],\'"]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}[^\s\],\'"]*'
        urls = re.findall(url_pattern, value)

        if urls:
            return [url.rstrip(".,;)]}") for url in urls]

        # Split by newlines, commas, or semicolons
        refs = []
        for separator in ["\n", ",", ";"]:
            if separator in value:
                refs = [ref.strip() for ref in value.split(separator) if ref.strip()]
                break

        if not refs:
            refs = [value]

        # Filter out non-URL looking strings
        filtered_refs = []
        for ref in refs:
            ref = ref.strip().strip("'\"")
            if ref and ("http" in ref or "www." in ref or "." in ref):
                filtered_refs.append(ref)

        return filtered_refs if filtered_refs else refs

    except Exception:
        # If all parsing fails, return the original value as a single item
        return [value]


@register.filter(name="pretty_json")
def pretty_json(value):
    """
    Format JSON data in a readable way.

    Args:
        value: JSON data (dict, list, or JSON string)

    Returns:
        str: Formatted JSON string
    """
    if value is None:
        return ""

    try:
        # If it's already a dict or list, use it directly
        if isinstance(value, (dict, list)):
            return json.dumps(value, indent=2, ensure_ascii=False)
        # If it's a string, try to parse it first
        elif isinstance(value, str):
            try:
                parsed = json.loads(value)
                return json.dumps(parsed, indent=2, ensure_ascii=False)
            except (json.JSONDecodeError, TypeError):
                return value
        else:
            return str(value)
    except Exception as e:
        logger.error(f"Error formatting JSON: {e}")
        return str(value)
