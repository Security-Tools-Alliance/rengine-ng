"""
Time utilities for calculating and formatting time durations.

This module provides functionality for calculating time differences and
formatting them in human-readable format.
"""

from datetime import datetime
from typing import Union

from reNgine.utilities.core.formatting import format_duration


def get_time_taken(latest: Union[datetime, str], earlier: Union[datetime, str]) -> str:
    """
    Calculate and format the time difference between two timestamps.

    Args:
        latest: The later timestamp (datetime object or ISO string)
        earlier: The earlier timestamp (datetime object or ISO string)

    Returns:
        Human-readable time duration string

    Examples:
        >>> get_time_taken(datetime.now(), datetime.now() - timedelta(hours=2))
        '2 hours'

        >>> get_time_taken("2023-01-01T12:00:00", "2023-01-01T10:30:00")
        '1 hours 30 minutes'
    """
    try:
        # Convert string timestamps to datetime objects if needed
        if isinstance(latest, str):
            latest = datetime.fromisoformat(latest.replace("Z", "+00:00"))
        if isinstance(earlier, str):
            earlier = datetime.fromisoformat(earlier.replace("Z", "+00:00"))

        # Calculate the duration
        duration = latest - earlier

        # Use the core formatting function for consistent output
        return format_duration(duration.total_seconds())

    except (ValueError, TypeError):
        # Fallback to original implementation if parsing fails
        return _get_time_taken_fallback(latest, earlier)


def _get_time_taken_fallback(latest: Union[datetime, str], earlier: Union[datetime, str]) -> str:
    """
    Fallback implementation for get_time_taken using the original logic.

    This is used when the main implementation fails due to parsing errors.
    """
    try:
        # Ensure we have datetime objects
        if isinstance(latest, str):
            latest = datetime.fromisoformat(latest.replace("Z", "+00:00"))
        if isinstance(earlier, str):
            earlier = datetime.fromisoformat(earlier.replace("Z", "+00:00"))

        duration = latest - earlier
        days, seconds = duration.days, duration.seconds
        hours = days * 24 + seconds // 3600
        minutes = (seconds % 3600) // 60
        seconds = seconds % 60

        if hours and minutes:
            return f"{hours} hours {minutes} minutes"
        elif hours:
            return f"{hours} hours"
        elif minutes:
            return f"{minutes} minutes"
        return f"{seconds} seconds"

    except Exception:
        return "0 seconds"


def format_timestamp(timestamp: Union[datetime, str], format_string: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Format a timestamp to a human-readable string.

    Args:
        timestamp: The timestamp to format (datetime object or ISO string)
        format_string: The format string to use (default: "%Y-%m-%d %H:%M:%S")

    Returns:
        Formatted timestamp string

    Examples:
        >>> format_timestamp(datetime(2023, 1, 1, 12, 0, 0))
        '2023-01-01 12:00:00'

        >>> format_timestamp("2023-01-01T12:00:00Z", "%Y-%m-%d")
        '2023-01-01'
    """
    try:
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

        return timestamp.strftime(format_string)

    except (ValueError, TypeError):
        return str(timestamp)


def get_current_timestamp() -> datetime:
    """
    Get the current timestamp as a datetime object.

    Returns:
        Current datetime object
    """
    return datetime.now()


def get_current_timestamp_string() -> str:
    """
    Get the current timestamp as an ISO string.

    Returns:
        Current timestamp as ISO string
    """
    return datetime.now().isoformat()


def parse_timestamp(timestamp_string: str) -> datetime:
    """
    Parse a timestamp string to a datetime object.

    Args:
        timestamp_string: The timestamp string to parse

    Returns:
        Parsed datetime object

    Raises:
        ValueError: If the timestamp string cannot be parsed
    """
    try:
        return datetime.fromisoformat(timestamp_string.replace("Z", "+00:00"))
    except ValueError as e:
        raise ValueError(f"Unable to parse timestamp '{timestamp_string}': {e}")


def is_timestamp_valid(timestamp_string: str) -> bool:
    """
    Check if a timestamp string is valid and can be parsed.

    Args:
        timestamp_string: The timestamp string to validate

    Returns:
        True if the timestamp is valid, False otherwise
    """
    try:
        parse_timestamp(timestamp_string)
        return True
    except ValueError:
        return False
