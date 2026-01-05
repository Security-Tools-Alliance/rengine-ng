"""
Timezone utilities - Django-dependent functions.
Functions for handling timezone-aware datetime operations with Django.
"""

from datetime import date, datetime, timedelta
from datetime import timezone as dt_timezone
from typing import Any, Optional

from django.utils import timezone


def parse_datetime_iso(value: Any) -> Optional[datetime]:
    """
    Parse datetime from ISO string or datetime object and make it timezone-aware.

    Handles ISO format strings (including "Z" suffix), datetime objects,
    and ensures the result is timezone-aware using Django's timezone utilities.

    Args:
        value: Datetime value (can be string ISO format, datetime object, or None)

    Returns:
        datetime: Timezone-aware datetime object, or None if parsing fails
    """
    if value is None:
        return None

    if isinstance(value, datetime):
        # If datetime is naive, make it aware
        return timezone.make_aware(value) if timezone.is_naive(value) else value
    if isinstance(value, str):
        try:
            # Replace "Z" with "+00:00" for ISO format compatibility
            iso_string = value.replace("Z", "+00:00")
            parsed_time = datetime.fromisoformat(iso_string)
            # Make timezone-aware if naive
            if timezone.is_naive(parsed_time):
                return timezone.make_aware(parsed_time)
            return parsed_time
        except (ValueError, AttributeError):
            return None

    return None


def date_to_aware_datetime(date_obj: date) -> datetime:
    """
    Convert a date object to a timezone-aware datetime at midnight.

    Args:
        date_obj: Date object to convert

    Returns:
        datetime: Timezone-aware datetime at midnight (00:00:00)
    """
    return timezone.make_aware(datetime.combine(date_obj, datetime.min.time()))


def local_to_utc_aware(local_time: datetime, timezone_offset_minutes: int) -> datetime:
    """
    Convert a local datetime to UTC-aware datetime with timezone offset.

    Args:
        local_time: Local datetime (naive or aware)
        timezone_offset_minutes: Timezone offset in minutes (can be negative)

    Returns:
        datetime: UTC-aware datetime
    """
    # Adjust time by offset
    utc_time = local_time + timedelta(minutes=timezone_offset_minutes)
    # Make timezone-aware in UTC
    if timezone.is_naive(utc_time):
        return timezone.make_aware(utc_time, dt_timezone.utc)
    # If already aware, ensure it's in UTC
    return utc_time.astimezone(dt_timezone.utc)


def ensure_timezone_aware(dt: datetime, default_tz=dt_timezone.utc) -> datetime:
    """
    Ensure a datetime is timezone-aware.

    If the datetime is naive, makes it aware using the default timezone.
    Uses Django's timezone.make_aware() for consistency.

    Args:
        dt: Datetime object (naive or aware)
        default_tz: Default timezone to use if datetime is naive (default: UTC)

    Returns:
        datetime: Timezone-aware datetime
    """
    return timezone.make_aware(dt, default_tz) if timezone.is_naive(dt) else dt
