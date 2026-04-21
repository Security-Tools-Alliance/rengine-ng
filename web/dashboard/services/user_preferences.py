"""
Single place to read and write user preferences (interface, DataTables display, etc.).
"""

from typing import Any

from dashboard.models import (
    DATATABLES_DISPLAY_CLASSIC,
    DATATABLES_DISPLAY_SCROLLER,
    DATATABLES_PAGE_LENGTH_CHOICES,
    DATATABLES_PAGE_LENGTH_DEFAULT,
    UserPreference,
)


PREF_DATATABLES_DISPLAY = "datatables_display"
PREF_DATATABLES_PAGE_LENGTH = "datatables_page_length"


def get_user_preference(user: Any, key: str, default: Any = None) -> Any:
    """
    Return the value for the given preference key for the user, or default if not set.

    Args:
        user: Django user (must be authenticated for preferences to exist).
        key: Preference key (e.g. PREF_DATATABLES_DISPLAY).
        default: Value to return when the key is missing or user has no preferences.

    Returns:
        The stored value or default.
    """
    if user is None or not getattr(user, "is_authenticated", True) or not user.is_authenticated:
        return default
    try:
        prefs = UserPreference.objects.get(user=user)
        return prefs.preferences.get(key, default)
    except UserPreference.DoesNotExist:
        return default


def set_user_preference(user: Any, key: str, value: Any) -> None:
    """
    Set a preference for the user. Creates UserPreference if it does not exist.

    Args:
        user: Django user (must be authenticated).
        key: Preference key.
        value: Value to store (must be JSON-serializable).
    """
    if user is None or not getattr(user, "is_authenticated", True) or not user.is_authenticated:
        return
    prefs, _ = UserPreference.objects.get_or_create(user=user, defaults={"preferences": {}})
    prefs.preferences[key] = value
    prefs.save(update_fields=["preferences"])


def get_datatables_display(user: Any) -> str:
    """
    Return the user's DataTables display mode: 'scroller' or 'classic'.

    Default is 'classic' when not set or when user is not authenticated.
    """
    value = get_user_preference(user, PREF_DATATABLES_DISPLAY, default=DATATABLES_DISPLAY_CLASSIC)
    if value in (DATATABLES_DISPLAY_CLASSIC, DATATABLES_DISPLAY_SCROLLER):
        return value
    return DATATABLES_DISPLAY_CLASSIC


def get_datatables_page_length(user: Any) -> int:
    """
    Return the user's default DataTables page length (rows per page).

    Default is DATATABLES_PAGE_LENGTH_DEFAULT when not set or invalid.
    """
    value = get_user_preference(user, PREF_DATATABLES_PAGE_LENGTH, default=DATATABLES_PAGE_LENGTH_DEFAULT)
    try:
        n = int(value)
    except (TypeError, ValueError):
        return DATATABLES_PAGE_LENGTH_DEFAULT
    return n if n in DATATABLES_PAGE_LENGTH_CHOICES else DATATABLES_PAGE_LENGTH_DEFAULT
