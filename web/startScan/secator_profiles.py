from __future__ import annotations

import logging
from typing import TypedDict

from django.conf import settings

from scanEngine.models import SecatorProfile


logger = logging.getLogger(__name__)


# Supported Secator profile categories used for grouping in the UI.
SECATOR_PROFILE_CATEGORIES: list[str] = ["speed", "evasion", "general", "network"]


class SecatorProfilesContext(TypedDict):
    custom_profiles_by_category: dict[str, list[SecatorProfile]]
    default_profiles: dict[str, str]


def build_secator_profiles_context() -> SecatorProfilesContext:
    """
    Build template context for Secator profiles selection component.

    The `secator_profiles.html` template expects:
    - default_profiles: mapping category -> default profile name
    - custom_profiles_by_category: mapping category -> list[SecatorProfile]
    """
    custom_profiles_by_category: dict[str, list[SecatorProfile]] = {
        category: [] for category in SECATOR_PROFILE_CATEGORIES
    }

    unknown_categories: set[str] = set()

    custom_profiles = SecatorProfile.objects.filter(profile_type="custom", is_active=True).order_by(
        "category", "name"
    )
    for profile in custom_profiles:
        if profile.category in custom_profiles_by_category:
            custom_profiles_by_category[profile.category].append(profile)
        else:
            unknown_categories.add(profile.category)

    if unknown_categories:
        logger.warning(
            "SecatorProfile(s) with unknown categories encountered; they will not be shown in the UI. "
            "Unknown categories: %s",
            ", ".join(sorted(str(c) for c in unknown_categories)),
        )
        if getattr(settings, "DEBUG", False):
            raise ValueError(
                f"Unknown SecatorProfile categories found: {sorted(unknown_categories)}. "
                f"Known categories: {SECATOR_PROFILE_CATEGORIES}"
            )

    default_profiles = SecatorProfile.get_default_profiles(categories=SECATOR_PROFILE_CATEGORIES)

    return {
        "custom_profiles_by_category": custom_profiles_by_category,
        "default_profiles": default_profiles,
    }

