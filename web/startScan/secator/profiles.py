from __future__ import annotations

from typing import TypedDict

from django.conf import settings

from reNgine.utilities.logger import get_module_logger
from scanEngine.models import SecatorProfile


PREFIX_SECATOR_PROFILES = "[SECATOR_PROFILES]"
logger = get_module_logger(__name__)


# Supported Secator profile categories used for grouping in the UI.
SECATOR_PROFILE_CATEGORIES: list[str] = ["speed", "evasion", "general", "network"]

# Secator library built-in speed profile names (excluded from rengine builtin list).
SECATOR_SPEED_BUILTIN_NAMES: frozenset[str] = frozenset({"aggressive", "insane", "polite", "paranoid"})

# Display icons for rengine built-in speed profiles (hardware-tier).
SPEED_RENGINE_BUILTIN_ICONS: dict[str, str] = {
    "raspberry": "🍓",
    "nuc": "💻",
    "vps": "☁️",
    "desktop": "🖥️",
    "desktop_advanced": "⚡",
    "powerful": "🚀",
}


class SpeedRengineBuiltinProfile(TypedDict):
    name: str
    description: str
    icon: str
    display_name: str


class SecatorProfilesContext(TypedDict, total=False):
    custom_profiles_by_category: dict[str, list[SecatorProfile]]
    default_profiles: dict[str, str]
    speed_rengine_builtin_profiles: list[SpeedRengineBuiltinProfile]


def build_secator_profiles_context() -> SecatorProfilesContext:
    """
    Build template context for Secator profiles selection component.

    The `secator_profiles.html` template expects:
    - default_profiles: mapping category -> default profile name
    - custom_profiles_by_category: mapping category -> list[SecatorProfile]
    - speed_rengine_builtin_profiles: list of {name, description, icon} for built-in
      speed profiles from config (hardware-tier), shown under Secator speed profiles.
    """
    custom_profiles_by_category: dict[str, list[SecatorProfile]] = {
        category: [] for category in SECATOR_PROFILE_CATEGORIES
    }

    unknown_categories: set[str] = set()

    custom_profiles = SecatorProfile.objects.filter(profile_type="custom", is_active=True).order_by("category", "name")
    for profile in custom_profiles:
        if profile.category in custom_profiles_by_category:
            custom_profiles_by_category[profile.category].append(profile)
        else:
            unknown_categories.add(profile.category)

    if unknown_categories:
        logger.log_line(
            PREFIX_SECATOR_PROFILES,
            "PROFILES",
            "SecatorProfile(s) with unknown categories encountered; they will not be shown in the UI. "
            "Unknown categories: %s" % (", ".join(sorted(str(c) for c in unknown_categories)),),
            level="warning",
        )
        if getattr(settings, "DEBUG", False):
            raise ValueError(
                f"Unknown SecatorProfile categories found: {sorted(unknown_categories)}. "
                f"Known categories: {SECATOR_PROFILE_CATEGORIES}"
            )

    default_profiles = SecatorProfile.get_default_profiles(categories=SECATOR_PROFILE_CATEGORIES)

    speed_rengine_builtin_profiles: list[SpeedRengineBuiltinProfile] = []
    rengine_speed = (
        SecatorProfile.objects.filter(
            profile_type="builtin",
            category="speed",
            is_active=True,
        )
        .exclude(name__in=SECATOR_SPEED_BUILTIN_NAMES)
        .order_by("name")
    )
    for profile in rengine_speed:
        display_name = profile.name.replace("_", " ").title()
        speed_rengine_builtin_profiles.append(
            {
                "name": profile.name,
                "description": profile.description or "",
                "icon": SPEED_RENGINE_BUILTIN_ICONS.get(profile.name, "⚙️"),
                "display_name": display_name,
            }
        )

    return {
        "custom_profiles_by_category": custom_profiles_by_category,
        "default_profiles": default_profiles,
        "speed_rengine_builtin_profiles": speed_rengine_builtin_profiles,
    }
