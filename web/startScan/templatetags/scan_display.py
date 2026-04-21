"""
Template tags and filters for scan display logic.

Provides scan_display_name from the scan's target (Target.value).
"""

from django import template

from reNgine.utilities.domain import get_scan_display_name


register = template.Library()


@register.filter
def scan_domain_display(scan, _unused=None) -> str:
    """
    Return the display name for a scan from its target value.

    Usage: {{ history|scan_domain_display }}
    """
    target = getattr(scan, "target", None) if scan else None
    target_value = (getattr(target, "value", None) or "") if target else ""
    return get_scan_display_name(target_value)
