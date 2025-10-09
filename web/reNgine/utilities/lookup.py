"""
Lookup utilities for reNgine.

This module provides utilities for working with lookup keywords and interesting lookups.
"""

import logging
from typing import List

logger = logging.getLogger(__name__)


def get_lookup_keywords() -> List[str]:
    """Get lookup keywords from InterestingLookupModel.

    Returns:
        list: Lookup keywords.
    """
    from scanEngine.models import InterestingLookupModel
    
    lookup_obj = InterestingLookupModel.objects.order_by("-id").first()
    if not lookup_obj:
        return []

    lookup_keywords = [key.strip() for key in lookup_obj.keywords.split(",")]
    return list(filter(None, lookup_keywords))  # remove empty strings from list
