"""
Proxy utilities for reNgine.

This module provides utilities for working with proxies and proxy management.
"""

import random
import re
import logging

logger = logging.getLogger(__name__)


def get_random_proxy() -> str:
    """Get a random proxy from the list of proxies input by user in the UI.

    Returns:
        str: Proxy name or '' if no proxy defined in db or use_proxy is False.
    """
    from scanEngine.models import Proxy
    
    proxy = Proxy.objects.filter(use_proxy=True).order_by("?").first()
    if not proxy:
        return ""
    proxy_name = random.choice(proxy.proxies.splitlines())
    logger.warning(f"Using proxy: {proxy_name}")
    # os.environ['HTTP_PROXY'] = proxy_name
    # os.environ['HTTPS_PROXY'] = proxy_name
    return proxy_name


def remove_ansi_escape_sequences(text: str) -> str:
    """
    Remove ANSI escape sequences from text.
    
    Args:
        text: Text to clean
        
    Returns:
        str: Text without ANSI escape sequences
    """
    return re.sub(r"\x1b\[[0-9;]*m", "", text)
