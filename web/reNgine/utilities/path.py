"""
Path utilities for reNgine.

This module provides utilities for working with file paths and path safety.
"""

import os
import logging
from typing import Union
from pathlib import Path

logger = logging.getLogger(__name__)


def is_safe_path(basedir: Union[str, Path], path: Union[str, Path], follow_symlinks: bool = True) -> bool:
    """
    Check if a path is safe (within the base directory).
    
    Source: https://security.openstack.org/guidelines/dg_using-file-paths.html
    
    Args:
        basedir: Base directory path
        path: Path to check
        follow_symlinks: Whether to follow symbolic links
        
    Returns:
        bool: True if path is safe, False otherwise
    """
    # resolves symbolic links
    if follow_symlinks:
        matchpath = os.path.realpath(path)
    else:
        matchpath = os.path.abspath(path)
    return basedir == os.path.commonpath((basedir, matchpath))


def remove_lead_and_trail_slash(s: str) -> str:
    """
    Remove leading and trailing slashes from a string.
    
    Source: https://stackoverflow.com/a/10408992
    
    Args:
        s: String to process
        
    Returns:
        str: String with leading and trailing slashes removed
    """
    if s.startswith("/"):
        s = s[1:]
    if s.endswith("/"):
        s = s[:-1]
    return s
