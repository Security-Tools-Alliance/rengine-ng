"""
Path utilities - Leaf layer.
Safe path handling with no Django dependencies.
"""

import os
from pathlib import Path
import re
from typing import List, Union

from celery.utils.log import get_task_logger


logger = get_task_logger(__name__)


def is_safe_path(basedir, path, follow_symlinks=True):
    """
    Check if a path is safe (inside base directory).
    Source: https://security.openstack.org/guidelines/dg_using-file-paths.html

    Args:
        basedir: Base directory path
        path: Path to check
        follow_symlinks: Whether to resolve symbolic links

    Returns:
        bool: True if path is safe, False otherwise
    """
    if follow_symlinks:
        matchpath = os.path.realpath(path)
    else:
        matchpath = os.path.abspath(path)
    return basedir == os.path.commonpath((basedir, matchpath))


def remove_lead_and_trail_slash(s):
    """
    Remove leading and trailing slashes from a string.
    Source: https://stackoverflow.com/a/10408992

    Args:
        s: String to clean

    Returns:
        str: String without leading/trailing slashes
    """
    if s.startswith("/"):
        s = s[1:]
    if s.endswith("/"):
        s = s[:-1]
    return s


class SafePath:
    """Utility class for safe path handling and directory creation."""

    @staticmethod
    def sanitize_component(component: str) -> str:
        """
        Sanitize a path component to prevent directory traversal.

        Args:
            component (str): Path component to sanitize

        Returns:
            str: Sanitized path component
        """
        return re.sub(r"[^a-zA-Z0-9\-\_\.]", "_", component)

    @classmethod
    def create_safe_path(
        cls, base_dir: Union[str, Path], components: List[str], create_dir: bool = True, mode: int = 0o755
    ) -> str:
        """
        Create a safe path within the base directory.

        Args:
            base_dir (str|Path): Base directory
            components (list): List of path components
            create_dir (bool): Whether to create the directory
            mode (int): Directory permissions if created

        Returns:
            str: Safe path object

        Raises:
            ValueError: If path would be outside base directory
            OSError: If directory creation fails
        """
        try:
            base_path = Path(base_dir).resolve()
            safe_components = [cls.sanitize_component(c) for c in components]
            full_path = base_path.joinpath(*safe_components)
            abs_path = full_path.resolve()

            if not str(abs_path).startswith(str(base_path)):
                raise ValueError(f"Invalid path: {abs_path} is outside base directory {base_path}")

            if create_dir:
                abs_path.mkdir(parents=True, mode=mode, exist_ok=True)
                logger.debug(f"Created directory: {abs_path}")

            return str(abs_path)

        except Exception as e:
            logger.error(f"Error creating safe path: {str(e)}")
            raise

    @classmethod
    def is_safe_path(cls, base_dir: Union[str, Path], path: Union[str, Path], follow_symlinks: bool = True) -> bool:
        """
        Enhanced version of is_safe_path that uses pathlib.
        Maintains compatibility with existing code while adding more security.

        Args:
            base_dir: Base directory
            path: Path to check
            follow_symlinks: Whether to follow symbolic links

        Returns:
            bool: True if path is safe, False otherwise
        """
        try:
            base_path = Path(base_dir).resolve()
            check_path = Path(path)

            check_path = check_path.resolve() if follow_symlinks else check_path.absolute()
            return str(check_path).startswith(str(base_path))
        except Exception:
            return False
