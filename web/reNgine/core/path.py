"""
Path utilities - Leaf layer.
Safe path handling with no Django dependencies.
"""

import os
from pathlib import Path
import re
import shutil
from typing import List, Literal, Optional, Union

from reNgine.utilities.logger import get_module_logger


logger = get_module_logger(__name__)

RmtreeResult = Literal["removed", "refused", "not_found", "failed"]

UnlinkResult = Literal["removed", "refused", "not_found", "failed"]


def safe_unlink(base_dir: Union[str, Path], path: Union[str, Path]) -> UnlinkResult:
    """Remove a single file only if path (after resolving symlinks) is under base_dir.

    Returns:
        "removed": File was removed.
        "refused": Path is outside base_dir (not removed).
        "not_found": Path does not exist or is not a file (nothing to remove).
        "failed": Path was valid but removal raised OSError.
    """
    base_dir_abs = os.path.abspath(str(base_dir))
    try:
        resolved_path = Path(path).resolve()
    except OSError as e:
        logger.warning("Failed to resolve path %s: %s", path, e)
        return "failed"
    resolved_abs = os.path.abspath(str(resolved_path))
    if not is_safe_path(base_dir_abs, resolved_abs):
        logger.warning("Refused to remove path outside base: %s -> %s", path, resolved_abs)
        return "refused"
    if not resolved_path.exists():
        return "not_found"
    if not resolved_path.is_file():
        return "not_found"
    try:
        resolved_path.unlink()
        logger.info("Removed file %s", resolved_abs)
        return "removed"
    except OSError as e:
        logger.warning("Failed to remove file %s: %s", resolved_abs, e)
        return "failed"


def _safe_path_components(
    path_str: str,
    *,
    separator: str = "/",
    reject_absolute: bool = False,
) -> Optional[List[str]]:
    """Return sanitized path components or None if invalid.

    Shared rules: reject empty input, null byte, empty segments, and any
    segment exactly equal to '..'. If reject_absolute is True, reject paths
    that start with /. Used by normalize_relative_path and
    _normalize_results_dir_components to avoid drift.
    """
    if not path_str or not path_str.strip() or "\x00" in path_str:
        return None
    raw = path_str.strip()
    if reject_absolute and raw.startswith("/"):
        return None
    raw = raw.replace("\\", "/")
    parts = [p for p in raw.split(separator) if p]
    if ".." in parts:
        return None
    if not parts:
        return None
    return [SafePath.sanitize_component(p) for p in parts]


def _normalize_results_dir_components(results_dir: str) -> Optional[List[str]]:
    """Normalize a results_dir string into safe path components.

    Splits on path separators, rejects empty segments and any path containing
    '..' (parent traversal). Sanitizes each segment. Returns None if invalid.
    """
    if not results_dir or not results_dir.strip() or "\x00" in results_dir:
        return None
    raw = results_dir.strip().replace("/", os.sep)
    return _safe_path_components(raw, separator=os.sep, reject_absolute=False)


def resolve_results_dir_under_base(base_dir: Union[str, Path], results_dir: str) -> Optional[Path]:
    """Resolve and validate a results_dir string against a base directory (e.g. RENGINE_RESULTS).

    For absolute results_dir: resolve and ensure it is a directory under base_dir.
    For relative results_dir: normalize into safe components, join under base, then validate.
    Returns the resolved Path if it exists, is a directory, and is under base_dir;
    otherwise None. Callers can pass the result to safe_rmtree(base_dir, path).
    """
    if not results_dir or not results_dir.strip():
        return None
    base = Path(base_dir).resolve()
    raw = results_dir.strip()
    path = Path(raw)
    if path.is_absolute():
        try:
            path = path.resolve()
        except (OSError, TypeError):
            return None
        if not path.is_dir():
            return None
        base_abs = str(base)
        path_abs = str(path)
        if not is_safe_path(base_abs, path_abs):
            return None
        return path
    components = _normalize_results_dir_components(results_dir)
    if not components:
        return None
    try:
        path = base.joinpath(*components).resolve()
    except (OSError, TypeError):
        return None
    if not path.is_dir():
        return None
    base_abs = str(base)
    path_abs = str(path)
    if not is_safe_path(base_abs, path_abs):
        return None
    return path


def safe_rmtree(base_dir: Union[str, Path], path: Union[str, Path]) -> RmtreeResult:
    """Remove directory tree only if path (after resolving symlinks) is under base_dir.

    Resolves the real target first so a symlink under base_dir that points
    outside the intended tree is refused.

    Returns:
        "removed": Directory was removed.
        "refused": Path is outside base_dir (not removed).
        "not_found": Path does not exist or is not a directory (nothing to remove).
        "failed": Path was valid but removal raised OSError.
    """
    base_dir_abs = os.path.abspath(str(base_dir))
    try:
        resolved_path = Path(path).resolve()
    except OSError as e:
        logger.warning("Failed to resolve path %s: %s", path, e)
        return "failed"
    resolved_abs = os.path.abspath(str(resolved_path))
    if not is_safe_path(base_dir_abs, resolved_abs):
        logger.warning("Refused to remove path outside base: %s -> %s", path, resolved_abs)
        return "refused"
    if not os.path.isdir(resolved_abs):
        return "not_found"
    try:
        shutil.rmtree(resolved_abs)
        logger.info("Removed directory %s", resolved_abs)
        return "removed"
    except OSError as e:
        logger.warning("Failed to remove directory %s: %s", resolved_abs, e)
        return "failed"


def normalize_relative_path(relative_path: str) -> Optional[str]:
    """Normalize a relative path for safe resolution under a base directory.

    Rejects absolute paths, null bytes, empty segments, and any '..' segment.
    Splits into segments, sanitizes each, and rejoins. Returns None if invalid.
    Filenames containing '..' as part of the name (e.g. 'file..name') remain valid.
    """
    components = _safe_path_components(relative_path, separator="/", reject_absolute=True)
    if not components:
        return None
    normalized = "/".join(components)
    return normalized or None


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
            logger.error("Error creating safe path: %s", e)
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
