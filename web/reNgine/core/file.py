"""
File operation utilities - Leaf layer.
Pure file operations with no Django dependencies.
"""

import os
from pathlib import Path
import shutil
from typing import Optional, Union

from celery.utils.log import get_task_logger


logger = get_task_logger(__name__)


def _is_safe_path(base_path: Union[str, Path], target_path: Union[str, Path]) -> bool:
    """
    Check if target_path is safe to access relative to base_path.
    Uses pathlib for robust path resolution and security checks.

    Args:
        base_path: Base directory path
        target_path: Target path to check

    Returns:
        bool: True if path is safe, False otherwise
    """
    try:
        base = Path(base_path).resolve()
        target = Path(target_path).resolve()

        # Check if target is within base directory using pathlib
        try:
            target.relative_to(base)
            return True
        except ValueError:
            # target is not relative to base
            return False

    except (OSError, ValueError, RuntimeError):
        return False


def _validate_path_security(path: Union[str, Path]) -> tuple[bool, Optional[str]]:
    """
    Validate that a path is secure for file operations.
    Uses pathlib for robust path validation and security checks.

    Args:
        path: Path to validate

    Returns:
        tuple: (is_safe, error_message)
    """
    try:
        path_obj = Path(path)

        # Check for directory traversal components
        for part in path_obj.parts:
            if part == "..":
                return False, f"Directory traversal detected in path: {path}"
            if part.startswith("~"):
                return False, f"Home directory reference detected in path: {path}"

        # Check if path exists
        if not path_obj.exists():
            return True, None

        # Check for symlinks using pathlib
        if path_obj.is_symlink():
            return False, f"Symlink detected: {path}"

        # Additional security checks
        resolved_path = path_obj.resolve()
        if str(resolved_path) != str(path_obj.absolute()):
            return False, f"Path resolution mismatch detected: {path}"

        return True, None
    except (OSError, ValueError, RuntimeError) as e:
        return False, f"Path validation error: {e}"


def _is_safe_pattern(pattern: str) -> bool:
    """
    Validate that a glob pattern is safe to use.
    Uses comprehensive security checks to prevent dangerous patterns.

    Args:
        pattern: Glob pattern to validate

    Returns:
        bool: True if pattern is safe, False otherwise
    """
    if not pattern or not isinstance(pattern, str):
        return False

    # Normalize pattern
    pattern = pattern.strip()
    if not pattern:
        return False

    # Check for dangerous patterns using pathlib
    try:
        # Only validate path structure if pattern doesn't contain glob characters
        if "*" not in pattern and "?" not in pattern:
            pattern_path = Path(pattern)

            # Check for directory traversal
            if ".." in pattern_path.parts:
                return False

            # Check for absolute paths
            if pattern_path.is_absolute():
                return False

            # Check for home directory references
            if any(part.startswith("~") for part in pattern_path.parts):
                return False
        else:
            # For glob patterns, do basic string checks
            if ".." in pattern:
                return False
            if pattern.startswith("/"):
                return False
            if "~" in pattern:
                return False

    except (OSError, ValueError):
        return False

    # Check for dangerous glob characters (Linux/Debian specific)
    dangerous_chars = ["**", "~", "/"]
    if any(char in pattern for char in dangerous_chars):
        return False

    # Check for patterns that start with dots (hidden files)
    if pattern.startswith("."):
        return False

    # Check for patterns that are too broad
    if pattern in {"*", "?", ""}:
        return False

    # Check for patterns that could match system files (Linux/Debian specific)
    system_patterns = {"*.so", "*.ini", "*.cfg", "*.conf", "*.log"}
    pattern_lower = pattern.lower()
    if pattern_lower in system_patterns:
        return False

    # Check for patterns that could match critical system files
    critical_patterns = {"*.*", "*.", ".*", "..*"}
    return pattern not in critical_patterns


def _atomic_validate_and_delete(target_path: Path, base_path: Path) -> bool:
    """
    Atomically validate and delete a file/directory to prevent TOCTOU attacks.

    This function performs security validation immediately before deletion
    to prevent race conditions where an attacker might modify the file system
    between validation and deletion.

    Args:
        target_path: Path to the file/directory to delete
        base_path: Base directory for security validation

    Returns:
        bool: True if successfully deleted, False if validation failed or deletion error
    """
    try:
        # Re-validate path security immediately before deletion (TOCTOU protection)
        is_safe, error_msg = _validate_path_security(target_path)
        if not is_safe:
            logger.error(f"TOCTOU protection: Security validation failed for '{target_path}': {error_msg}")
            return False

        # Re-validate that target is within base directory
        if not _is_safe_path(base_path, target_path):
            logger.error(f"TOCTOU protection: Target '{target_path}' is outside base directory '{base_path}'")
            return False

        # Check if file still exists (might have been deleted by another process)
        if not target_path.exists():
            logger.debug(f"Target '{target_path}' no longer exists - skipping deletion")
            return True

        # Re-check file type (might have been changed by attacker)
        if target_path.is_symlink():
            logger.error(f"TOCTOU protection: Target '{target_path}' is a symlink - refusing to delete")
            return False

        # Perform deletion
        if target_path.is_file():
            target_path.unlink()
            logger.debug(f"Atomically removed file: {target_path}")
        elif target_path.is_dir():
            shutil.rmtree(target_path)
            logger.debug(f"Atomically removed directory: {target_path}")
        else:
            logger.error(f"TOCTOU protection: Unknown file type for '{target_path}' - refusing to delete")
            return False

        return True

    except OSError as e:
        logger.error(f"TOCTOU protection: Failed to delete '{target_path}': {e}")
        return False
    except Exception as e:
        logger.error(f"TOCTOU protection: Unexpected error deleting '{target_path}': {e}")
        return False


def remove_file_or_pattern(path: Union[str, Path], pattern: Optional[str] = None) -> bool:
    """
    Safely removes a file/directory or pattern matching files.
    Uses pathlib for robust path handling and comprehensive security checks.

    Security features:
    - TOCTOU (Time-of-Check-Time-of-Use) protection with atomic validation
    - Symlink attack prevention
    - Directory traversal protection
    - Pattern validation to prevent dangerous glob patterns
    - Re-validation immediately before deletion to prevent race conditions

    Args:
        path: Path to file/directory to remove
        pattern: Optional pattern for multiple files (e.g. "*.csv")

    Returns:
        bool: True if successful, False if error occurred
    """
    try:
        path_obj = Path(path)

        # Validate base path security
        is_safe, error_msg = _validate_path_security(path_obj)
        if not is_safe:
            logger.error(f"Security validation failed for path '{path}': {error_msg}")
            return False

        if pattern:
            # Validate pattern for security
            if not _is_safe_pattern(pattern):
                logger.error(f"Unsafe pattern detected: '{pattern}'")
                return False

            # Ensure path is a directory when using patterns
            if not path_obj.is_dir():
                logger.error(f"Pattern matching requires a directory, got: {path}")
                return False

            # Use pathlib for pattern matching
            matched_files = list(path_obj.glob(pattern))
            if not matched_files:
                logger.warning(f"No files matching pattern '{pattern}' in {path}")
                return True

            all_deleted = True
            for file_path in matched_files:
                # Validate each matched file path
                is_safe, error_msg = _validate_path_security(file_path)
                if not is_safe:
                    logger.error(f"Security validation failed for file '{file_path}': {error_msg}")
                    all_deleted = False
                    continue

                # Additional check: ensure file is within the base directory
                if not _is_safe_path(path_obj, file_path):
                    logger.error(f"File '{file_path}' is outside allowed directory '{path}'")
                    all_deleted = False
                    continue

                # TOCTOU protection: Re-validate security immediately before deletion
                if not _atomic_validate_and_delete(file_path, path_obj):
                    logger.error(f"Atomic validation failed for '{file_path}' - skipping deletion")
                    all_deleted = False
            return all_deleted
        else:
            if not path_obj.exists():
                logger.warning(f"Path {path} does not exist")
                return True

            # TOCTOU protection: Re-validate security immediately before deletion
            if not _atomic_validate_and_delete(path_obj, path_obj.parent):
                logger.error(f"Atomic validation failed for '{path}' - skipping deletion")
                return False

            return True

    except (OSError, ValueError, RuntimeError) as e:
        logger.error(f"Failed to delete {path}: {str(e)}")
        return False


def is_nuclei_config_valid(config_path):
    """
    Check if the Nuclei configuration file contains valid configuration content.

    A valid Nuclei config file should contain at least one non-empty, non-comment line
    that appears to be a valid configuration directive (contains '=' or starts with a valid
    Nuclei configuration keyword).

    Args:
        config_path (str): Path to the Nuclei configuration file

    Returns:
        bool: True if the config file has valid content, False otherwise
    """
    try:
        if not os.path.exists(config_path):
            return False

        valid_config_found = False
        with open(config_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                # Check if line contains a configuration directive
                # Nuclei config typically uses key=value format or specific keywords
                if "=" in line or _is_nuclei_config_keyword(line):
                    valid_config_found = True
                    break
                else:
                    # Log suspicious content for debugging
                    logger.debug(f"Nuclei config line {line_num} doesn't appear to be valid config: '{line}'")

        if not valid_config_found:
            logger.warning(f"Nuclei config file {config_path} contains no valid configuration directives")

        return valid_config_found

    except Exception as e:
        logger.warning(f"Could not read Nuclei config file {config_path}: {e}")
        return False


def _is_nuclei_config_keyword(line):
    """
    Check if a line contains a valid Nuclei configuration keyword.

    Args:
        line (str): Line to check

    Returns:
        bool: True if line contains a valid Nuclei config keyword
    """
    # Common Nuclei configuration keywords (case-insensitive)
    nuclei_keywords = {
        "include",
        "exclude",
        "severity",
        "tags",
        "author",
        "description",
        "reference",
        "classification",
        "metadata",
        "info",
        "requests",
        "variables",
        "payloads",
        "matchers",
        "extractors",
        "conditions",
        "name",
        "template",
        "id",
        "version",
        "type",
        "protocol",
        "port",
    }

    # Remove leading whitespace and get the first word
    stripped_line = line.strip()
    if not stripped_line:
        return False

    # Get the first word (before any space, colon, or special character)
    first_word = stripped_line.split()[0].lower() if stripped_line.split() else ""

    # Also check if the line contains a colon (YAML format) with a valid keyword
    if ":" in stripped_line:
        key_part = stripped_line.split(":")[0].strip().lower()
        return key_part in nuclei_keywords

    return first_word in nuclei_keywords


def read_file_lines(file_path, skip_empty=True, skip_comments=True):
    """
    Read lines from a file with optional filtering and security validation.

    Security features:
    - Path validation to prevent directory traversal attacks
    - Symlink detection to prevent reading from unintended locations
    - Safe file type validation

    Args:
        file_path: Path to file
        skip_empty: Skip empty lines
        skip_comments: Skip lines starting with #

    Returns:
        list: List of file lines
    """
    try:
        # Convert to Path object for robust handling
        path_obj = Path(file_path)

        # Validate path security
        is_safe, error_msg = _validate_path_security(path_obj)
        if not is_safe:
            logger.error(f"Security validation failed for file path '{file_path}': {error_msg}")
            return []

        # Check if file exists
        if not path_obj.exists():
            logger.warning(f"File {file_path} does not exist")
            return []

        # Ensure it's a file, not a directory or symlink
        if not path_obj.is_file():
            if path_obj.is_dir():
                logger.error(f"Path is a directory, not a file: {file_path}")
            elif path_obj.is_symlink():
                logger.error(f"Path is a symlink, refusing to read: {file_path}")
            else:
                logger.error(f"Path exists but is not a regular file: {file_path}")
            return []

        lines = []
        with open(path_obj, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()

                if skip_empty and not line:
                    continue
                if skip_comments and line.startswith("#"):
                    continue

                lines.append(line)

        logger.debug(f"Successfully read {len(lines)} lines from {file_path}")
        return lines

    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return []


def write_file_lines(file_path, lines, mode="w"):
    """
    Write lines to a file with security validation.

    Security features:
    - Path validation to prevent directory traversal attacks
    - Symlink detection to prevent writing to unintended locations
    - Safe directory creation with proper permissions

    Args:
        file_path: Path to file
        lines: List of lines to write
        mode: Write mode ('w' or 'a')

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Convert to Path object for robust handling
        path_obj = Path(file_path)

        # Validate path security
        is_safe, error_msg = _validate_path_security(path_obj)
        if not is_safe:
            logger.error(f"Security validation failed for file path '{file_path}': {error_msg}")
            return False

        # Ensure parent directory exists with safe permissions
        parent_dir = path_obj.parent
        if not parent_dir.exists():
            try:
                parent_dir.mkdir(parents=True, mode=0o755, exist_ok=True)
                logger.debug(f"Created parent directory: {parent_dir}")
            except OSError as e:
                logger.error(f"Failed to create parent directory '{parent_dir}': {e}")
                return False

        # Validate parent directory security
        is_parent_safe, parent_error_msg = _validate_path_security(parent_dir)
        if not is_parent_safe:
            logger.error(f"Parent directory security validation failed for '{parent_dir}': {parent_error_msg}")
            return False

        # Write file with atomic operation
        with open(path_obj, mode, encoding="utf-8") as f:
            for line in lines:
                f.write(f"{line}\n")

        logger.debug(f"Successfully wrote {len(lines)} lines to {file_path}")
        return True

    except Exception as e:
        logger.error(f"Error writing to file {file_path}: {e}")
        return False


def ensure_directory_exists(directory_path, mode=0o755):
    """
    Ensure a directory exists, creating it if necessary with security validation.

    Security features:
    - Path validation to prevent directory traversal attacks
    - Symlink detection to prevent creation in unintended locations
    - Safe permissions enforcement

    Args:
        directory_path: Path to directory
        mode: Directory permissions (default: 0o755)

    Returns:
        bool: True if directory exists or was created, False otherwise
    """
    try:
        # Convert to Path object for robust handling
        path_obj = Path(directory_path)

        # Validate path security
        is_safe, error_msg = _validate_path_security(path_obj)
        if not is_safe:
            logger.error(f"Security validation failed for directory path '{directory_path}': {error_msg}")
            return False

        # Check if directory already exists
        if path_obj.exists():
            if path_obj.is_dir():
                logger.debug(f"Directory already exists: {directory_path}")
                return True
            else:
                logger.error(f"Path exists but is not a directory: {directory_path}")
                return False

        # Create directory with safe permissions
        try:
            path_obj.mkdir(parents=True, mode=mode, exist_ok=True)
            logger.debug(f"Created directory: {directory_path} with mode {oct(mode)}")
            return True
        except OSError as e:
            logger.error(f"Failed to create directory '{directory_path}': {e}")
            return False

    except Exception as e:
        logger.error(f"Error ensuring directory exists {directory_path}: {e}")
        return False
