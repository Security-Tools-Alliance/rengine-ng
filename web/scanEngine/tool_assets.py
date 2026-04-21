"""
Helpers for custom scan assets (GF patterns, Nuclei templates).
Single responsibility; used by tool_specific_settings and GetFileContents.
"""

from pathlib import Path
import re
from typing import TypedDict

from django.contrib import messages

from reNgine.utilities.logger import get_module_logger


PREFIX_TOOL_ASSETS = "[TOOL_ASSETS]"
logger = get_module_logger(__name__)


class UploadResult(TypedDict):
    """Result of save_uploaded_assets: counts of saved and errored files."""

    saved: int
    errors: int


def list_asset_files(asset_dir: str, extension: str) -> list[str]:
    """List file names in asset_dir with the given extension (e.g. 'json', 'yaml'). For 'yaml', both .yaml and .yml are listed."""
    path = Path(asset_dir)
    if not path.is_dir():
        return []
    suffix = extension if extension.startswith(".") else f".{extension}"
    suffixes = (suffix, ".yml") if suffix == ".yaml" else (suffix,)
    return sorted(p.name for p in path.iterdir() if p.is_file() and p.suffix.lower() in suffixes)


def _normalize_asset_filename(raw_name: str, max_length: int = 100) -> str | None:
    """
    Normalize an uploaded asset base filename.

    - Strips characters invalid/unsafe on common filesystems.
    - Trims surrounding whitespace.
    - Removes leading dots to avoid hidden/system-like names.
    - Returns None if the name becomes empty or only dots/whitespace.
    - Truncates to max_length characters.
    """
    sanitized = re.sub(r'[\\/*?:"<>|]', "", raw_name)
    sanitized = sanitized.strip()
    sanitized = sanitized.lstrip(".")
    if not sanitized or set(sanitized) <= {"."}:
        return None
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length].rstrip(". ")
        if not sanitized or set(sanitized) <= {"."}:
            return None
    return sanitized


def save_uploaded_assets(
    request, file_key: str, directory: str, allowed_extension: str, pattern_name: str
) -> UploadResult:
    """
    Save one or more uploaded files into directory. Creates directory if needed.
    Validates extension and filename; adds success/error messages to request.

    Returns:
        UploadResult: saved count and error count so callers can distinguish
            total failure (saved == 0 and errors > 0) from partial or full success.
    """
    dir_path = Path(directory)
    dir_path.mkdir(parents=True, exist_ok=True)
    ext = allowed_extension if allowed_extension.startswith(".") else f".{allowed_extension}"
    allowed_suffixes = (ext, ".yml") if ext == ".yaml" else (ext,)
    allowed_suffixes_lower = tuple(s.lower() for s in allowed_suffixes)
    files = request.FILES.getlist(file_key)
    if not files:
        if file_key in request.FILES:
            files = [request.FILES[file_key]]
        else:
            return UploadResult(saved=0, errors=0)
    saved_count = 0
    error_count = 0
    for uploaded_file in files:
        name = uploaded_file.name
        path_name = Path(name)
        stem = path_name.stem
        file_ext = path_name.suffix.lower()
        if file_ext not in allowed_suffixes_lower:
            expected = "*.yaml or *.yml" if ext == ".yaml" else f"*{ext}"
            messages.error(
                request,
                f"Invalid {pattern_name}: {name} (expected {expected})",
            )
            error_count += 1
            continue
        normalized_stem = _normalize_asset_filename(stem)
        if normalized_stem is None:
            messages.error(
                request,
                f"Invalid {pattern_name}: '{name}' (filename invalid or empty after sanitization).",
            )
            error_count += 1
            continue
        ext_to_use = file_ext
        base_name = f"{normalized_stem}{ext_to_use}"
        target = dir_path / base_name
        collision = 0
        while target.exists():
            collision += 1
            target = dir_path / f"{normalized_stem}_{collision}{ext_to_use}"
        try:
            with target.open("wb") as out_f:
                for chunk in uploaded_file.chunks():
                    if chunk:
                        out_f.write(chunk)
            messages.info(request, f"{pattern_name} {target.name} uploaded.")
            saved_count += 1
        except OSError as e:
            logger.log_line(
                PREFIX_TOOL_ASSETS,
                "SAVE",
                "Failed to save %s: %s" % (target, e),
                level="warning",
            )
            messages.error(request, f"Failed to save {target.name}.")
            error_count += 1
    return UploadResult(saved=saved_count, errors=error_count)
