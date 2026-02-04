"""
Wordlist upload and persistence helpers.

Used by scanEngine.views (add_wordlist) to keep view logic thin and to allow
unit testing of wordlist logic in isolation.
"""

import codecs
import os
from pathlib import Path
import re
import tempfile

from django.db import IntegrityError

from reNgine.settings import RENGINE_WORDLISTS
from reNgine.utilities.logger import get_module_logger
from scanEngine.models import Wordlist


logger = get_module_logger(__name__)

_MAX_WORDLIST_SHORT_NAME_RETRIES = 1000
_WORDLIST_SHORT_NAME_MAX_LENGTH = Wordlist._meta.get_field("short_name").max_length


def short_name_from_stem(stem: str) -> str:
    """Sanitize stem to a valid short_name (alphanumeric, hyphens, underscores)."""
    return re.sub(r"[^a-zA-Z0-9_-]", "_", stem).strip("_") or "wordlist"


def is_txt_filename(filename: str) -> bool:
    """Return True if filename has a .txt extension."""
    return Path(filename).suffix.lower() == ".txt"


def _is_short_name_unique_violation(exc: IntegrityError) -> bool:
    """Return True if the IntegrityError is from Wordlist.short_name uniqueness."""
    from django.db import connection

    if connection.vendor == "postgresql":
        cause = getattr(exc, "__cause__", None)
        if cause is None:
            return False
        if getattr(cause, "pgcode", None) != "23505":
            return False
        diag = getattr(cause, "diag", None)
        constraint_name = (getattr(diag, "constraint_name", None) or "").lower()
        return "short_name" in constraint_name and "wordlist" in constraint_name
    msg = str(exc).lower()
    return "short_name" in msg or ("wordlist" in msg and "unique" in msg)


def _truncate_base_short(base_short: str, max_len: int = 45, suffix: int | None = None) -> str:
    """Truncate base_short so that base_short[_N] fits in Wordlist.short_name max length.

    If suffix is provided, base_short is truncated so that the final string
    (including "_" and the suffix) is at most max_len characters, without
    truncating the suffix itself.
    """
    if suffix is None:
        if len(base_short) <= max_len:
            return base_short
        truncated = base_short[:max_len].rstrip("_")
        return truncated or "wordlist"

    suffix_str = f"_{suffix}"
    suffix_len = len(suffix_str)
    if suffix_len >= max_len:
        return suffix_str[:max_len]

    allowed_base_len = max_len - suffix_len
    if len(base_short) > allowed_base_len:
        base_short = base_short[:allowed_base_len].rstrip("_") or "wordlist"
    return f"{base_short}{suffix_str}"


def _candidate_short_name(base_short: str, suffix: int, max_total: int = _WORDLIST_SHORT_NAME_MAX_LENGTH) -> str:
    """Build candidate short_name for the given suffix, preserving the full suffix.

    Ensures base_short is truncated (if needed) so that the final short_name,
    including the suffix, never exceeds max_total characters.
    """
    if suffix:
        return _truncate_base_short(base_short, max_len=max_total, suffix=suffix)
    if len(base_short) <= max_total:
        return base_short
    truncated = base_short[:max_total].rstrip("_")
    return truncated or "wordlist"


def _write_content_to_file(target: Path, content: str) -> int:
    """Write content to target; return line count. Raises OSError on write failure."""
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return len(content.splitlines())


def _stream_upload_to_file(target: Path, uploaded_file) -> tuple[int, bool]:
    """Stream uploaded file to target; return (line_count, has_non_empty_line).

    Uses incremental UTF-8 decoding so multibyte characters split across chunks
    do not raise UnicodeDecodeError. Invalid bytes raise UnicodeDecodeError.
    Detects emptiness while streaming. Raises OSError or UnicodeDecodeError on failure.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    uploaded_file.seek(0)
    decoder = codecs.getincrementaldecoder("utf-8")()
    line_count = 0
    has_non_empty_line = False
    buffer = ""
    with open(target, "w", encoding="utf-8") as out:
        for chunk in uploaded_file.chunks():
            if chunk:
                buffer += decoder.decode(chunk)
            lines = buffer.splitlines(keepends=True)
            buffer = lines.pop(-1) if lines and not buffer.endswith("\n") else ""
            for line in lines:
                out.write(line)
                line_count += 1
                if not has_non_empty_line and line.strip():
                    has_non_empty_line = True
        buffer += decoder.decode(b"", final=True)
        if buffer:
            out.write(buffer)
            line_count += 1
            if not has_non_empty_line and buffer.strip():
                has_non_empty_line = True
    return line_count, has_non_empty_line


def save_one(
    name: str,
    base_short: str,
    *,
    content: str | None = None,
    uploaded_file=None,
) -> tuple[str | None, str | None]:
    """Save one wordlist with a unique short_name (retries on IntegrityError).

    Writes to a temp file first; on successful create, renames to the final path.
    On short_name collision only the temp file is removed, never an existing
    wordlist file. Returns (short_name, None) on success; (None, error_code) on failure.
    Error codes: 'write', 'encoding', 'empty', 'max_retries'.
    """
    base_short = _truncate_base_short(base_short)
    wordlists_dir = Path(RENGINE_WORDLISTS)
    for suffix in range(_MAX_WORDLIST_SHORT_NAME_RETRIES):
        candidate = _candidate_short_name(base_short, suffix)
        target = wordlists_dir / f"{candidate}.txt"
        fd, temp_path = tempfile.mkstemp(suffix=".txt", dir=wordlists_dir, prefix=".tmp_wordlist_")
        os.close(fd)
        temp_target = Path(temp_path)
        try:
            if content is not None:
                line_count = _write_content_to_file(temp_target, content)
            elif uploaded_file is not None:
                line_count, has_non_empty = _stream_upload_to_file(temp_target, uploaded_file)
                if not has_non_empty:
                    temp_target.unlink(missing_ok=True)
                    return (None, "empty")
            else:
                temp_target.unlink(missing_ok=True)
                return (None, "write")
        except UnicodeDecodeError:
            temp_target.unlink(missing_ok=True)
            return (None, "encoding")
        except OSError:
            temp_target.unlink(missing_ok=True)
            return (None, "write")

        try:
            Wordlist.objects.create(name=name, short_name=candidate, count=line_count)
            temp_target.replace(target)
            return (candidate, None)
        except IntegrityError as e:
            temp_target.unlink(missing_ok=True)
            if not _is_short_name_unique_violation(e):
                raise
    logger.warning(
        "Wordlist short_name uniqueness retries exhausted for base_short=%s, path=%s",
        base_short,
        wordlists_dir / f"{base_short}_*.txt",
    )
    return (None, "max_retries")
