"""
Helpers for the in-app update trigger and status — Leaf layer.

The trigger file is written by the web container and consumed by the updater
sidecar. The status file is written by the sidecar and read by the web
container.

Both files live inside RENGINE_UPDATE_SHARE_DIR (default: /shared), which is
a Docker volume shared between the ``web`` and ``updater`` services.

Security: every path is validated against the base directory using
``is_safe_path`` before any file I/O (Rule 1.2 / Rule 1.4).
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any

from reNgine.core.path import is_safe_path
from reNgine.definitions import UPDATE_STATUS_FILENAME, UPDATE_TRIGGER_FILENAME


def _share_dir() -> Path:
    share = os.environ.get("RENGINE_UPDATE_SHARE_DIR", "/shared")
    return Path(share)


def _validated_path(filename: str) -> Path:
    """Return the absolute path inside the share dir after a safety check."""
    base = _share_dir()
    target = (base / filename).resolve()
    if not is_safe_path(str(base.resolve()), str(target)):
        raise ValueError("Unsafe share path component: %r" % (filename,))
    return target


def write_update_trigger(install_type: str) -> None:
    """Write the trigger file so the updater sidecar picks up the request."""
    from reNgine.definitions import UPDATE_INSTALL_TYPES

    if install_type not in UPDATE_INSTALL_TYPES:
        raise ValueError("Invalid install_type: %r" % (install_type,))
    path = _validated_path(UPDATE_TRIGGER_FILENAME)
    path.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {
        "install_type": install_type,
        "requested_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    path.write_text(json.dumps(data), encoding="utf-8")


def read_update_status() -> dict[str, Any]:
    """Return the status dict written by the updater sidecar, or {} if absent."""
    try:
        path = _validated_path(UPDATE_STATUS_FILENAME)
    except ValueError:
        return {}
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def is_update_running() -> bool:
    """Return True if the trigger file exists (sidecar has not yet consumed it)."""
    try:
        path = _validated_path(UPDATE_TRIGGER_FILENAME)
        return path.exists()
    except ValueError:
        return False


def clear_freshly_updated_flag() -> None:
    """Remove the freshly_updated key from the status file after the UI has acknowledged it."""
    try:
        path = _validated_path(UPDATE_STATUS_FILENAME)
    except ValueError:
        return
    if not path.exists():
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return
    data.pop("freshly_updated", None)
    path.write_text(json.dumps(data), encoding="utf-8")
