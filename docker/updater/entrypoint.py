"""
reNgine-ng in-app updater sidecar.

Polls /shared/update_trigger for a JSON file written by the web container.
On detection, runs the update steps (git pull + docker compose), publishing
progress events to the Django Channels layer via channels_redis so the web
container can stream them over WebSocket.

Environment variables:
  REDIS_URL              Redis connection URL (default: redis://redis:6379)
  REPO_PATH              Absolute path to the repo root (default: /repo)
  COMPOSE_PROJECT_NAME   Docker Compose project name (default: rengine)
  RENGINE_UPDATE_SHARE_DIR  Directory for trigger / status files (default: /shared)
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

from channels_redis.core import RedisChannelLayer


# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------

REDIS_URL: str = os.environ.get("REDIS_URL", "redis://redis:6379")
REPO_PATH: Path = Path(os.environ.get("REPO_PATH", "/repo"))
COMPOSE_PROJECT_NAME: str = os.environ.get("COMPOSE_PROJECT_NAME", "rengine")
SHARE_DIR: Path = Path(os.environ.get("RENGINE_UPDATE_SHARE_DIR", "/shared"))

TRIGGER_FILE: Path = SHARE_DIR / "update_trigger"
STATUS_FILE: Path = SHARE_DIR / "update_status.json"

COMPOSE_FILE: str = str(REPO_PATH / "docker" / "docker-compose.yml")
COMPOSE_PROJECT_DIR: str = str(REPO_PATH / "docker")

WS_GROUP: str = "update-progress"

POLL_INTERVAL: float = 2.0

# Services to stop before updating (web + proxy only; db, redis, sidecar stay up)
SERVICES_TO_STOP: list[str] = ["web", "proxy"]
SERVICES_TO_UPDATE: list[str] = ["web", "proxy"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _compose_cmd(*args: str) -> list[str]:
    return [
        "docker",
        "compose",
        "--project-name",
        COMPOSE_PROJECT_NAME,
        "--file",
        COMPOSE_FILE,
        "--project-directory",
        COMPOSE_PROJECT_DIR,
        *args,
    ]


def _run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
    """Run a subprocess and return the result (stdout/stderr captured)."""
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)  # noqa: S603


async def _publish(channel_layer: RedisChannelLayer, payload: dict[str, Any]) -> None:
    """Send a progress event to all connected WebSocket clients."""
    try:
        await channel_layer.group_send(
            WS_GROUP,
            {"type": "update_progress", "payload": payload},
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[updater] channel_layer.group_send failed: {exc}", file=sys.stderr)


def _write_status(data: dict[str, Any]) -> None:
    SHARE_DIR.mkdir(parents=True, exist_ok=True)
    STATUS_FILE.write_text(json.dumps(data), encoding="utf-8")


# ---------------------------------------------------------------------------
# Update steps
# ---------------------------------------------------------------------------


STEPS = [
    "validate",
    "stopping_services",
    "pulling_code",
    "pulling_images",
    "starting_services",
]


async def run_update(install_type: str, channel_layer: RedisChannelLayer) -> None:
    """Execute the full update sequence and publish progress."""
    total = len(STEPS)
    started_at = datetime.now(tz=timezone.utc).isoformat()

    async def step(index: int, step_name: str, message: str) -> None:
        await _publish(
            channel_layer,
            {
                "step": step_name,
                "step_index": index,
                "total_steps": total,
                "message": message,
                "status": "running",
                "started_at": started_at,
            },
        )

    async def done(new_version: str) -> None:
        payload = {
            "step": "complete",
            "message": f"Update to {new_version} complete. Services are restarting.",
            "status": "complete",
            "new_version": new_version,
            "started_at": started_at,
        }
        await _publish(channel_layer, payload)
        _write_status(
            {
                "status": "complete",
                "new_version": new_version,
                "freshly_updated": True,
                "completed_at": datetime.now(tz=timezone.utc).isoformat(),
            }
        )

    async def fail(step_name: str, message: str) -> None:
        payload = {
            "step": step_name,
            "message": message,
            "status": "error",
            "started_at": started_at,
        }
        await _publish(channel_layer, payload)
        _write_status(
            {
                "status": "error",
                "step": step_name,
                "message": message,
                "failed_at": datetime.now(tz=timezone.utc).isoformat(),
            }
        )

    # ------------------------------------------------------------------
    # Step 1: validate (git fetch to confirm connectivity)
    # ------------------------------------------------------------------
    await step(0, "validate", "Fetching remote to validate connectivity...")
    result = _run(["git", "-C", str(REPO_PATH), "fetch", "origin"])
    if result.returncode != 0:
        await fail("validate", "git fetch failed: cannot reach remote repository.")
        return

    # ------------------------------------------------------------------
    # Step 2: stop services
    # ------------------------------------------------------------------
    await step(1, "stopping_services", f"Stopping services: {', '.join(SERVICES_TO_STOP)}...")
    result = _run(_compose_cmd("stop", *SERVICES_TO_STOP))
    if result.returncode != 0:
        await fail("stopping_services", "docker compose stop failed.")
        return

    # ------------------------------------------------------------------
    # Step 3: pull code
    # ------------------------------------------------------------------
    await step(2, "pulling_code", "Pulling latest code from repository...")
    result = _run(["git", "-C", str(REPO_PATH), "pull", "--ff-only"])
    if result.returncode != 0:
        await fail("pulling_code", "git pull --ff-only failed. There may be local changes.")
        # Attempt to restart services so the system is not left in a broken state
        _run(_compose_cmd("up", "-d", *SERVICES_TO_STOP))
        return

    # Read new version from version.txt
    version_file = REPO_PATH / "web" / "reNgine" / "version.txt"
    try:
        new_version = version_file.read_text(encoding="utf-8").strip()
    except OSError:
        new_version = "unknown"

    # ------------------------------------------------------------------
    # Step 4: pull or build images
    # ------------------------------------------------------------------
    if install_type == "source":
        await step(3, "building_images", "Building images from source (this may take a while)...")
        result = _run(_compose_cmd("build", *SERVICES_TO_UPDATE))
    else:
        await step(3, "pulling_images", "Pulling pre-built images from GitHub...")
        result = _run(_compose_cmd("pull", *SERVICES_TO_UPDATE))

    if result.returncode != 0:
        step_name = "building_images" if install_type == "source" else "pulling_images"
        await fail(step_name, f"docker compose {'build' if install_type == 'source' else 'pull'} failed.")
        _run(_compose_cmd("up", "-d", *SERVICES_TO_STOP))
        return

    # ------------------------------------------------------------------
    # Step 5: start services
    # ------------------------------------------------------------------
    await step(4, "starting_services", "Starting updated services...")
    result = _run(_compose_cmd("up", "-d"))
    if result.returncode != 0:
        await fail("starting_services", "docker compose up -d failed.")
        return

    await done(new_version)


# ---------------------------------------------------------------------------
# Main poll loop
# ---------------------------------------------------------------------------


async def main() -> None:
    print(f"[updater] Starting. Polling {TRIGGER_FILE} every {POLL_INTERVAL}s", flush=True)

    channel_layer = RedisChannelLayer(hosts=[REDIS_URL])

    while True:
        if TRIGGER_FILE.exists():
            try:
                raw = TRIGGER_FILE.read_text(encoding="utf-8")
                data = json.loads(raw)
                install_type = data.get("install_type", "prebuilt")
            except (OSError, json.JSONDecodeError):
                install_type = "prebuilt"

            # Delete trigger immediately to avoid re-processing
            try:
                TRIGGER_FILE.unlink(missing_ok=True)
            except OSError:
                pass

            print(f"[updater] Trigger detected. install_type={install_type!r}", flush=True)

            _write_status(
                {
                    "status": "running",
                    "install_type": install_type,
                    "started_at": datetime.now(tz=timezone.utc).isoformat(),
                }
            )

            try:
                await run_update(install_type, channel_layer)
            except Exception as exc:  # noqa: BLE001
                print(f"[updater] Unexpected error: {exc}", file=sys.stderr, flush=True)
                _write_status(
                    {
                        "status": "error",
                        "message": "Unexpected error during update.",
                        "failed_at": datetime.now(tz=timezone.utc).isoformat(),
                    }
                )

        await asyncio.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    asyncio.run(main())
