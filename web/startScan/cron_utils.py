"""
Single entry point for run_scheduled_scans cron job management.

This module owns all logic for installing and detecting the run_scheduled_scans
cron line in the web container. To avoid divergence and hard-to-debug crontab
state, any code that needs to "ensure the cron job is present" must call
ensure_run_scheduled_scans_cron() here; do not duplicate crontab logic elsewhere.

Call sites (all delegate to ensure_run_scheduled_scans_cron()):
  1. Web entrypoint (docker/web/entrypoint.sh): after migrations, runs
     `manage.py ensure_scheduled_scans_cron` so existing schedules get the cron
     at container startup.
  2. Management command ensure_scheduled_scans_cron: thin CLI wrapper that
     calls ensure_run_scheduled_scans_cron(); used by the entrypoint and
     optionally by operators.
  3. Signal startScan.signals.ensure_cron_on_schedule_created: on ScanSchedule
     post_save (when created and enabled), calls ensure_run_scheduled_scans_cron()
     so the crontab is updated as soon as the first schedule is created from the UI.

The wrapper script (run_scheduled_scans.sh) and cron daemon are started in the
entrypoint; this module only ensures the crontab line is present.
"""

import os
import subprocess

from reNgine.utilities.logger import get_module_logger


logger = get_module_logger(__name__)

# Marker comment to detect our cron line (stable even if script path changes)
CRON_LINE_MARKER = "# run_scheduled_scans"


# Default script path (set by entrypoint in Docker: $HOME/run_scheduled_scans.sh)
def _get_cron_script_path() -> str:
    home = os.environ.get("HOME", "/home/rengine")
    return os.path.join(home, "run_scheduled_scans.sh")


def ensure_run_scheduled_scans_cron() -> bool:
    """
    Ensure the run_scheduled_scans cron job is in the current user's crontab.

    If the line is already present (detected by CRON_LINE_MARKER), do nothing.
    Otherwise append a line that runs the wrapper script every minute with the
    marker comment. No-op if crontab is not available (e.g. tests).

    Returns:
        True if crontab was updated or already contained the job, False if skipped (e.g. no cron).
    """
    script_path = _get_cron_script_path()
    cron_line = f"* * * * * {script_path}   {CRON_LINE_MARKER}"
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        current = (result.stdout or "") if result.returncode == 0 else ""
        if CRON_LINE_MARKER in current:
            logger.debug("run_scheduled_scans cron job already present")
            return True
        new_crontab = current.rstrip()
        if new_crontab and not new_crontab.endswith("\n"):
            new_crontab += "\n"
        new_crontab += cron_line + "\n"
        proc = subprocess.run(
            ["crontab", "-"],
            input=new_crontab,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode != 0:
            logger.warning("Failed to install run_scheduled_scans cron: %s", proc.stderr)
            return False
        logger.info("Installed run_scheduled_scans cron job in web container")
        return True
    except FileNotFoundError:
        logger.debug("crontab not available (e.g. not in web container), skipping")
        return False
    except subprocess.TimeoutExpired:
        logger.warning("crontab command timed out")
        return False
    except Exception as e:
        logger.warning("Could not ensure run_scheduled_scans cron: %s", e)
        return False
