"""
Centralized resolution of Secator worker config: API access type (tunnel vs classic)
and container script base (SECATOR_WORKER_CONTAINER_* vs deploy_path).
Used by remote_runner, worker_tunnel, and worker_deploy to avoid duplicating logic.
"""

from typing import Any

from django.conf import settings

from scanEngine.models import SecatorWorker


REMOTE_SCRIPTS_DIR = "scripts"


def is_tunnel_api_access(worker: Any) -> bool:
    """True if worker uses SSH tunnel for API access (tunnel mode)."""
    return getattr(worker, "api_access_type", None) == SecatorWorker.API_ACCESS_TUNNEL


def get_container_script_base(worker: SecatorWorker) -> tuple[str, str]:
    """
    Return (python_exe, base_cmd) for running scripts inside the worker container.
    base_cmd is either SECATOR_WORKER_CONTAINER_SCRIPT_BASE/scripts or deploy_path/scripts.
    """
    host_base = f"{worker.deploy_path.rstrip('/')}/{REMOTE_SCRIPTS_DIR}"
    container_script_base = (getattr(settings, "SECATOR_WORKER_CONTAINER_SCRIPT_BASE", "") or "").strip()
    base_cmd = f"{container_script_base.rstrip('/')}/{REMOTE_SCRIPTS_DIR}" if container_script_base else host_base
    python_exe = getattr(settings, "SECATOR_WORKER_CONTAINER_PYTHON", "python")
    return python_exe, base_cmd
