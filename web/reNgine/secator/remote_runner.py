"""
Orchestrate running a Secator scan on a remote worker via SSH.
Syncs configs, pushes job JSON and runner script, runs Python in the worker container.
"""

from contextlib import suppress
import json
from pathlib import Path
import time

from reNgine.utilities.logger import get_module_logger
from scanEngine.models import SecatorWorker
from scanEngine.services.worker_config import (
    REMOTE_SCRIPTS_DIR,
    get_container_script_base,
    is_tunnel_api_access,
)
from scanEngine.services.worker_config_sync import sync_configs_for_run
from scanEngine.services.worker_ssh import (
    get_ssh_client,
    normalize_remote_error,
    quote_for_shell,
    run_in_container,
    sftp_ensure_dir,
    sftp_put_string,
    validate_deploy_path,
)
from scanEngine.services.worker_tunnel import start_worker_tunnel, stop_worker_tunnel


logger = get_module_logger(__name__)

RUNNER_SCRIPT_NAME = "run_secator_job.py"
REVOKE_TIMEOUT_SECONDS = 30


def _get_runner_script_content() -> str:
    """Return the content of the worker-side runner script (no reNgine imports)."""
    script_path = Path(__file__).parent / "worker_run_job.py"
    return script_path.read_text(encoding="utf-8")


def _profile_names_from_config(secator_config: dict) -> list[str]:
    """Extract a flat list of profile names from secator_config (e.g. profiles dict or list)."""
    profiles = secator_config.get("profiles")
    if not profiles:
        return []
    if isinstance(profiles, list):
        return [str(p) for p in profiles if p]
    if isinstance(profiles, dict):
        return [str(v) for v in profiles.values() if v]
    return []


def revoke_task_on_remote_worker(
    worker: SecatorWorker,
    celery_id: str,
    task_name: str | None = None,
) -> bool:
    """
    Revoke a Celery task on the remote worker by running the standalone script in revoke mode.
    The script calls secator.celery.revoke_task(celery_id) inside the container (same as local).

    Args:
        worker: The remote Secator worker.
        celery_id: Celery task ID to revoke.
        task_name: Optional task name for logging (not passed to script).

    Returns:
        True if revoke command succeeded (exit 0), False otherwise.
    """
    validate_deploy_path(worker.deploy_path)
    tunnel_handle = None
    if is_tunnel_api_access(worker):
        try:
            tunnel_handle = start_worker_tunnel(worker)
            time.sleep(1.5)
        except ValueError as e:
            logger.warning("Tunnel not started for worker %s: %s", worker.name, e)
            return False
    try:
        python_exe, base_cmd = get_container_script_base(worker)
        script_path = f"{base_cmd}/{RUNNER_SCRIPT_NAME}"
        cmd = f"{quote_for_shell(python_exe)} {quote_for_shell(script_path)} revoke {quote_for_shell(celery_id)}"
        client = get_ssh_client(worker)
        try:
            exit_code, out, err = run_in_container(client, worker, cmd, timeout=REVOKE_TIMEOUT_SECONDS)
            if exit_code != 0:
                logger.warning(
                    "Remote revoke failed for worker %s task %s: exit %s, stderr: %s",
                    worker.name,
                    celery_id,
                    exit_code,
                    err,
                )
                return False
            if task_name:
                logger.debug("Revoked task %s (%s) on worker %s", celery_id, task_name, worker.name)
            return True
        finally:
            client.close()
    except Exception as e:
        logger.warning("revoke_task_on_remote_worker failed for worker %s: %s", worker.name, e)
        return False
    finally:
        if tunnel_handle is not None:
            stop_worker_tunnel(tunnel_handle)


def run_scan_on_worker(
    worker: SecatorWorker,
    scan_history_id: int,
    domain_id: int,
    workspace_name: str,
    execution_mode: str,
    targets: list[str],
    workflow_name: str | None = None,
    scan_type: str | None = None,
    task_names: list[str] | None = None,
    secator_config: dict | None = None,
    timeout_seconds: int = 7200,
    subscan_id: int | None = None,
) -> None:
    """
    Run a Secator scan on the remote worker: sync configs, push job and script, exec in container.
    Raises RuntimeError on SSH/sync/exec failure (safe message only).
    """
    secator_config = secator_config or {}
    task_names = task_names or []
    validate_deploy_path(worker.deploy_path)
    tunnel_handle = _start_tunnel_if_needed(worker)
    try:
        profile_names = _profile_names_from_config(secator_config)
        sync_configs_for_run(
            worker,
            workflow_name=workflow_name,
            scan_type=scan_type,
            task_names=task_names if execution_mode == "tasks" else None,
            profile_names=profile_names,
        )
        job = _build_job_payload(
            worker,
            scan_history_id,
            domain_id,
            workspace_name,
            execution_mode,
            targets,
            workflow_name,
            scan_type,
            task_names,
            secator_config,
            profile_names,
            subscan_id,
        )
        client = get_ssh_client(worker)
        try:
            _upload_and_execute_on_worker(client, worker, job, scan_history_id, timeout_seconds)
        except RuntimeError:
            raise
        except Exception as e:
            logger.warning("run_scan_on_worker failed for worker %s: %s", worker.name, e)
            raise RuntimeError("Failed to run scan on worker. Check SSH and container.") from e
        finally:
            client.close()
    finally:
        if tunnel_handle is not None:
            stop_worker_tunnel(tunnel_handle)


def _start_tunnel_if_needed(worker: SecatorWorker):
    """Start SSH tunnel when worker uses tunnel API access; return handle or None."""
    if not is_tunnel_api_access(worker):
        return None
    try:
        handle = start_worker_tunnel(worker)
        time.sleep(1.5)
        return handle
    except ValueError as e:
        logger.warning("Tunnel not started for worker %s: %s", worker.name, e)
        raise RuntimeError("Could not start SSH tunnel for worker. Check tunnel configuration.") from e


def _build_job_payload(
    worker: SecatorWorker,
    scan_history_id: int,
    domain_id: int,
    workspace_name: str,
    execution_mode: str,
    targets: list[str],
    workflow_name: str | None,
    scan_type: str | None,
    task_names: list[str],
    secator_config: dict,
    profile_names: list[str],
    subscan_id: int | None,
) -> dict:
    """Build the job dict for the remote runner script."""
    context: dict = {
        "scan_history_id": scan_history_id,
        "domain_id": domain_id,
        "workspace_name": workspace_name,
        "workspace_id": workspace_name,
        "worker_id": worker.id,
    }
    if subscan_id is not None:
        context["subscan_id"] = subscan_id
        with suppress(Exception):
            from startScan.models import SubScan

            subscan = SubScan.objects.filter(id=subscan_id).select_related("subdomain").first()
            if subscan and subscan.subdomain_id:
                context["subdomain_id"] = subscan.subdomain_id
    job = {
        "execution_mode": execution_mode,
        "targets": targets,
        "context": context,
        "run_opts": {
            "proxy": secator_config.get("proxy"),
            "delay": secator_config.get("delay", 0),
            "profiles": profile_names,
        },
    }
    if execution_mode == "workflow":
        job["workflow_name"] = workflow_name
    elif execution_mode == "scan":
        job["scan_type"] = scan_type
    elif execution_mode == "tasks":
        job["task_names"] = task_names
    return job


def _upload_and_execute_on_worker(
    client,
    worker: SecatorWorker,
    job: dict,
    scan_history_id: int,
    timeout_seconds: int,
) -> None:
    """Upload script and job JSON to worker host and run in container; raise RuntimeError on failure."""
    base_upload = f"{worker.deploy_path.rstrip('/')}/{REMOTE_SCRIPTS_DIR}"
    job_filename = f"job_{scan_history_id}.json"
    job_json = json.dumps(job, indent=2)
    remote_job_path = f"{base_upload}/{job_filename}"
    remote_script_path = f"{base_upload}/{RUNNER_SCRIPT_NAME}"
    script_content = _get_runner_script_content()
    python_exe, base_cmd = get_container_script_base(worker)

    sftp = client.open_sftp()
    try:
        sftp_ensure_dir(sftp, base_upload)
        sftp_put_string(sftp, script_content, remote_script_path)
        sftp_put_string(sftp, job_json, remote_job_path)
    finally:
        sftp.close()

    script_path = f"{base_cmd}/{RUNNER_SCRIPT_NAME}"
    job_path = f"{base_cmd}/{job_filename}"
    cmd = f"{quote_for_shell(python_exe)} {quote_for_shell(script_path)} {quote_for_shell(job_path)}"
    exit_code, out, err = run_in_container(client, worker, cmd, timeout=timeout_seconds)
    if exit_code != 0:
        err_msg = normalize_remote_error(exit_code, out, err, "Remote scan execution failed. Check worker logs.")
        logger.warning(
            "Remote worker run failed for scan %s: %s",
            scan_history_id,
            err_msg,
        )
        raise RuntimeError(err_msg) from None
