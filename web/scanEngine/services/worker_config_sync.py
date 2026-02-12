"""
Sync custom Secator configs (workflows, scans, profiles) to a remote worker.
Target path on host: deploy_path/templates/ (mounted in container as ~/.secator/templates).
Uses worker_ssh for SFTP.
"""

from typing import Any

import yaml

from reNgine.core.validators import sanitize_path_component
from reNgine.utilities.error import UserSafeError
from reNgine.utilities.logger import get_module_logger
from scanEngine.models import SecatorProfile, SecatorScan, SecatorTask, SecatorWorker, SecatorWorkflow
from scanEngine.services.worker_ssh import (
    get_ssh_client,
    sftp_ensure_dir,
    sftp_put_string,
    validate_deploy_path,
)


logger = get_module_logger(__name__)

SUBDIRS = ("workflows", "scans", "tasks", "profiles")


def _remote_templates_base(worker: SecatorWorker) -> str:
    """Base path on the worker host for templates (deploy_path/templates)."""
    return f"{worker.deploy_path.rstrip('/')}/templates"


def _collect_custom_workflows():
    """Return custom workflows with (sanitized_name, yaml_content)."""
    for w in SecatorWorkflow.objects.filter(workflow_type="custom", is_active=True):
        if not w.yaml_configuration:
            continue
        name = sanitize_path_component(w.name) or "unnamed"
        yield name, w.yaml_configuration


def _collect_custom_scans():
    """Return custom scans with (sanitized_name, yaml_content)."""
    for s in SecatorScan.objects.filter(scan_config_type="custom", is_active=True):
        if not s.yaml_configuration:
            continue
        name = sanitize_path_component(s.name) or "unnamed"
        yield name, s.yaml_configuration


def _collect_custom_tasks():
    """Return custom tasks (not builtin) with yaml_configuration as (sanitized_name, yaml_content)."""
    for t in SecatorTask.objects.filter(is_builtin=False, is_active=True):
        if not t.yaml_configuration:
            continue
        name = sanitize_path_component(t.name) or "unnamed"
        yield name, t.yaml_configuration


def _collect_custom_profiles():
    """Return custom profiles as (sanitized_name, yaml_content) in Secator profile format."""
    for p in SecatorProfile.objects.filter(profile_type="custom", is_active=True):
        name = sanitize_path_component(p.name) or "unnamed"
        opts = p._parse_opts()
        data = {
            "type": "profile",
            "name": p.name,
            "category": p.category,
            "description": p.description or "",
            "enforce": getattr(p, "enforce", False),
            "opts": opts,
        }
        yield name, yaml.dump(data, default_flow_style=False, allow_unicode=True)


def sync_all_custom_configs_to_worker(worker: SecatorWorker) -> None:
    """
    Sync all custom workflows, scans, tasks, and profiles to the worker.
    Raises UserSafeError on SSH/SFTP failure (safe message only).
    """
    validate_deploy_path(worker.deploy_path)
    base = _remote_templates_base(worker)
    client = get_ssh_client(worker)
    try:
        sftp = client.open_sftp()
        try:
            for sub in SUBDIRS:
                sftp_ensure_dir(sftp, f"{base}/{sub}")

            for name, content in _collect_custom_workflows():
                path = f"{base}/workflows/{name}.yaml"
                sftp_put_string(sftp, content, path)
                logger.debug("Synced workflow %s to worker %s", name, worker.name)

            for name, content in _collect_custom_scans():
                path = f"{base}/scans/{name}.yaml"
                sftp_put_string(sftp, content, path)
                logger.debug("Synced scan %s to worker %s", name, worker.name)

            for name, content in _collect_custom_tasks():
                path = f"{base}/tasks/{name}.yaml"
                sftp_put_string(sftp, content, path)
                logger.debug("Synced task %s to worker %s", name, worker.name)

            for name, content in _collect_custom_profiles():
                path = f"{base}/profiles/{name}.yaml"
                sftp_put_string(sftp, content, path)
                logger.debug("Synced profile %s to worker %s", name, worker.name)
        finally:
            sftp.close()
    except Exception as e:
        logger.warning("Config sync failed for worker %s: %s", worker.name, e)
        raise UserSafeError("Config sync failed. Check SSH and deploy path.") from e
    finally:
        client.close()


def sync_configs_for_run(
    worker: SecatorWorker,
    workflow_name: str | None = None,
    scan_type: str | None = None,
    task_names: list[str] | None = None,
    profile_names: list[str] | None = None,
) -> None:
    """
    Sync only the custom configs needed for a given run (workflow, scan, tasks, profiles).
    If a name is built-in, it is skipped. Pushes only the referenced custom configs.
    Raises UserSafeError on failure.
    """
    validate_deploy_path(worker.deploy_path)
    base = _remote_templates_base(worker)
    client = get_ssh_client(worker)
    try:
        sftp = client.open_sftp()
        try:
            for sub in SUBDIRS:
                sftp_ensure_dir(sftp, f"{base}/{sub}")
            _sync_workflow_for_run(sftp, base, workflow_name)
            _sync_scan_for_run(sftp, base, scan_type)
            _sync_tasks_for_run(sftp, base, task_names)
            _sync_profiles_for_run(sftp, base, profile_names)
        finally:
            sftp.close()
    except Exception as e:
        logger.warning("Config sync for run failed for worker %s: %s", worker.name, e)
        raise UserSafeError("Config sync failed. Check SSH and deploy path.") from e
    finally:
        client.close()


def _sync_workflow_for_run(sftp: Any, base: str, workflow_name: str | None) -> None:
    """Push a single custom workflow config if name is given and found."""
    if not workflow_name:
        return
    w = SecatorWorkflow.objects.filter(name=workflow_name, workflow_type="custom", is_active=True).first()
    if not w or not w.yaml_configuration:
        return
    name = sanitize_path_component(w.name) or "unnamed"
    sftp_put_string(sftp, w.yaml_configuration, f"{base}/workflows/{name}.yaml")


def _sync_scan_for_run(sftp: Any, base: str, scan_type: str | None) -> None:
    """Push a single custom scan config if type is given and found."""
    if not scan_type:
        return
    s = SecatorScan.objects.filter(name=scan_type, scan_config_type="custom", is_active=True).first()
    if not s or not s.yaml_configuration:
        return
    name = sanitize_path_component(s.name) or "unnamed"
    sftp_put_string(sftp, s.yaml_configuration, f"{base}/scans/{name}.yaml")


def _sync_tasks_for_run(sftp: Any, base: str, task_names: list[str] | None) -> None:
    """Push custom task configs for the given task names."""
    if not task_names:
        return
    for tname in task_names:
        t = SecatorTask.objects.filter(name=tname, is_builtin=False, is_active=True).first()
        if not t or not t.yaml_configuration:
            continue
        name = sanitize_path_component(t.name) or "unnamed"
        sftp_put_string(sftp, t.yaml_configuration, f"{base}/tasks/{name}.yaml")


def _sync_profiles_for_run(sftp: Any, base: str, profile_names: list[str] | None) -> None:
    """Push custom profile configs for the given profile names."""
    if not profile_names:
        return
    for pname in profile_names:
        p = SecatorProfile.objects.filter(name=pname, profile_type="custom", is_active=True).first()
        if not p:
            continue
        name = sanitize_path_component(p.name) or "unnamed"
        opts = p._parse_opts()
        data = {
            "type": "profile",
            "name": p.name,
            "category": p.category,
            "description": p.description or "",
            "enforce": getattr(p, "enforce", False),
            "opts": opts,
        }
        content = yaml.dump(data, default_flow_style=False, allow_unicode=True)
        sftp_put_string(sftp, content, f"{base}/profiles/{name}.yaml")
