"""
SSH-based deployment of Secator workers to remote hosts.
Uses worker_ssh for SSH/SFTP and remote commands; tries docker compose (v2) then docker-compose (standalone).
Also provides build_worker_bundle_zip for manual deploy (download ZIP with compose, .env, templates).
"""

import io
from pathlib import Path
from typing import Callable, Optional, Tuple
import zipfile

from django.conf import settings
import paramiko

from reNgine.utilities.error import UserSafeError
from reNgine.utilities.logger import get_module_logger
from scanEngine.models import SecatorWorker
from scanEngine.services.worker_ssh import (
    REMOTE_COMPOSE_DOWN_TIMEOUT,
    REMOTE_COMPOSE_UP_TIMEOUT,
    detect_compose_cmd,
    get_ssh_client,
    normalize_remote_error,
    quote_for_shell,
    run_remote_command,
    validate_deploy_path,
)


PREFIX_WORKER_DEPLOY = "[WORKER_DEPLOY]"
logger = get_module_logger(__name__)

_COMPOSE_FILENAME = "docker-compose.worker.yml"
_ENV_FILENAME = ".env"
_ENTRYPOINT_FILENAME = "entrypoint.sh"


def _get_compose_path() -> Path:
    """Path to docker-compose.worker.yml (project root / docker / file)."""
    base = Path(settings.BASE_DIR)
    return base.parent / "docker" / _COMPOSE_FILENAME


def _get_entrypoint_path() -> Path:
    """Path to worker entrypoint.sh (docker/worker/entrypoint.sh)."""
    base = Path(settings.BASE_DIR)
    return base.parent / "docker" / "worker" / _ENTRYPOINT_FILENAME


def _get_python_ssl_suppress_dir() -> Path:
    """Path to worker python_ssl_suppress (sitecustomize.py for urllib3 warning suppression)."""
    base = Path(settings.BASE_DIR)
    return base.parent / "docker" / "worker" / "python_ssl_suppress"


_API_KEY_PLACEHOLDER = "your-generated-api-key-here"

_API_KEY_ERROR_MESSAGE = (
    "SECATOR_ADDONS_API_KEY is missing or still set to the placeholder. "
    "Configure a valid API key in settings before deploying or updating the worker."
)


def _validate_api_key_for_worker() -> None:
    """Raise UserSafeError if the API key is not set or is the placeholder."""
    api_key = (getattr(settings, "SECATOR_ADDONS_API_KEY", "") or "").strip()
    if not api_key or api_key == _API_KEY_PLACEHOLDER:
        raise UserSafeError(_API_KEY_ERROR_MESSAGE)


def get_worker_api_env_dict(worker: SecatorWorker) -> dict[str, str]:
    """Return Secator API env vars for this worker (for .env file or job injection)."""
    api_url = worker.get_api_base_url()
    api_key = getattr(settings, "SECATOR_ADDONS_API_KEY", "") or _API_KEY_PLACEHOLDER
    api_header_name = getattr(settings, "SECATOR_ADDONS_API_HEADER_NAME", "") or "Api-Key"
    force_ssl = getattr(settings, "SECATOR_ADDONS_API_FORCE_SSL", False)
    api_host = getattr(settings, "DOMAIN_NAME", "") or ""
    api_workspace_get_endpoint = getattr(settings, "SECATOR_ADDONS_API_WORKSPACE_GET_ENDPOINT", "") or ""
    return {
        "SECATOR_ADDONS_API_ENABLED": "true",
        "SECATOR_ADDONS_API_URL": api_url,
        "SECATOR_ADDONS_API_KEY": api_key,
        "SECATOR_ADDONS_API_HEADER_NAME": api_header_name,
        "SECATOR_ADDONS_API_FORCE_SSL": "true" if force_ssl else "false",
        "SECATOR_ADDONS_API_HOST": api_host,
        "SECATOR_ADDONS_API_WORKSPACE_GET_ENDPOINT": api_workspace_get_endpoint,
    }


def _build_worker_env_content(worker: SecatorWorker) -> str:
    """Build .env file content for the remote worker. API vars set; broker/backend left empty (CLI-only mode)."""
    _validate_api_key_for_worker()
    env_dict = get_worker_api_env_dict(worker)
    lines = [
        "# Broker/backend not used in CLI-only worker mode",
        *[f"{k}={v}" for k, v in env_dict.items()],
    ]
    if worker.container_name:
        lines.append(f"SECATOR_WORKER_CONTAINER_NAME={worker.container_name}")
    return "\n".join(lines) + "\n"


def _build_worker_env_content_for_bundle(worker: SecatorWorker) -> str:
    """Build .env content for the download bundle (no API key validation; placeholder allowed)."""
    env_dict = get_worker_api_env_dict(worker)
    lines = [
        "# Broker/backend not used in CLI-only worker mode",
        *[f"{k}={v}" for k, v in env_dict.items()],
    ]
    if worker.container_name:
        lines.append(f"SECATOR_WORKER_CONTAINER_NAME={worker.container_name}")
    return "\n".join(lines) + "\n"


def build_worker_bundle_zip(worker: SecatorWorker) -> bytes:
    """
    Build a ZIP archive for manual worker deployment (same content as deploy + sync config).
    Contains: docker-compose.worker.yml, .env, entrypoint.sh (if present), python_ssl_suppress/sitecustomize.py, templates/*, README.txt.
    Raises UserSafeError if compose file is missing (safe message only).
    """
    validate_deploy_path(worker.deploy_path)
    compose_path = _get_compose_path()
    if not compose_path.is_file():
        logger.log_line(
            PREFIX_WORKER_DEPLOY,
            "BUNDLE",
            "Compose file not found at %s" % (compose_path,),
            level="error",
        )
        raise UserSafeError("Worker compose file not found. Check server configuration.")

    from scanEngine.services.worker_config_sync import (
        _collect_custom_profiles,
        _collect_custom_scans,
        _collect_custom_tasks,
        _collect_custom_workflows,
    )

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(_COMPOSE_FILENAME, compose_path.read_bytes())
        zf.writestr(_ENV_FILENAME, _build_worker_env_content_for_bundle(worker).encode("utf-8"))
        entrypoint_path = _get_entrypoint_path()
        if entrypoint_path.is_file():
            zf.writestr(_ENTRYPOINT_FILENAME, entrypoint_path.read_bytes())
        ssl_suppress_dir = _get_python_ssl_suppress_dir()
        sitecustomize = ssl_suppress_dir / "sitecustomize.py"
        if sitecustomize.is_file():
            zf.writestr("python_ssl_suppress/sitecustomize.py", sitecustomize.read_bytes())
        for name, content in _collect_custom_workflows():
            zf.writestr(f"templates/workflows/{name}.yaml", content)
        for name, content in _collect_custom_scans():
            zf.writestr(f"templates/scans/{name}.yaml", content)
        for name, content in _collect_custom_tasks():
            zf.writestr(f"templates/tasks/{name}.yaml", content)
        for name, content in _collect_custom_profiles():
            zf.writestr(f"templates/profiles/{name}.yaml", content)
        readme = (
            "Manual Secator worker deployment bundle.\n\n"
            "1. Extract this archive on the target server (e.g. into /opt/secator-worker).\n"
            "2. If needed, edit .env and set SECATOR_ADDONS_API_KEY to your API key.\n"
            "3. Run: docker compose -f docker-compose.worker.yml up -d\n\n"
            "The python_ssl_suppress/ directory contains sitecustomize.py to suppress urllib3\n"
            "InsecureRequestWarning when the reNgine API uses a self-signed certificate.\n\n"
            "See WORKER_DEPLOYMENT.md for full documentation.\n"
        )
        zf.writestr("README.txt", readme.encode("utf-8"))
    return buffer.getvalue()


def deploy_worker(
    worker: SecatorWorker,
    progress_callback: Callable[[str, str], None],
) -> None:
    """
    Deploy the worker on the remote host via SSH: copy compose + .env, then start the container.
    progress_callback(step, message) is called at each logical step for UI streaming.
    Raises UserSafeError with a safe message on failure (do not leak credentials).
    """
    validate_deploy_path(worker.deploy_path)
    progress_callback("validating", "Deploy path validated.")

    compose_path = _get_compose_path()
    if not compose_path.is_file():
        logger.log_line(
            PREFIX_WORKER_DEPLOY,
            "DEPLOY",
            "Compose file not found at %s" % (compose_path,),
            level="error",
        )
        progress_callback("error", "Worker compose file not found. Check server configuration.")
        raise UserSafeError("Worker compose file not found. Check server configuration.")
    progress_callback("compose_check", "Compose file found.")

    client = None
    try:
        client = get_ssh_client(worker)
    except Exception as e:
        logger.log_line(
            PREFIX_WORKER_DEPLOY,
            "DEPLOY",
            "SSH connection failed for worker %s: %s" % (worker.name, e),
            level="warning",
        )
        progress_callback("error", "SSH connection failed. Check host, port, user and credentials.")
        raise UserSafeError("SSH connection failed. Check host, port, user and credentials.") from e
    progress_callback("ssh_connect", "SSH connection established.")

    try:
        exit_code, _, err = run_remote_command(client, "docker --version")
        if exit_code != 0:
            progress_callback("error", "Docker is not available on the remote host.")
            raise UserSafeError("Docker is not available on the remote host.")
        progress_callback("docker_check", "Docker is available.")

        compose_cmd = detect_compose_cmd(client)
        if not compose_cmd:
            progress_callback("error", "Neither 'docker compose' nor 'docker-compose' found on the remote host.")
            raise UserSafeError("Neither 'docker compose' nor 'docker-compose' found on the remote host.")
        progress_callback("compose_cmd", f"Using {compose_cmd}.")

        deploy_path = worker.deploy_path.rstrip("/")
        quoted_dp = quote_for_shell(deploy_path)
        sftp = client.open_sftp()
        try:
            try:
                sftp.stat(deploy_path)
            except FileNotFoundError:
                run_remote_command(client, f"mkdir -p {quoted_dp}")
            for sub in ("workflows", "scans", "tasks", "profiles"):
                run_remote_command(
                    client,
                    f"mkdir -p {quote_for_shell(f'{deploy_path}/templates/{sub}')}",
                )
            run_remote_command(client, f"mkdir -p {quote_for_shell(f'{deploy_path}/scripts')}")
            run_remote_command(client, f"mkdir -p {quote_for_shell(f'{deploy_path}/python_ssl_suppress')}")
            progress_callback("mkdir", "Deploy path and templates/scripts created.")

            with open(compose_path, "rb") as f:
                compose_content = f.read()
            remote_compose = f"{deploy_path}/{_COMPOSE_FILENAME}"
            with sftp.file(remote_compose, "wb") as rf:
                rf.write(compose_content)
            progress_callback("copy_compose", "docker-compose.worker.yml copied.")

            entrypoint_path = _get_entrypoint_path()
            if entrypoint_path.is_file():
                remote_entrypoint = f"{deploy_path}/{_ENTRYPOINT_FILENAME}"
                with open(entrypoint_path, "rb") as f:
                    entrypoint_content = f.read()
                with sftp.file(remote_entrypoint, "wb") as rf:
                    rf.write(entrypoint_content)
                run_remote_command(client, f"chmod +x {quote_for_shell(remote_entrypoint)}")
                progress_callback("copy_entrypoint", "entrypoint.sh copied.")
            else:
                logger.log_line(
                    PREFIX_WORKER_DEPLOY,
                    "DEPLOY",
                    "Worker entrypoint not found at %s" % (entrypoint_path,),
                    level="warning",
                )

            ssl_suppress_dir = _get_python_ssl_suppress_dir()
            sitecustomize_src = ssl_suppress_dir / "sitecustomize.py"
            if sitecustomize_src.is_file():
                remote_sitecustomize = f"{deploy_path}/python_ssl_suppress/sitecustomize.py"
                with open(sitecustomize_src, "rb") as f:
                    with sftp.file(remote_sitecustomize, "wb") as rf:
                        rf.write(f.read())
                progress_callback("copy_ssl_suppress", "python_ssl_suppress copied.")

            progress_callback("copy_env", "Preparing .env...")
            env_content = _build_worker_env_content(worker)
            remote_env = f"{deploy_path}/{_ENV_FILENAME}"
            with sftp.file(remote_env, "wb") as rf:
                rf.write(env_content.encode("utf-8"))
            progress_callback("copy_env", ".env copied.")
        finally:
            sftp.close()

        progress_callback("docker_up", "Starting container...")
        up_cmd = f"cd {quoted_dp} && {compose_cmd} -f {_COMPOSE_FILENAME} up -d"
        exit_code, out, err = run_remote_command(client, up_cmd, timeout=REMOTE_COMPOSE_UP_TIMEOUT)
        if exit_code != 0:
            err_msg = normalize_remote_error(
                exit_code, out, err, "Failed to start worker container on the remote host."
            )
            logger.log_line(
                PREFIX_WORKER_DEPLOY,
                "DEPLOY",
                "Worker up command failed: %s" % (err_msg,),
                level="warning",
            )
            progress_callback(
                "error",
                f"Failed to start worker container on the remote host.\n\nDetails:\n{err_msg}",
            )
            raise UserSafeError(err_msg)
        progress_callback("done", "Worker deployed successfully.")
    except (UserSafeError, RuntimeError):
        raise
    except paramiko.SSHException as e:
        logger.log_line(
            PREFIX_WORKER_DEPLOY,
            "DEPLOY",
            "SSH error during deploy: %s" % (e,),
            level="warning",
        )
        progress_callback("error", "SSH error during deployment.")
        raise UserSafeError("SSH error during deployment.") from e
    finally:
        if client:
            client.close()


def restart_worker_container(worker: SecatorWorker) -> Tuple[bool, str]:
    """
    Copy docker-compose (and entrypoint if present) to the remote host, then restart the container.
    Returns (success, log). Log contains copy steps and command output for display in the UI.
    """
    validate_deploy_path(worker.deploy_path)
    compose_path = _get_compose_path()
    if not compose_path.is_file():
        return False, "Worker compose file not found. Check server configuration."

    client = None
    try:
        client = get_ssh_client(worker)
    except Exception as e:
        logger.log_line(
            PREFIX_WORKER_DEPLOY,
            "RESTART",
            "SSH failed for worker %s during restart: %s" % (worker.name, e),
            level="warning",
        )
        return False, "SSH connection failed"

    deploy_path = worker.deploy_path.rstrip("/")
    quoted_dp = quote_for_shell(deploy_path)
    log_parts: list[str] = []
    try:
        sftp = client.open_sftp()
        try:
            with open(compose_path, "rb") as f:
                compose_content = f.read()
            remote_compose = f"{deploy_path}/{_COMPOSE_FILENAME}"
            with sftp.file(remote_compose, "wb") as rf:
                rf.write(compose_content)
            log_parts.append(f"Copied {_COMPOSE_FILENAME} to remote.")
            entrypoint_path = _get_entrypoint_path()
            if entrypoint_path.is_file():
                remote_entrypoint = f"{deploy_path}/{_ENTRYPOINT_FILENAME}"
                with open(entrypoint_path, "rb") as f:
                    entrypoint_content = f.read()
                with sftp.file(remote_entrypoint, "wb") as rf:
                    rf.write(entrypoint_content)
                run_remote_command(client, f"chmod +x {quote_for_shell(remote_entrypoint)}")
                log_parts.append(f"Copied {_ENTRYPOINT_FILENAME} to remote.")
            sitecustomize_src = _get_python_ssl_suppress_dir() / "sitecustomize.py"
            if sitecustomize_src.is_file():
                run_remote_command(client, f"mkdir -p {quote_for_shell(f'{deploy_path}/python_ssl_suppress')}")
                remote_sitecustomize = f"{deploy_path}/python_ssl_suppress/sitecustomize.py"
                with open(sitecustomize_src, "rb") as f:
                    with sftp.file(remote_sitecustomize, "wb") as rf:
                        rf.write(f.read())
                log_parts.append("Copied python_ssl_suppress to remote.")
        finally:
            sftp.close()

        compose_cmd = detect_compose_cmd(client)
        if not compose_cmd:
            return False, "\n".join(log_parts) + "\n\nDocker Compose not found on the remote host."
        down_cmd = f"cd {quoted_dp} && {compose_cmd} -f {_COMPOSE_FILENAME} down"
        log_parts.extend(("", f"$ {down_cmd}", ""))
        exit_down, out_down, err_down = run_remote_command(client, down_cmd, timeout=REMOTE_COMPOSE_DOWN_TIMEOUT)
        if out_down:
            log_parts.append(out_down)
        if err_down:
            log_parts.append(err_down)
        up_cmd = f"cd {quoted_dp} && {compose_cmd} -f {_COMPOSE_FILENAME} up -d"
        log_parts.extend(("", f"$ {up_cmd}", ""))
        exit_code, out, err = run_remote_command(client, up_cmd, timeout=REMOTE_COMPOSE_UP_TIMEOUT)
        if out:
            log_parts.append(out)
        if err:
            log_parts.append(err)
        if exit_code != 0:
            err_msg = normalize_remote_error(exit_code, out, err, "Worker up failed.")
            logger.log_line(
                PREFIX_WORKER_DEPLOY,
                "RESTART",
                "Worker up failed for %s: %s" % (worker.name, err_msg),
                level="warning",
            )
            log_parts.extend(("", err_msg))
        log_text = "\n".join(log_parts).strip() or "(no output)"
        return (False, log_text) if exit_code != 0 else (True, log_text)
    except paramiko.SSHException as e:
        logger.log_line(
            PREFIX_WORKER_DEPLOY,
            "RESTART",
            "SSH error during restart for worker %s: %s" % (worker.name, e),
            level="warning",
        )
        log_parts.append("SSH error during restart.")
        return False, "\n".join(log_parts).strip() or "SSH error during restart."
    finally:
        client.close()


def push_env_and_restart_worker(worker: SecatorWorker) -> tuple[bool, Optional[str]]:
    """
    Write the worker .env to the remote host and restart the container.
    Returns (success, error_message). Use when API access settings changed.
    """
    validate_deploy_path(worker.deploy_path)
    client = None
    try:
        client = get_ssh_client(worker)
    except Exception as e:
        logger.log_line(
            PREFIX_WORKER_DEPLOY,
            "ENV_PUSH",
            "SSH failed for worker %s during env push: %s" % (worker.name, e),
            level="warning",
        )
        return False, "SSH connection failed"

    deploy_path = worker.deploy_path.rstrip("/")
    quoted_dp = quote_for_shell(deploy_path)
    remote_env = f"{deploy_path}/{_ENV_FILENAME}"
    try:
        return _write_env_and_restart_container(worker, client, remote_env, deploy_path, quoted_dp)
    except paramiko.SSHException as e:
        logger.log_line(
            PREFIX_WORKER_DEPLOY,
            "ENV_PUSH",
            "SSH error during env push for worker %s: %s" % (worker.name, e),
            level="warning",
        )
        return False, "SSH error during update"
    finally:
        client.close()


def _write_env_and_restart_container(worker, client, remote_env, deploy_path, quoted_dp):
    """Write worker .env to remote path, then run compose down/up; returns (success, error_message)."""
    env_content = _build_worker_env_content(worker)
    sftp = client.open_sftp()
    try:
        with sftp.file(remote_env, "wb") as rf:
            rf.write(env_content.encode("utf-8"))
    finally:
        sftp.close()

    compose_cmd = detect_compose_cmd(client)
    if not compose_cmd:
        return False, "Docker Compose not found on the remote host"
    run_remote_command(
        client,
        f"cd {quoted_dp} && {compose_cmd} -f {_COMPOSE_FILENAME} down",
        timeout=REMOTE_COMPOSE_DOWN_TIMEOUT,
    )
    exit_code, out, err = run_remote_command(
        client,
        f"cd {quoted_dp} && {compose_cmd} -f {_COMPOSE_FILENAME} up -d",
        timeout=REMOTE_COMPOSE_UP_TIMEOUT,
    )
    if exit_code != 0:
        err_msg = normalize_remote_error(exit_code, out, err, "Failed to start worker container on the remote host.")
        logger.log_line(
            PREFIX_WORKER_DEPLOY,
            "ENV_PUSH",
            "Worker up failed for %s: %s" % (worker.name, err_msg),
            level="warning",
        )
        return False, err_msg
    return True, None


def refresh_worker_status(
    worker: SecatorWorker,
    progress_callback: Callable[[str, str], None],
) -> dict:
    """
    Check worker status via SSH: container running, then API reachable from inside container (wget).
    progress_callback(step, message) is called at each step for UI streaming.
    Returns dict with ssh_ok, container_running, api_reachable, last_error.
    """
    from scanEngine.services.worker_ssh import (
        check_api_reachable_from_container,
        get_container_name,
    )

    result = {
        "ssh_ok": False,
        "container_running": False,
        "api_reachable": False,
        "last_error": None,
    }
    try:
        client = get_ssh_client(worker)
    except Exception as e:
        logger.log_line(
            PREFIX_WORKER_DEPLOY,
            "DEPLOY",
            "SSH failed for worker %s: %s" % (worker.name, e),
            level="debug",
        )
        result["last_error"] = "SSH connection failed"
        progress_callback("error", "SSH connection failed.")
        return result

    result["ssh_ok"] = True
    progress_callback("ssh_connect", "SSH connection established.")
    try:
        container_name = get_container_name(worker)
        exit_code, out, _ = run_remote_command(
            client,
            f"docker ps -q -f name={quote_for_shell(container_name)} 2>/dev/null",
        )
        result["container_running"] = exit_code == 0 and bool(out.strip())
        if result["container_running"]:
            progress_callback("container_check", "Container is running.")
        else:
            progress_callback("container_check", "Container is not running.")
            client.close()
            return result

        api_base = worker.get_api_base_url()
        health_url = f"{api_base.rstrip('/')}/health/" if api_base else ""
        if health_url:
            progress_callback("api_check", "Checking API reachability...")
            reachable, err = check_api_reachable_from_container(client, worker, health_url, timeout=15)
            result["api_reachable"] = reachable
            if not reachable and err:
                result["last_error"] = result["last_error"] or err
            if reachable:
                progress_callback("api_check", "API reachable.")
            else:
                progress_callback("error", "API not reachable: " + (err or "unknown"))
        else:
            progress_callback("api_check", "No API URL configured; skipping.")
    except Exception as e:
        logger.log_line(
            PREFIX_WORKER_DEPLOY,
            "STATUS",
            "Status check failed for worker %s: %s" % (worker.name, e),
            level="debug",
        )
        result["last_error"] = result["last_error"] or "Could not check container status"
        progress_callback("error", "Could not check container status.")
    finally:
        client.close()
    return result


def teardown_worker_remote(worker: SecatorWorker) -> tuple[bool, Optional[str]]:
    """
    On the remote host: stop and remove the container, then remove deploy path files.
    Returns (success, error_message). Does not delete the worker from DB.
    """
    validate_deploy_path(worker.deploy_path)
    client = None
    try:
        client = get_ssh_client(worker)
    except Exception as e:
        logger.log_line(
            PREFIX_WORKER_DEPLOY,
            "TEARDOWN",
            "SSH failed for worker %s during teardown: %s" % (worker.name, e),
            level="warning",
        )
        return False, "SSH connection failed"

    deploy_path = worker.deploy_path.rstrip("/")
    quoted_dp = quote_for_shell(deploy_path)
    compose_cmd = detect_compose_cmd(client)
    try:
        if compose_cmd:
            down_cmd = f"cd {quoted_dp} && {compose_cmd} -f {_COMPOSE_FILENAME} down 2>/dev/null; true"
            run_remote_command(client, down_cmd, timeout=60)
        rm_cmd = (
            f"rm -f {quote_for_shell(f'{deploy_path}/{_COMPOSE_FILENAME}')} "
            f"{quote_for_shell(f'{deploy_path}/{_ENV_FILENAME}')}"
        )
        run_remote_command(client, rm_cmd)
        return True, None
    except Exception as e:
        logger.log_line(
            PREFIX_WORKER_DEPLOY,
            "TEARDOWN",
            "Teardown failed for worker %s: %s" % (worker.name, e),
            level="warning",
        )
        return False, "Teardown failed on the remote host."
    finally:
        client.close()
