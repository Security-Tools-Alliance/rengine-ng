"""
Shared SSH/SFTP and remote command execution for Secator workers.
Used by worker_deploy, worker_config_sync, API verification, and remote_runner.
Supports running commands on the host and inside the worker container (docker exec).
"""

from pathlib import Path
import shlex
from typing import Any, Optional

from django.conf import settings

from reNgine.utilities.error import UserSafeError
from reNgine.utilities.logger import get_module_logger


PREFIX_WORKER_SSH = "[WORKER_SSH]"
logger = get_module_logger(__name__)

# Shared timeouts for remote commands (seconds) to avoid drift between call sites
REMOTE_CMD_TIMEOUT = 30
REMOTE_COMPOSE_UP_TIMEOUT = 120
REMOTE_COMPOSE_DOWN_TIMEOUT = 60


def default_ssh_key_path() -> str:
    """Path to the default SSH private key (generated at container startup)."""
    return str(getattr(settings, "RENGINE_SSH_DEFAULT_KEY_PATH", "") or (Path.home() / ".ssh" / "id_ed25519"))


def get_public_key_content() -> Optional[str]:
    """
    Read the default SSH public key content for display or install on worker hosts.
    Returns None if the .pub file does not exist.
    """
    pub_path = Path(f"{default_ssh_key_path()}.pub")
    if not pub_path.is_file():
        return None
    try:
        return pub_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


# Shell metacharacters that must not appear in deploy_path (path is used in shell commands).
_DEPLOY_PATH_FORBIDDEN_CHARS = set(";&|`$()\n\r")


def validate_deploy_path(path: str) -> None:
    """
    Reject deploy_path that could be used for path traversal, injection, or shell injection.
    Path must be absolute, must not be the filesystem root (/), and must not contain
    shell metacharacters (; & | ` $ ( ) newline) since the path is interpolated into
    shell commands (e.g. cd, mkdir, rm). Single-segment roots like /opt or /srv are allowed.
    """
    if not path or "\0" in path or ".." in path:
        raise ValueError("Invalid deploy path.")
    if not path.startswith("/"):
        raise ValueError("Invalid deploy path.")
    if any(c in _DEPLOY_PATH_FORBIDDEN_CHARS for c in path):
        raise ValueError("Invalid deploy path.")
    segments = [s for s in path.strip("/").split("/") if s]
    if not segments:
        raise ValueError("Invalid deploy path.")


def get_ssh_client(worker: Any):
    """
    Create and connect paramiko SSH client for the worker. Caller must close it.
    worker must have: ssh_host, ssh_port, ssh_user, ssh_auth_type, ssh_key_path, ssh_password_encrypted.
    """
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    auth_key = getattr(worker, "AUTH_KEY", "key")
    kwargs: dict[str, Any] = {
        "hostname": worker.ssh_host,
        "port": worker.ssh_port,
        "username": worker.ssh_user,
    }
    if worker.ssh_auth_type == auth_key:
        key_path = (worker.ssh_key_path or "").strip() or default_ssh_key_path()
        kwargs["key_filename"] = key_path
    elif worker.ssh_auth_type == getattr(worker, "AUTH_PASSWORD", "password") and worker.ssh_password_encrypted:
        kwargs["password"] = worker.ssh_password_encrypted
    client.connect(**kwargs)
    return client


def run_remote_command(
    client: Any,
    command: str,
    timeout: int = REMOTE_CMD_TIMEOUT,
) -> tuple[int, str, str]:
    """Run a command over SSH on the host; returns (exit_code, stdout, stderr)."""
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return exit_code, out, err


def get_container_name(worker: Any) -> str:
    """Default container name when worker.container_name is not set."""
    return (worker.container_name or "secator-worker").strip() or "secator-worker"


def quote_for_shell(s: str) -> str:
    """
    Quote a string for safe interpolation into a remote shell command.
    Use for any user-controlled or path-derived value (deploy_path, container_name, etc.).
    """
    return shlex.quote(s)


def run_in_container(
    client: Any,
    worker: Any,
    command: str,
    timeout: int = REMOTE_CMD_TIMEOUT,
) -> tuple[int, str, str]:
    """
    Run a command inside the worker's Docker container via SSH.
    Executes: docker exec <container_name> <command> on the remote host.
    Returns (exit_code, stdout, stderr).
    """
    container = get_container_name(worker)
    full_cmd = f"docker exec {quote_for_shell(container)} {command}"
    return run_remote_command(client, full_cmd, timeout=timeout)


def _sh_quote(s: str) -> str:
    """Escape string for safe use inside single-quoted shell argument."""
    return "'" + s.replace("'", "'\"'\"'") + "'"


def normalize_remote_error(
    exit_code: int,
    stdout: str,
    stderr: str,
    default_message: str = "Remote command failed.",
) -> str:
    """
    Build a single user-safe error message from remote command output.
    Prefers stderr, then stdout, then default_message; appends exit code when non-zero.
    """
    if out := (stderr or "").strip() or (stdout or "").strip():
        return f"{out}" if exit_code == 0 else f"{out} (exit code {exit_code})"
    return f"Exit code {exit_code}" if exit_code != 0 else default_message


def check_api_reachable_from_container(
    client: Any,
    worker: Any,
    health_url: str,
    timeout: int = 15,
) -> tuple[bool, Optional[str]]:
    """
    From the remote host, run curl inside the container to test health_url.
    Uses -k for self-signed certs, and sends Host and Authorization headers so
    the certificate and Django (e.g. CSRF) accept the request.
    Returns (reachable, error_message). reachable is True when exit code is 0.
    """
    domain_name = getattr(settings, "DOMAIN_NAME", "") or "localhost"
    api_key = getattr(settings, "SECATOR_ADDONS_API_KEY", "") or ""
    api_header_name = getattr(settings, "SECATOR_ADDONS_API_HEADER_NAME", "") or "Api-Key"
    host_header = f"Host: {domain_name}"
    auth_header = f"Authorization: {api_header_name} {api_key}"
    curl_cmd = (
        f"curl -k -f -s -o /dev/null -H {_sh_quote(host_header)} -H {_sh_quote(auth_header)} {_sh_quote(health_url)}"
    )
    exit_code, out, err = run_in_container(client, worker, curl_cmd, timeout=timeout)
    if exit_code == 0:
        return True, None
    return False, normalize_remote_error(exit_code, out, err, "Health check failed.")


def sftp_ensure_dir(sftp: Any, remote_path: str) -> None:
    """Create remote directory and parents if they do not exist."""
    parts = Path(remote_path.rstrip("/")).parts
    current = ""
    for part in parts:
        if part == "/":
            current = "/"
            continue
        current = f"{current}/{part}" if current else part
        try:
            sftp.stat(current)
        except FileNotFoundError:
            sftp.mkdir(current)


def sftp_put_bytes(sftp: Any, data: bytes, remote_path: str) -> None:
    """Write bytes to a remote file; parent directory must exist or be created first."""
    with sftp.file(remote_path, "wb") as f:
        f.write(data)


def sftp_put_string(sftp: Any, content: str, remote_path: str, encoding: str = "utf-8") -> None:
    """Write string to a remote file."""
    sftp_put_bytes(sftp, content.encode(encoding), remote_path)


def detect_compose_cmd(client: Any) -> Optional[str]:
    """Return 'docker compose' or 'docker-compose' depending on what is available on the host."""
    exit_code, _, _ = run_remote_command(client, "docker compose version 2>/dev/null")
    if exit_code == 0:
        return "docker compose"
    exit_code, _, _ = run_remote_command(client, "docker-compose --version 2>/dev/null")
    return "docker-compose" if exit_code == 0 else None


def install_public_key_on_host(client: Any, public_key_content: str) -> None:
    """
    Ensure the public key is present in ~/.ssh/authorized_keys on the remote host.
    Appends only when the key is not already present (idempotent). Uses SFTP to
    write a temp file, then a remote command to append if missing and set permissions.
    Raises UserSafeError with a generic message on failure (no sensitive details).
    """
    if not public_key_content or not public_key_content.strip():
        raise UserSafeError("Public key content is empty.")
    tmp_path = "/tmp/rengine_pubkey.pub"
    try:
        sftp = client.open_sftp()
        try:
            sftp_put_string(sftp, public_key_content.strip() + "\n", tmp_path)
        finally:
            sftp.close()
    except Exception as e:
        logger.log_line(
            PREFIX_WORKER_SSH,
            "SSH",
            "SFTP write failed when installing public key: %s" % (e,),
            level="warning",
        )
        raise UserSafeError("Could not write key to host.") from e

    cmd = (
        "mkdir -p ~/.ssh && "
        "(grep -qFf "
        + tmp_path
        + " ~/.ssh/authorized_keys 2>/dev/null || cat "
        + tmp_path
        + " >> ~/.ssh/authorized_keys) && "
        "chmod 600 ~/.ssh/authorized_keys && "
        "chmod 700 ~/.ssh 2>/dev/null; "
        "rm -f " + tmp_path
    )
    exit_code, out, err = run_remote_command(client, cmd, timeout=15)
    if exit_code != 0:
        logger.log_line(
            PREFIX_WORKER_SSH,
            "SSH",
            "Failed to install key on host: exit_code=%s stderr=%s" % (exit_code, err),
            level="warning",
        )
        raise UserSafeError("Could not install key on host.")
