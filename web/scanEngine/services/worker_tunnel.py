"""
SSH reverse tunnel for worker API access.
When api_access_type is tunnel, reNgine runs ssh -R bind:port so the worker host listens.

Bind address is configurable via RENGINE_TUNNEL_BIND_ADDRESS (default 172.17.0.1, Docker bridge).
- 172.17.0.1: Docker default bridge gateway; only the Secator container can reach the tunnel via
  host.docker.internal (default in settings.py).
- 127.0.0.1: only localhost (container cannot reach the tunnel).
- 0.0.0.0: all interfaces; use only if the bridge has another gateway (e.g. custom network).
Requires GatewayPorts yes in sshd_config for any non-127.0.0.1 bind. API is protected by TLS and API key.
"""

import subprocess
from typing import Any, Optional

from django.conf import settings

from reNgine.utilities.logger import get_module_logger
from scanEngine.models import SecatorWorker

from .worker_config import is_tunnel_api_access
from .worker_ssh import default_ssh_key_path


PREFIX_WORKER_TUNNEL = "[WORKER_TUNNEL]"
logger = get_module_logger(__name__)


def start_worker_tunnel(worker: SecatorWorker) -> Optional[subprocess.Popen[bytes]]:
    """
    Start an SSH reverse tunnel so the worker can reach reNgine API at 127.0.0.1:api_tunnel_port.
    Runs: ssh -R api_tunnel_port:target_host:target_port user@worker_host -N
    Returns the Popen handle for stop_worker_tunnel, or None if tunnel is not applicable (e.g. classic mode).
    Raises ValueError if worker is not configured for tunnel or SSH key auth is required but missing.
    """
    if not is_tunnel_api_access(worker):
        return None

    target_host = settings.RENGINE_TUNNEL_TARGET_HOST
    target_port = settings.RENGINE_TUNNEL_TARGET_PORT
    bind_address = (settings.RENGINE_TUNNEL_BIND_ADDRESS or "172.17.0.1").strip()
    remote_port = worker.api_tunnel_port
    if remote_port < 1 or remote_port > 65535:
        raise ValueError("api_tunnel_port must be between 1 and 65535")

    if worker.ssh_auth_type != worker.AUTH_KEY:
        raise ValueError("SSH tunnel requires key-based authentication")

    key_path = (worker.ssh_key_path or "").strip() or default_ssh_key_path()
    host = worker.ssh_host
    port = worker.ssh_port
    user = worker.ssh_user

    reverse = f"{bind_address}:{remote_port}:{target_host}:{target_port}"
    cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ServerAliveInterval=30",
        "-o",
        "ServerAliveCountMax=3",
        "-i",
        key_path,
        "-p",
        str(port),
        "-R",
        reverse,
        f"{user}@{host}",
        "-N",
    ]
    try:
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        logger.log_line(
            PREFIX_WORKER_TUNNEL,
            "TUNNEL",
            "Started SSH reverse tunnel for worker %s (remote %s:%s -> %s:%s)"
            % (worker.name, bind_address, remote_port, target_host, target_port),
            level="info",
        )
        return process
    except FileNotFoundError:
        logger.log_line(
            PREFIX_WORKER_TUNNEL,
            "TUNNEL",
            "ssh command not found",
            level="warning",
        )
        raise ValueError("SSH client not available") from None
    except Exception as e:
        logger.log_line(
            PREFIX_WORKER_TUNNEL,
            "TUNNEL",
            "Failed to start tunnel for worker %s: %s" % (worker.name, e),
            level="warning",
        )
        raise


def stop_worker_tunnel(handle: Any) -> None:
    """Terminate the SSH tunnel process started by start_worker_tunnel."""
    if handle is None:
        return
    if not hasattr(handle, "terminate") or not callable(getattr(handle, "terminate")):
        return
    try:
        handle.terminate()
        handle.wait(timeout=10)
    except subprocess.TimeoutExpired:
        handle.kill()
        handle.wait()
    except Exception as e:
        logger.log_line(
            PREFIX_WORKER_TUNNEL,
            "STOP",
            "Error stopping tunnel process: %s" % (e,),
            level="debug",
        )
