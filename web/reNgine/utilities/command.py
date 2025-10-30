import shlex
import subprocess

from celery.utils.log import get_task_logger


logger = get_task_logger(__name__)


def prepare_command(cmd, shell):
    """
    Prepare the command for execution.

    Args:
        cmd (str): The command to prepare.
        shell (bool): Whether to use shell execution.

    Returns:
        str or list: The prepared command, either as a string (for shell execution) or a list (for non-shell execution).
    """
    return cmd if shell else shlex.split(cmd)


def run_command(command, shell=True, cwd=None, timeout=None):
    """
    Execute a command using subprocess with security protection.

    Args:
        command (str): The command to execute.
        shell (bool): Whether to use shell execution. Defaults to True.
        cwd (str, optional): The working directory for the command. Defaults to None.
        timeout (int, optional): Command timeout in seconds. Defaults to None.

    Returns:
        tuple: (return_code, output)
    """
    try:
        # Prepare command to avoid injection attacks
        prepared_command = prepare_command(command, shell)

        result = subprocess.run(prepared_command, shell=shell, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {command}")
        return -1, "Command timed out"
    except Exception as e:
        logger.error(f"Error running command {command}: {e}")
        return -1, str(e)
