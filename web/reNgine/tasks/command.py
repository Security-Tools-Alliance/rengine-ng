import re

from celery.utils.log import get_task_logger

from reNgine.celery import app
from reNgine.utilities.command import (
    create_command_object,
    execute_command,
    prepare_command,
    write_history,
)


logger = get_task_logger(__name__)


@app.task(name="run_command", bind=False, queue="run_command_queue")
def run_command(
    cmd,
    cwd=None,
    shell=False,
    history_file=None,
    scan_id=None,
    activity_id=None,
    remove_ansi_sequence=False,
    combine_output=False,
):
    """
    Execute a command and return its output.

    Args:
        cmd (str): The command to execute.
        cwd (str, optional): The working directory for the command. Defaults to None.
        shell (bool, optional): Whether to use shell execution. Defaults to False.
        history_file (str, optional): File to write command history. Defaults to None.
        scan_id (int, optional): ID of the associated scan. Defaults to None.
        activity_id (int, optional): ID of the associated activity. Defaults to None.
        remove_ansi_sequence (bool, optional): Whether to remove ANSI escape sequences from output. Defaults to False.
        combine_output (bool, optional): Whether to combine stdout and stderr. Defaults to False.

    Returns:
        tuple: A tuple containing the return code and output of the command.
    """
    logger.info(f"Starting execution of command: {cmd}")

    from reNgine.utilities.command import execute_with_dns

    return execute_with_dns(
        cmd,
        scan_id,
        _run_command_internal,
        cwd,
        shell,
        history_file,
        scan_id,
        activity_id,
        remove_ansi_sequence,
        combine_output,
    )


def _run_command_internal(cmd, cwd, shell, history_file, scan_id, activity_id, remove_ansi_sequence, combine_output):
    """
    Internal implementation of run_command with comprehensive error handling.

    Preserves full exception context and tracebacks for debugging while ensuring
    the function always returns a valid tuple (return_code, final_output).
    """
    command_obj = None
    return_code = -1
    final_output = ""
    error_output = ""

    try:
        command_obj = create_command_object(cmd, scan_id, activity_id)
        command = prepare_command(cmd, shell)
        logger.debug(f"Prepared run command: {command}")

        try:
            process = execute_command(command, shell, cwd)
            output, error_output = process.communicate()
            return_code = process.returncode
        except OSError as e:
            # Use logger.exception() to capture full traceback
            logger.exception(f"OSError while executing command '{cmd}'")
            return_code = -1
            final_output = ""
            error_output = str(e)
        except Exception as e:
            # Use logger.exception() to capture full traceback for unexpected errors
            logger.exception(f"Unexpected error while executing command '{cmd}'")
            return_code = -1
            final_output = ""
            error_output = str(e)
        else:
            # Process output only if command executed successfully (no exception)
            # Combine stdout and stderr if requested
            if combine_output:
                combined_output = ""
                if output:
                    combined_output += output
                if error_output:
                    combined_output += error_output

                if combined_output:
                    combined_output = (
                        re.sub(r"\x1b\[[0-9;]*[mGKH]", "", combined_output) if remove_ansi_sequence else combined_output
                    )

                final_output = combined_output
            else:
                # Default behavior: only use stdout
                if output:
                    final_output = re.sub(r"\x1b\[[0-9;]*[mGKH]", "", output) if remove_ansi_sequence else output
                else:
                    final_output = ""

            if return_code != 0:
                error_msg = f"Command failed with exit code {return_code}"
                if error_output:
                    error_msg += f"\nError output:\n{error_output}"
                logger.error(error_msg)

        # Save command object if it was created
        if command_obj:
            try:
                command_obj.output = final_output or None
                command_obj.error_output = error_output or None
                command_obj.return_code = return_code
                command_obj.save()
            except Exception:
                # Use logger.exception() to capture full traceback
                logger.exception(f"Failed to save command object for cmd: {cmd}")

        # Write history if requested
        if history_file:
            try:
                write_history(history_file, cmd, return_code, final_output)
            except Exception:
                # Use logger.exception() to capture full traceback
                logger.exception(f"Failed to write command history to {history_file}")

    except Exception as e:
        # Catch-all for any unexpected errors in the outer scope
        # Use logger.exception() to preserve full traceback for debugging
        logger.exception(
            f"Critical error in _run_command_internal for command '{cmd}'. "
            f"This indicates an unexpected issue outside normal execution flow."
        )
        return_code = -1
        # Include exception type and message for better error context
        final_output = f"Critical error: {type(e).__name__}: {str(e)}"

    return return_code, final_output
