import re
import select
import subprocess
import time

from celery.utils.log import get_task_logger

from reNgine.celery import app
from reNgine.utilities.command import (
    create_command_object,
    prepare_command,
    execute_command,
    write_history,
    process_line
)

logger = get_task_logger(__name__)


@app.task(name='run_command', bind=False, queue='run_command_queue')
def run_command(cmd, cwd=None, shell=False, history_file=None, scan_id=None, activity_id=None, remove_ansi_sequence=False, combine_output=False):
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
    command_obj = create_command_object(cmd, scan_id, activity_id)
    command = prepare_command(cmd, shell)
    logger.debug(f"Prepared run command: {command}")
    
    process = execute_command(command, shell, cwd)
    output, error_output = process.communicate()
    return_code = process.returncode

    # Combine stdout and stderr if requested
    if combine_output:
        combined_output = ""
        if output:
            combined_output += output
        if error_output:
            combined_output += error_output
        
        if combined_output:
            combined_output = re.sub(r'\x1b\[[0-9;]*[mGKH]', '', combined_output) if remove_ansi_sequence else combined_output
        
        final_output = combined_output
    else:
        # Default behavior: only use stdout
        if output:
            final_output = re.sub(r'\x1b\[[0-9;]*[mGKH]', '', output) if remove_ansi_sequence else output
        else:
            final_output = ""
    
    if return_code != 0:
        error_msg = f"Command failed with exit code {return_code}"
        if error_output:
            error_msg += f"\nError output:\n{error_output}"
        logger.error(error_msg)
        
    command_obj.output = final_output or None
    command_obj.error_output = error_output or None
    command_obj.return_code = return_code
    command_obj.save()
    
    if history_file:
        write_history(history_file, cmd, return_code, final_output)
    
    return return_code, final_output


def stream_command(cmd, cwd=None, shell=False, history_file=None, encoding='utf-8', scan_id=None, activity_id=None, trunc_char=None):
    """
    Execute a command and yield its output line by line in real-time.
    
    This function uses select.select() to monitor file descriptors and processes
    output as soon as it becomes available, ensuring proper streaming behavior
    for tools like httpx and nuclei.

    Args:
        cmd (str): The command to execute.
        cwd (str, optional): The working directory for the command. Defaults to None.
        shell (bool, optional): Whether to use shell execution. Defaults to False.
        history_file (str, optional): File to write command history. Defaults to None.
        encoding (str, optional): Encoding for the command output. Defaults to 'utf-8'.
        scan_id (int, optional): ID of the associated scan. Defaults to None.
        activity_id (int, optional): ID of the associated activity. Defaults to None.
        trunc_char (str, optional): Character to truncate lines. Defaults to None.

    Yields:
        str or dict: Each line of the command output, processed and potentially parsed as JSON.
    """
    logger.info(f"Starting real-time execution of command: {cmd}")
    command_obj = create_command_object(cmd, scan_id, activity_id)
    command = prepare_command(cmd, shell)
    logger.debug(f"Prepared stream command: {command}")

    # Execute command with line buffering for better streaming
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=shell,
        cwd=cwd,
        bufsize=1,  # Line buffered
        universal_newlines=True,
        encoding=encoding
    )

    # Initialize buffers and tracking variables
    stdout_buffer = ""
    stderr_buffer = ""
    full_output = ""
    full_error = ""

    # Use select for real-time streaming on Linux
    while True:
        # Check if process has terminated
        if process.poll() is not None:
            # Read any remaining data
            remaining_stdout = process.stdout.read()
            remaining_stderr = process.stderr.read()

            if remaining_stdout:
                stdout_buffer += remaining_stdout
                full_output += remaining_stdout
            if remaining_stderr:
                stderr_buffer += remaining_stderr
                full_error += remaining_stderr

            # Process any remaining complete lines
            while '\n' in stdout_buffer:
                line, stdout_buffer = stdout_buffer.split('\n', 1)
                if line.strip():
                    try:
                        if item := process_line(line, trunc_char):
                            yield item
                    except Exception as e:
                        logger.error(f"Error processing output line: {e}")
            break

        # Use select to wait for data availability
        try:
            ready, _, _ = select.select([process.stdout, process.stderr], [], [], 0.1)

            for fd in ready:
                try:
                    if data := fd.read(1024):
                        if fd == process.stdout:
                            stdout_buffer += data
                            full_output += data

                            # Process complete lines immediately
                            while '\n' in stdout_buffer:
                                line, stdout_buffer = stdout_buffer.split('\n', 1)
                                if line.strip():
                                    try:
                                        if item := process_line(
                                            line, trunc_char
                                        ):
                                            yield item
                                    except Exception as e:
                                        logger.error(f"Error processing output line: {e}")
                        else:
                            stderr_buffer += data
                            full_error += data
                except Exception as e:
                    logger.debug(f"Error reading from file descriptor: {e}")
                    continue

        except Exception as e:
            logger.debug(f"Select error: {e}")
            # Fallback to simple polling if select fails
            time.sleep(0.1)

    # Wait for process completion
    process.wait()
    return_code = process.returncode

    # Log completion status
    if return_code != 0:
        error_msg = f"Command failed with exit code {return_code}"
        if full_error:
            error_msg += f"\nError output:\n{full_error}"
        logger.error(error_msg)
    else:
        logger.info(f"Command completed successfully with exit code {return_code}")

    # Save command results
    command_obj.output = full_output or None
    command_obj.error_output = full_error or None
    command_obj.return_code = return_code
    command_obj.save()

    logger.debug(f'Command returned exit code: {return_code}')

    # Write history if requested
    if history_file:
        write_history(history_file, cmd, return_code, full_output) 