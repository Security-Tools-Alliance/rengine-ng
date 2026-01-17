import json
import os
import re
import select
import shlex
import subprocess
import time

from celery.utils.log import get_task_logger
from django.utils import timezone

from reNgine.utilities.dns_wrapper import build_command_with_dns
from startScan.models import Command, ScanHistory


logger = get_task_logger(__name__)


# --------------#
# CLI BUILDERS #
# --------------#


def _build_cmd(cmd, options, flags, sep=" "):
    for k, v in options.items():
        if not v:
            continue
        cmd += f" {k}{sep}{v}"

    for flag in flags:
        if not flag:
            continue
        cmd += f" --{flag}"

    return cmd


def get_nmap_cmd(
    input_file,
    args=None,
    host=None,
    ports=None,
    output_file=None,
    script=None,
    script_args=None,
    max_rate=None,
    flags=None,
):
    if flags is None:
        flags = []
    # Initialize base options
    options = {
        "--max-rate": max_rate,
        "-oX": output_file,
        "--script": script,
        "--script-args": script_args,
    }

    # Build command with options
    cmd = "nmap"
    cmd = _build_cmd(cmd, options, flags)

    # Add ports and service detection
    if ports and "-p" not in cmd:
        cmd = f"{cmd} -p {ports}"
    if "-sV" not in cmd:
        cmd = f"{cmd} -sV"
    if "-Pn" not in cmd:
        cmd = f"{cmd} -Pn"

    # Add input source
    if not input_file:
        cmd += f" {host}" if host else ""
    else:
        cmd += f" -iL {input_file}"

    return cmd


# -------------------#
# Command Execution #
# -------------------#


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


def create_command_object(cmd, scan_id, activity_id):
    """
    Create a Command object in the database.

    Args:
        cmd (str): The command to be executed.
        scan_id (int): ID of the associated scan.
        activity_id (int): ID of the associated activity.

    Returns:
        Command: The created Command object.
    """
    return Command.objects.create(command=cmd, time=timezone.now(), scan_history_id=scan_id, activity_id=activity_id)


def process_line(line, trunc_char=None):
    """
    Process a line of output from the command.

    Args:
        line (str): The line to process.
        trunc_char (str, optional): Character to truncate the line. Defaults to None.

    Returns:
        str or dict: The processed line, either as a string or a JSON object if the line is valid JSON.
    """
    line = line.strip()
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    line = ansi_escape.sub("", line)
    line = line.replace("\\x0d\\x0a", "\n")
    if trunc_char and line.endswith(trunc_char):
        line = line[:-1]
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return line


def write_history(history_file, cmd, return_code, output):
    """
    Write command execution history to a file.

    Args:
        history_file (str): Path to the history file.
        cmd (str): The executed command.
        return_code (int): The return code of the command.
        output (str): The output of the command.
    """
    mode = "a" if os.path.exists(history_file) else "w"
    with open(history_file, mode) as f:
        f.write(f"\n{cmd}\n{return_code}\n{output}\n------------------\n")


def execute_command(command, shell, cwd):
    """
    Execute a command using subprocess.

    Args:
        command (str or list): The command to execute.
        shell (bool): Whether to use shell execution.
        cwd (str): The working directory for the command.

    Returns:
        subprocess.Popen: The Popen object for the executed command.
    """
    return subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=shell,
        cwd=cwd,
        bufsize=-1,
        universal_newlines=True,
        encoding="utf-8",
    )


def decode_bytes_robust(data, primary_encoding="utf-8", fallback_encoding="latin-1"):
    """
    Robustly decode bytes with fallback encoding.

    Attempts to decode with primary encoding first, falls back to fallback encoding
    if UnicodeDecodeError occurs. latin-1 can decode any byte sequence.

    Args:
        data (bytes): Data to decode
        primary_encoding (str): Primary encoding to try (default: utf-8)
        fallback_encoding (str): Fallback encoding (default: latin-1)

    Returns:
        str: Decoded string
    """
    if not data:
        return ""

    try:
        return data.decode(primary_encoding)
    except UnicodeDecodeError:
        logger.debug(f"Failed to decode with {primary_encoding}, using {fallback_encoding}")
        try:
            return data.decode(fallback_encoding)
        except Exception as e:
            # Last resort: decode with 'replace' error handler
            logger.warning(f"Failed to decode with {fallback_encoding}, using 'replace' mode: {e}")
            return data.decode(primary_encoding, errors="replace")


def stream_command(
    cmd, cwd=None, shell=False, history_file=None, encoding="utf-8", scan_id=None, activity_id=None, trunc_char=None
):
    """
    Execute a command and yield its output line by line in real-time.

    Automatically applies DNS arguments injection for tools that support it
    (subfinder, httpx, nmap, nuclei, dnsx, etc.)

    Handles subprocess output decoding with the specified encoding (default "utf-8").
    If decoding fails due to UnicodeDecodeError, falls back to "latin-1" encoding
    to ensure all bytes can be represented.

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
    yield from execute_with_dns(
        cmd, scan_id, stream_command_internal, cwd, shell, history_file, encoding, scan_id, activity_id, trunc_char
    )


def stream_command_internal(
    cmd, cwd=None, shell=False, history_file=None, encoding="utf-8", scan_id=None, activity_id=None, trunc_char=None
):
    """
    Internal implementation of stream command with comprehensive error handling.
    Use stream_command() instead which handles DNS automatically.

    Handles encoding issues robustly by reading bytes and decoding manually
    with fallback to latin-1 if the primary encoding fails.
    """
    logger.info(f"Starting real-time execution of command: {cmd}")

    command_obj = None
    process = None

    try:
        command_obj = create_command_object(cmd, scan_id, activity_id)
        command = prepare_command(cmd, shell)
        logger.debug(f"Prepared stream command: {command}")

        # Execute command with line buffering for better streaming
        # Note: We read bytes and decode manually to handle encoding errors gracefully
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=shell,
                cwd=cwd,
                bufsize=0,  # Line buffered
            )
        except OSError as e:
            # Use logger.exception() to capture full traceback
            logger.exception(f"OSError while executing streaming command '{cmd}'")
            if command_obj:
                try:
                    command_obj.output = ""
                    command_obj.error_output = str(e)
                    command_obj.return_code = -1
                    command_obj.save()
                except Exception:
                    # Use logger.exception() to capture full traceback
                    logger.exception(f"Failed to save command object after OSError for cmd: {cmd}")
            return
        except Exception as e:
            # Use logger.exception() to capture full traceback for unexpected errors
            logger.exception(f"Unexpected error while executing streaming command '{cmd}'")
            if command_obj:
                try:
                    command_obj.output = ""
                    command_obj.error_output = str(e)
                    command_obj.return_code = -1
                    command_obj.save()
                except Exception:
                    # Use logger.exception() to capture full traceback
                    logger.exception(f"Failed to save command object after exception for cmd: {cmd}")
            return

        # Initialize buffers and tracking variables (bytes)
        stdout_buffer = b""
        stderr_buffer = b""
        full_output_bytes = b""
        full_error_bytes = b""

        # Use select for real-time streaming on Linux
        while True:
            # Check if process has terminated
            if process.poll() is not None:
                # Read any remaining data (bytes)
                remaining_stdout = process.stdout.read()
                remaining_stderr = process.stderr.read()

                if remaining_stdout:
                    stdout_buffer += remaining_stdout
                    full_output_bytes += remaining_stdout
                if remaining_stderr:
                    stderr_buffer += remaining_stderr
                    full_error_bytes += remaining_stderr

                # Process any remaining complete lines
                while b"\n" in stdout_buffer:
                    line_bytes, stdout_buffer = stdout_buffer.split(b"\n", 1)
                    # Decode line with robust error handling
                    line = decode_bytes_robust(line_bytes, primary_encoding=encoding)
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
                                full_output_bytes += data

                                # Process complete lines immediately
                                while b"\n" in stdout_buffer:
                                    line_bytes, stdout_buffer = stdout_buffer.split(b"\n", 1)
                                    # Decode line with robust error handling
                                    line = decode_bytes_robust(line_bytes, primary_encoding=encoding)
                                    if line.strip():
                                        try:
                                            if item := process_line(line, trunc_char):
                                                yield item
                                        except Exception as e:
                                            logger.error(f"Error processing output line: {e}")
                            else:
                                stderr_buffer += data
                                full_error_bytes += data
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

        # Decode full output and error with robust error handling
        full_output = decode_bytes_robust(full_output_bytes, primary_encoding=encoding)
        full_error = decode_bytes_robust(full_error_bytes, primary_encoding=encoding)

        # Log completion status
        if return_code != 0:
            error_msg = f"Command failed with exit code {return_code}"
            if full_error:
                error_msg += f"\nError output:\n{full_error}"
            logger.error(error_msg)
        else:
            logger.info(f"Command completed successfully with exit code {return_code}")

        # Save command results
        if command_obj:
            try:
                command_obj.output = full_output
                command_obj.error_output = full_error
                command_obj.return_code = return_code
                command_obj.save()
            except Exception:
                # Use logger.exception() to capture full traceback
                logger.exception(f"Failed to save command object for streaming cmd: {cmd}")

        logger.debug(f"Command returned exit code: {return_code}")

        # Write history if requested
        if history_file:
            try:
                write_history(history_file, cmd, return_code, full_output)
            except Exception:
                # Use logger.exception() to capture full traceback
                logger.exception(f"Failed to write command history to {history_file}")

    except Exception as e:
        # Catch-all for any unexpected errors in the outer scope
        # Use logger.exception() to preserve full traceback for debugging
        logger.exception(
            f"Critical error in stream_command_internal for command '{cmd}'. "
            f"This indicates an unexpected issue outside normal execution flow."
        )
        if command_obj:
            try:
                command_obj.output = ""
                # Include exception type and message for better error context
                command_obj.error_output = f"Critical error: {type(e).__name__}: {str(e)}"
                command_obj.return_code = -1
                command_obj.save()
            except Exception:
                # Use logger.exception() to capture full traceback
                logger.exception(f"Failed to save command object after critical error for cmd: {cmd}")


# ------------------#
# Header generation #
# ------------------#


def parse_custom_header(custom_header):
    """
    Parse the custom_header input to ensure it is a dictionary with valid header values.

    Args:
        custom_header (dict or str): Dictionary or string containing the custom headers.

    Returns:
        dict: Parsed dictionary of custom headers.
    """

    def is_valid_header_value(value):
        return bool(re.match(r"^[\w\-\s.,;:@()/+*=\'\[\]{}]+$", value))

    if isinstance(custom_header, str):
        header_dict = {}
        headers = custom_header.split(",")
        for header in headers:
            parts = header.split(":", 1)
            if len(parts) == 2:
                key, value = parts
                key = key.strip()
                value = value.strip()
                if is_valid_header_value(value):
                    header_dict[key] = value
                else:
                    raise ValueError(f"Invalid header value: '{value}'")
            else:
                raise ValueError(f"Invalid header format: '{header}'")
        return header_dict
    elif isinstance(custom_header, dict):
        for key, value in custom_header.items():
            if not is_valid_header_value(value):
                raise ValueError(f"Invalid header value: '{value}'")
        return custom_header
    else:
        raise ValueError("custom_header must be a dictionary or a string")


def generate_header_param(custom_header, tool_name=None):
    """
    Generate command-line parameters for a specific tool based on the custom header.

    Args:
        custom_header (dict or str): Dictionary or string containing the custom headers.
        tool_name (str, optional): Name of the tool. Defaults to None.

    Returns:
        str: Command-line parameter for the specified tool.
    """
    logger.debug(f"Generating header parameters for tool: {tool_name}")
    logger.debug(f"Input custom_header: {custom_header}")

    # Ensure the custom_header is a dictionary
    custom_header = parse_custom_header(custom_header)

    # Common formats
    common_headers = [f"{key}: {value}" for key, value in custom_header.items()]
    semi_colon_headers = ";;".join(common_headers)
    colon_headers = [f"{key}:{value}" for key, value in custom_header.items()]

    # Define format mapping for each tool
    format_mapping = {
        "common": " ".join([f' -H "{header}"' for header in common_headers]),
        "dalfox": " ".join([f' -H "{header}"' for header in colon_headers]),
        "hakrawler": f' -h "{semi_colon_headers}"',
        "gospider": generate_gospider_params(custom_header),
    }

    # Get the appropriate format based on the tool name
    result = format_mapping.get(tool_name, format_mapping.get("common"))
    logger.debug(f"Selected format for {tool_name}: {result}")

    # Return the corresponding parameter for the specified tool or default to common_headers format
    return result


def generate_gospider_params(custom_header):
    """
    Generate command-line parameters for gospider based on the custom header.

    Args:
        custom_header (dict): Dictionary containing the custom headers.

    Returns:
        str: Command-line parameters for gospider.
    """
    params = []
    for key, value in custom_header.items():
        if key.lower() == "user-agent":
            params.append(f' -u "{value}"')
        elif key.lower() == "cookie":
            params.append(f' --cookie "{value}"')
        else:
            params.append(f' -H "{key}:{value}"')
    return " ".join(params)


def apply_dns_wrapper(cmd, scan_id):
    """
    Apply DNS wrapper to command if scan has a target domain with custom DNS.

    Args:
        cmd (str): Original command string
        scan_id (int): Scan ID to retrieve domain from

    Returns:
        str: Command with DNS arguments injected if applicable, original otherwise
    """
    if not scan_id:
        return cmd

    try:
        return get_dns_command(scan_id, cmd)
    except Exception as e:
        logger.debug(f"DNS wrapper not applied: {e}")
        return cmd


def execute_with_dns(cmd, scan_id, executor_func, *args, **kwargs):
    """
    Execute a function with DNS arguments injection.

    Args:
        cmd (str): Command to execute
        scan_id (int): Scan ID
        executor_func: Function to execute (either _run_command_internal or stream_command_internal)
        *args, **kwargs: Arguments to pass to executor_func

    Returns:
        Whatever executor_func returns
    """
    # Apply DNS wrapper (inject DNS arguments for tools that support it)
    cmd = apply_dns_wrapper(cmd, scan_id)

    # Execute the command
    return executor_func(cmd, *args, **kwargs)


def get_dns_command(scan_id, cmd):
    """
    Injects DNS server arguments into a command if the associated scan's domain has custom DNS servers.

    This function retrieves the scan's domain and, if DNS servers are configured, modifies the command to include them.

    Args:
        scan_id (int): The ID of the scan whose domain should be checked for DNS servers.
        cmd (str): The original command string.

    Returns:
        str: The command string with DNS arguments injected if applicable, otherwise the original command.
    """
    try:
        scan = ScanHistory.objects.get(pk=scan_id)
    except ScanHistory.DoesNotExist:
        logger.warning(f"Scan with ID {scan_id} does not exist. DNS wrapper not applied.")
        return cmd
    except Exception:
        # Use logger.exception() to capture full traceback for unexpected database errors
        logger.exception(f"Error retrieving scan {scan_id}. DNS wrapper not applied.")
        return cmd

    try:
        domain = scan.domain
    except Exception:
        # Use logger.exception() to capture full traceback
        logger.exception(f"Error accessing domain for scan {scan_id}. DNS wrapper not applied.")
        return cmd

    if not domain or not domain.get_dns_servers():
        return cmd

    # Parse command: extract tool and arguments using shlex for proper handling of quoted arguments
    try:
        cmd_parts = shlex.split(cmd)
    except ValueError as e:
        logger.warning(f"Failed to parse command with shlex: {e}. Falling back to simple split.")
        cmd_parts = cmd.split()

    if len(cmd_parts) < 1:
        return cmd

    tool_path = cmd_parts[0]
    args = cmd_parts[1:] if len(cmd_parts) > 1 else []

    # Extract tool name from path (e.g., /home/rengine/tools/go/bin/httpx → httpx)
    tool_name = os.path.basename(tool_path)

    try:
        # Build command with DNS wrapper using tool name for detection
        dns_cmd = build_command_with_dns(tool_name, args, domain=domain)

        # Replace tool name back with original path in the first element
        if dns_cmd and dns_cmd[0] == tool_name:
            dns_cmd[0] = tool_path

        new_cmd = " ".join(dns_cmd)

        if new_cmd != cmd:
            logger.info(f"DNS wrapper applied: {tool_name} → added DNS {', '.join(domain.get_dns_servers())}")

        return new_cmd
    except Exception:
        # Use logger.exception() to capture full traceback for debugging
        logger.exception(f"Error building DNS command for '{cmd}'. Returning original command.")
        return cmd
