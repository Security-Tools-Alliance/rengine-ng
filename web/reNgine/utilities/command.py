import json
import os
import re
import shlex
import subprocess
from django.utils import timezone
from celery.utils.log import get_task_logger
from startScan.models import Command

logger = get_task_logger(__name__)


#--------------#
# CLI BUILDERS #
#--------------#

def _build_cmd(cmd, options, flags, sep=" "):
    for k,v in options.items():
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
        flags=None):

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
    cmd = 'nmap'
    cmd = _build_cmd(cmd, options, flags)
 
    # Add ports and service detection
    if ports and '-p' not in cmd:
        cmd = f'{cmd} -p {ports}'
    if '-sV' not in cmd:
        cmd = f'{cmd} -sV'
    if '-Pn' not in cmd:
        cmd = f'{cmd} -Pn'

    # Add input source
    if not input_file:
        cmd += f" {host}" if host else ""
    else:
        cmd += f" -iL {input_file}"

    return cmd


#-------------------#
# Command Execution #
#-------------------#

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
    return Command.objects.create(
        command=cmd,
        time=timezone.now(),
        scan_history_id=scan_id,
        activity_id=activity_id
    )


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
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    line = ansi_escape.sub('', line)
    line = line.replace('\\x0d\\x0a', '\n')
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
    mode = 'a' if os.path.exists(history_file) else 'w'
    with open(history_file, mode) as f:
        f.write(f'\n{cmd}\n{return_code}\n{output}\n------------------\n')


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
        encoding='utf-8'
    )


#------------------#
# Header generation #
#------------------#

def parse_custom_header(custom_header):
    """
    Parse the custom_header input to ensure it is a dictionary with valid header values.

    Args:
        custom_header (dict or str): Dictionary or string containing the custom headers.

    Returns:
        dict: Parsed dictionary of custom headers.
    """
    def is_valid_header_value(value):
        return bool(re.match(r'^[\w\-\s.,;:@()/+*=\'\[\]{}]+$', value))

    if isinstance(custom_header, str):
        header_dict = {}
        headers = custom_header.split(',')
        for header in headers:
            parts = header.split(':', 1)
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
    semi_colon_headers = ';;'.join(common_headers)
    colon_headers = [f"{key}:{value}" for key, value in custom_header.items()]

    # Define format mapping for each tool
    format_mapping = {
        'common': ' '.join([f' -H "{header}"' for header in common_headers]),
        'dalfox': ' '.join([f' -H "{header}"' for header in colon_headers]),
        'hakrawler': f' -h "{semi_colon_headers}"',
        'gospider': generate_gospider_params(custom_header),
    }

    # Get the appropriate format based on the tool name
    result = format_mapping.get(tool_name, format_mapping.get('common'))
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
        if key.lower() == 'user-agent':
            params.append(f' -u "{value}"')
        elif key.lower() == 'cookie':
            params.append(f' --cookie "{value}"')
        else:
            params.append(f' -H "{key}:{value}"')
    return ' '.join(params) 