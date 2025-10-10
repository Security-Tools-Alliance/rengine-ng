"""
Command utilities for building and executing system commands.

This module provides functionality for building command-line commands
and executing them using various tools and frameworks.
"""

import subprocess
from typing import Any, Dict, List, Tuple

from reNgine.utilities.core.data import remove_ansi_sequences
from reNgine.utilities.distributed.command import DistributedCommandBuilder
from reNgine.utilities.distributed.utilities import get_distributed_utilities


class CommandProcessor:
    """Command processor using distributed utilities"""

    def __init__(self, config=None):
        self.distributed_utils = get_distributed_utilities(config)
        self.command_processor = self.distributed_utils.get_command_processor()

    def build_nmap_command(
        self, target: str, ports: List[int] = None, scan_type: str = "syn", output_file: str = None, **kwargs
    ) -> str:
        """Build nmap command using distributed command builder"""
        command_builder = DistributedCommandBuilder("nmap")

        # Add scan type
        if scan_type == "syn":
            command_builder.add_flag("-sS")
        elif scan_type == "tcp":
            command_builder.add_flag("-sT")
        elif scan_type == "udp":
            command_builder.add_flag("-sU")

        # Add ports
        if ports:
            port_list = ",".join(map(str, ports))
            command_builder.add_option("-p", port_list)

        # Add output file
        if output_file:
            command_builder.add_option("-oN", output_file)

        # Add target
        command_builder.add_argument(target)

        return command_builder.build()

    def build_httpx_command(
        self, urls: List[str], threads: int = 10, timeout: int = 10, output_file: str = None, **kwargs
    ) -> str:
        """Build httpx command using distributed command builder"""
        command_builder = DistributedCommandBuilder("httpx")

        # Add flags
        command_builder.add_flag("-silent")
        command_builder.add_flag("-json")

        # Add options
        command_builder.add_option("-threads", threads)
        command_builder.add_option("-timeout", timeout)

        # Add output file
        if output_file:
            command_builder.add_option("-o", output_file)

        # Add URLs
        for url in urls:
            command_builder.add_argument(url)

        return command_builder.build()

    def build_subfinder_command(self, domain: str, output_file: str = None, threads: int = 10, **kwargs) -> str:
        """Build subfinder command using distributed command builder"""
        command_builder = DistributedCommandBuilder("subfinder")

        # Add options
        command_builder.add_option("-d", domain)
        command_builder.add_option("-t", threads)

        # Add output file
        if output_file:
            command_builder.add_option("-o", output_file)

        return command_builder.build()

    def execute_command(self, command: str, timeout: int = 300, **kwargs) -> Dict[str, Any]:
        """Execute a single command using distributed command processor"""
        try:
            result = self.command_processor.execute_commands_batch(
                [command], "single_command", timeout=timeout, **kwargs
            )

            if result.is_successful:
                return {
                    "success": True,
                    "command": command,
                    "output": result.data.get("output", ""),
                    "execution_time": result.processing_time,
                }
            else:
                return {
                    "success": False,
                    "command": command,
                    "error": result.errors[0] if result.errors else "Unknown error",
                    "execution_time": result.processing_time,
                }

        except Exception as e:
            return {"success": False, "command": command, "error": str(e), "execution_time": 0}

    def execute_commands_batch(
        self, commands: List[str], batch_id: str = "batch", timeout: int = 300, **kwargs
    ) -> Dict[str, Any]:
        """Execute multiple commands using distributed command processor"""
        try:
            result = self.command_processor.execute_commands_batch(commands, batch_id, timeout=timeout, **kwargs)

            if result.is_successful:
                return {
                    "success": True,
                    "commands": commands,
                    "results": result.data.get("results", []),
                    "execution_time": result.processing_time,
                }
            else:
                return {
                    "success": False,
                    "commands": commands,
                    "error": result.errors[0] if result.errors else "Unknown error",
                    "execution_time": result.processing_time,
                }

        except Exception as e:
            return {"success": False, "commands": commands, "error": str(e), "execution_time": 0}


def run_command(
    cmd: str, shell: bool = True, timeout: int = 300, remove_ansi_sequence: bool = False, **kwargs
) -> Tuple[int, str]:
    """
    Run a command and return exit code and output.

    Args:
        cmd: Command to execute
        shell: Whether to use shell execution
        timeout: Command timeout in seconds
        remove_ansi_sequence: Whether to remove ANSI escape sequences

    Returns:
        Tuple of (exit_code, output)
    """
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=timeout, **kwargs)

        output = result.stdout
        if remove_ansi_sequence:
            output = remove_ansi_sequences(output)

        return result.returncode, output

    except subprocess.TimeoutExpired:
        return -1, f"Command timed out after {timeout} seconds"
    except Exception as e:
        return -1, str(e)


def generate_header_param(custom_header: str, tool: str) -> str:
    """
    Generate header parameter for different tools.

    Args:
        custom_header: Custom header string
        tool: Tool name (gospider, hakrawler, etc.)

    Returns:
        Formatted header parameter
    """
    if not custom_header:
        return ""

    if tool == "hakrawler":
        return f' -h "{custom_header}"'
    else:
        return f' -H "{custom_header}"'


def validate_command_input(command: str, required_tools: List[str] = None) -> Dict[str, Any]:
    """
    Validate command input parameters.

    Args:
        command: Command to validate
        required_tools: List of required tools

    Returns:
        Validation result
    """
    validation_result = {"valid": True, "errors": [], "warnings": []}

    if not command or not isinstance(command, str):
        validation_result["valid"] = False
        validation_result["errors"].append("Command must be a non-empty string")
        return validation_result

    if required_tools:
        for tool in required_tools:
            if tool not in command:
                validation_result["warnings"].append(f"Tool '{tool}' not found in command")

    return validation_result


def get_command_statistics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Get statistics from command execution results.

    Args:
        results: List of command execution results

    Returns:
        Statistics dictionary
    """
    if not results:
        return {
            "total_commands": 0,
            "successful_commands": 0,
            "failed_commands": 0,
            "success_rate": 0,
            "total_execution_time": 0,
        }

    total_commands = len(results)
    successful_commands = sum(1 for r in results if r.get("success", False))
    failed_commands = total_commands - successful_commands
    total_execution_time = sum(r.get("execution_time", 0) for r in results)

    success_rate = (successful_commands / total_commands * 100) if total_commands > 0 else 0

    return {
        "total_commands": total_commands,
        "successful_commands": successful_commands,
        "failed_commands": failed_commands,
        "success_rate": success_rate,
        "total_execution_time": total_execution_time,
    }


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
    import logging

    logger = logging.getLogger(__name__)

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
    import logging
    import os
    import shlex

    logger = logging.getLogger(__name__)

    try:
        from startScan.models import ScanHistory

        scan = ScanHistory.objects.get(pk=scan_id)
    except Exception as e:
        logger.warning(f"Error retrieving scan {scan_id}: {e}. DNS wrapper not applied.")
        return cmd

    try:
        domain = scan.domain
    except Exception as e:
        logger.warning(f"Error accessing domain for scan {scan_id}: {e}. DNS wrapper not applied.")
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
    except Exception as e:
        logger.warning(f"Error building DNS command for '{cmd}': {e}. Returning original command.")
        return cmd


def build_command_with_dns(tool_name, args, domain=None, dns_servers=None):
    """
    Build command with DNS server arguments for specific tools.

    Args:
        tool_name (str): Name of the tool
        args (list): Original command arguments
        domain: Domain object with DNS servers (optional)
        dns_servers: List of DNS servers (optional)

    Returns:
        list: Command parts with DNS arguments added
    """
    import logging

    logger = logging.getLogger(__name__)

    # Get DNS servers from domain or direct parameter
    if dns_servers is not None:
        dns_servers = dns_servers
    elif domain is not None:
        dns_servers = domain.get_dns_servers()
    else:
        dns_servers = []

    # Handle string input (convert to list)
    if isinstance(dns_servers, str):
        dns_servers = [dns_servers]

    # Filter out empty/None values
    dns_servers = [s for s in dns_servers if s and str(s).strip()]

    if not dns_servers:
        return [tool_name] + (args or [])

    # Tool-specific DNS argument patterns
    dns_patterns = {
        "nmap": ["--dns-servers", ",".join(dns_servers)],
        "httpx": ["-dns", ",".join(dns_servers)],
        "subfinder": ["-r", ",".join(dns_servers)],
        "amass": ["-dns", ",".join(dns_servers)],
        "dnsrecon": ["-s", ",".join(dns_servers)],
        "dig": [f"@{dns_servers[0]}"] if dns_servers else [],
        "nslookup": [dns_servers[0]] if dns_servers else [],
    }

    if tool_name in dns_patterns:
        return [tool_name] + dns_patterns[tool_name] + (args or [])
    # Generic fallback - try to add DNS servers as arguments
    logger.debug(f"No specific DNS pattern for {tool_name}, using generic approach")
    return [tool_name] + (args or [])
