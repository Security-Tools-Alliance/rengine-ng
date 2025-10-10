"""
Distributed command execution utilities.

This module provides distributed command execution capabilities that can be
reused across different task types while following SOLID, KISS, and DRY principles.

Key components:
1. DistributedCommandProcessor - Base class for distributed command processing
2. DistributedCommandExecutor - Generic command executor for batch operations
3. DistributedCommandBuilder - Command builder with distributed support
4. DistributedCommandResult - Result handling for command execution
"""

import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

from celery.utils.log import get_task_logger

from reNgine.utilities.core.file import file_exists
from reNgine.utilities.database_interface import DatabaseInterface
from reNgine.utilities.distributed.base import (
    DistributedCommandProcessor,
    DistributedConfig,
    DistributedResult,
    ProcessingStatus,
    aggregate_distributed_results,
    create_batch_tasks,
    create_distributed_config,
    validate_distributed_input,
)
from reNgine.utilities.dns_wrapper import build_command_with_dns


logger = get_task_logger(__name__)


class DistributedCommandResult(DistributedResult[Dict[str, Any]]):
    """Result container for distributed command execution"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.commands_executed: List[str] = []
        self.output_files: List[str] = []
        self.return_codes: List[int] = []

    def add_command_result(self, command: str, return_code: int, output_file: Optional[str] = None) -> None:
        """Add a command execution result"""
        self.commands_executed.append(command)
        self.return_codes.append(return_code)
        if output_file:
            self.output_files.append(output_file)


class DistributedCommandBuilder:
    """Command builder with distributed support"""

    def __init__(self, base_command: str = ""):
        self.base_command = base_command
        self.options: Dict[str, Any] = {}
        self.flags: List[str] = []
        self.input_files: List[str] = []
        self.output_files: List[str] = []
        self.arguments: List[str] = []

    def add_option(self, key: str, value: Any, separator: str = " ") -> "DistributedCommandBuilder":
        """Add an option to the command"""
        if value is not None and value != "":
            self.options[key] = value
        return self

    def add_flag(self, flag: str) -> "DistributedCommandBuilder":
        """Add a flag to the command"""
        if flag:
            self.flags.append(flag)
        return self

    def add_input_file(self, file_path: str) -> "DistributedCommandBuilder":
        """Add an input file to the command"""
        if file_path and file_exists(file_path):
            self.input_files.append(file_path)
        return self

    def add_output_file(self, file_path: str) -> "DistributedCommandBuilder":
        """Add an output file to the command"""
        if file_path:
            self.output_files.append(file_path)
        return self

    def add_argument(self, argument: str) -> "DistributedCommandBuilder":
        """Add an argument to the command"""
        if argument:
            self.arguments.append(argument)
        return self

    def build(self) -> str:
        """Build the final command string"""
        cmd = self.base_command

        # Add options
        for key, value in self.options.items():
            cmd += f" {key}{' ' if '=' not in key else ''}{value}"

        # Add flags
        for flag in self.flags:
            cmd += f" --{flag}"

        # Add input files
        for input_file in self.input_files:
            cmd += f" -i {input_file}"

        # Add output files
        for output_file in self.output_files:
            cmd += f" -o {output_file}"

        # Add arguments
        for argument in self.arguments:
            cmd += f" {argument}"

        return cmd.strip()

    def build_for_batch(self, batch_items: List[str], batch_id: str) -> Tuple[str, str]:
        """Build command for batch processing"""
        # Create temporary input file for batch
        input_file = f"/tmp/batch_{batch_id}_input.txt"
        with open(input_file, "w") as f:
            f.write("\n".join(batch_items))

        # Add input file to command
        self.add_input_file(input_file)

        # Create output file for batch
        output_file = f"/tmp/batch_{batch_id}_output.txt"
        self.add_output_file(output_file)

        return self.build(), input_file


class DistributedCommandExecutor(DistributedCommandProcessor):
    """Distributed command executor for batch operations"""

    def __init__(self, config: Optional[DistributedConfig] = None, db_interface: Optional[DatabaseInterface] = None):
        super().__init__(config)
        self.db_interface = db_interface
        self.command_builders: Dict[str, DistributedCommandBuilder] = {}
        self.execution_history: Dict[str, List[Dict[str, Any]]] = {}

    def get_task_name(self) -> str:
        return "distributed_command_executor"

    def create_command_builder(self, base_command: str, batch_id: str) -> DistributedCommandBuilder:
        """Create a command builder for a batch"""
        builder = DistributedCommandBuilder(base_command)
        self.command_builders[batch_id] = builder
        return builder

    def execute_command_batch(
        self,
        commands: List[str],
        batch_id: str,
        scan_id: Optional[int] = None,
        activity_id: Optional[int] = None,
        **kwargs,
    ) -> DistributedCommandResult:
        """Execute a batch of commands"""
        start_time = time.time()
        self.log_processing_start(batch_id, len(commands))

        result = DistributedCommandResult(data={}, status=ProcessingStatus.IN_PROGRESS, batch_id=batch_id)

        try:
            with self.safe_execution():
                executed_commands = []
                output_files = []
                return_codes = []
                errors = []

                for i, command in enumerate(commands):
                    try:
                        # Record command
                        self.record_command(batch_id, command)

                        # Execute command
                        cmd_result = self._execute_single_command(
                            command, scan_id=scan_id, activity_id=activity_id, **kwargs
                        )

                        executed_commands.append(command)
                        return_codes.append(cmd_result["return_code"])

                        if cmd_result.get("output_file"):
                            output_files.append(cmd_result["output_file"])

                        if cmd_result["return_code"] != 0:
                            error_msg = f"Command failed with return code {cmd_result['return_code']}: {command}"
                            errors.append(error_msg)
                            logger.warning(error_msg)

                    except Exception as e:
                        error_msg = f"Error executing command '{command}': {str(e)}"
                        errors.append(error_msg)
                        logger.error(error_msg)
                        return_codes.append(-1)

                # Update result
                result.data = {
                    "commands": executed_commands,
                    "output_files": output_files,
                    "return_codes": return_codes,
                    "success_count": sum(1 for rc in return_codes if rc == 0),
                    "failure_count": sum(1 for rc in return_codes if rc != 0),
                }

                result.commands_executed = executed_commands
                result.output_files = output_files
                result.return_codes = return_codes
                result.errors = errors
                result.status = ProcessingStatus.COMPLETED if not errors else ProcessingStatus.FAILED
                result.processing_time = time.time() - start_time

                # Record execution history
                self.execution_history[batch_id] = {
                    "commands": executed_commands,
                    "return_codes": return_codes,
                    "errors": errors,
                    "processing_time": result.processing_time,
                }

        except Exception as e:
            result.status = ProcessingStatus.FAILED
            result.errors = [str(e)]
            result.processing_time = time.time() - start_time
            logger.error(f"Batch execution failed for {batch_id}: {e}")

        self.log_processing_completion(batch_id, result.is_successful, result.processing_time)
        return result

    def _execute_single_command(
        self, command: str, scan_id: Optional[int] = None, activity_id: Optional[int] = None, **kwargs
    ) -> Dict[str, Any]:
        """Execute a single command"""
        try:
            # Create command object for tracking
            command_obj = None
            if scan_id and self.db_interface:
                command_data = {
                    "command": command,
                    "scan_history_id": scan_id,
                    "activity_id": activity_id,
                    "output": "",
                    "error_output": "",
                    "return_code": 0,
                }
                command_obj = self.db_interface.create_record("command", command_data)

            # Prepare command with DNS wrapper if needed
            if scan_id:
                command = build_command_with_dns(command)

            # Execute command
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True
            )

            stdout, stderr = process.communicate()
            return_code = process.returncode

            # Update command object
            if command_obj and self.db_interface:
                update_data = {"output": stdout, "error_output": stderr, "return_code": return_code}
                self.db_interface.update_record("command", command_obj.id, update_data)

            return {"return_code": return_code, "stdout": stdout, "stderr": stderr, "command": command}

        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return {"return_code": -1, "stdout": "", "stderr": str(e), "command": command}

    def execute_nmap_batch(
        self,
        targets: List[str],
        batch_id: str,
        ports: Optional[List[int]] = None,
        script: Optional[str] = None,
        output_format: str = "xml",
        **kwargs,
    ) -> DistributedCommandResult:
        """Execute nmap commands in batch"""
        commands = []

        for target in targets:
            builder = self.create_command_builder("nmap", batch_id)

            # Add common nmap options
            builder.add_flag("n")
            builder.add_option("-sS", None)  # SYN scan
            builder.add_option("-T4", None)  # Timing template

            # Add ports if specified
            if ports:
                port_list = ",".join(map(str, ports))
                builder.add_option("-p", port_list)

            # Add script if specified
            if script:
                builder.add_option("--script", script)

            # Add output format
            if output_format == "xml":
                builder.add_flag("oX")
            elif output_format == "json":
                builder.add_flag("oJ")

            # Add target
            builder.add_argument(target)

            commands.append(builder.build())

        return self.execute_command_batch(commands, batch_id, **kwargs)

    def execute_httpx_batch(
        self, urls: List[str], batch_id: str, threads: int = 10, follow_redirect: bool = False, **kwargs
    ) -> DistributedCommandResult:
        """Execute httpx commands in batch"""
        commands = []

        for url in urls:
            builder = self.create_command_builder("/home/rengine/tools/go/bin/httpx", batch_id)

            # Add httpx options
            builder.add_flag("cl")  # Content length
            builder.add_flag("ct")  # Content type
            builder.add_flag("rt")  # Response time
            builder.add_flag("location")  # Location header
            builder.add_flag("td")  # Title
            builder.add_flag("websocket")  # WebSocket
            builder.add_flag("cname")  # CNAME
            builder.add_flag("asn")  # ASN
            builder.add_flag("cdn")  # CDN
            builder.add_flag("probe")  # Probe
            builder.add_flag("random-agent")  # Random user agent
            builder.add_flag("nfs")  # No follow redirects by default
            builder.add_flag("json")  # JSON output
            builder.add_flag("silent")  # Silent mode

            # Add threads
            builder.add_option("-t", threads)

            # Add follow redirects if requested
            if follow_redirect:
                builder.add_flag("fr")

            # Add URL
            builder.add_argument(url)

            commands.append(builder.build())

        return self.execute_command_batch(commands, batch_id, **kwargs)

    def execute_subfinder_batch(
        self, domains: List[str], batch_id: str, sources: Optional[List[str]] = None, **kwargs
    ) -> DistributedCommandResult:
        """Execute subfinder commands in batch"""
        commands = []

        for domain in domains:
            builder = self.create_command_builder("/home/rengine/tools/go/bin/subfinder", batch_id)

            # Add subfinder options
            builder.add_flag("silent")  # Silent mode
            builder.add_flag("json")  # JSON output

            # Add sources if specified
            if sources:
                builder.add_option("-sources", ",".join(sources))

            # Add domain
            builder.add_argument(domain)

            commands.append(builder.build())

        return self.execute_command_batch(commands, batch_id, **kwargs)

    def get_execution_summary(self, batch_id: str) -> Dict[str, Any]:
        """Get execution summary for a batch"""
        history = self.execution_history.get(batch_id, {})
        if not history:
            return {"error": "No execution history found for batch"}

        return {
            "batch_id": batch_id,
            "total_commands": len(history.get("commands", [])),
            "successful_commands": sum(1 for rc in history.get("return_codes", []) if rc == 0),
            "failed_commands": sum(1 for rc in history.get("return_codes", []) if rc != 0),
            "processing_time": history.get("processing_time", 0),
            "errors": history.get("errors", []),
        }


# Utility functions for distributed command execution


def create_distributed_command_executor(
    batch_size: int = 15, worker_timeout: int = 300, db_interface: Optional[DatabaseInterface] = None, **kwargs
) -> DistributedCommandExecutor:
    """Create a distributed command executor with common defaults"""
    config = create_distributed_config(batch_size=batch_size, worker_timeout=worker_timeout, **kwargs)
    return DistributedCommandExecutor(config, db_interface)


def execute_commands_distributed(
    commands: List[str],
    executor: Optional[DistributedCommandExecutor] = None,
    db_interface: Optional[DatabaseInterface] = None,
    **kwargs,
) -> List[DistributedCommandResult]:
    """Execute commands in a distributed manner"""
    if not validate_distributed_input(commands):
        return []

    if executor is None:
        executor = create_distributed_command_executor(db_interface=db_interface)

    # Create batch tasks
    batch_tasks = create_batch_tasks(commands, executor.execute_command_batch, executor.config.batch_size, **kwargs)

    if not batch_tasks:
        return []

    # Execute batches in parallel
    try:
        from reNgine.utilities.deadlock_prevention import safe_group_execution

        results = safe_group_execution(batch_tasks, executor.config.worker_timeout * len(batch_tasks))
        return results
    except Exception as e:
        logger.error(f"Distributed command execution failed: {e}")
        return []


def execute_nmap_distributed(
    targets: List[str],
    ports: Optional[List[int]] = None,
    script: Optional[str] = None,
    db_interface: Optional[DatabaseInterface] = None,
    **kwargs,
) -> Dict[str, Any]:
    """Execute nmap commands in a distributed manner"""
    if not validate_distributed_input(targets):
        return {"success": False, "error": "Invalid input"}

    executor = create_distributed_command_executor(db_interface=db_interface)

    # Create batch tasks for nmap
    batch_tasks = []
    for i in range(0, len(targets), executor.config.batch_size):
        batch = targets[i : i + executor.config.batch_size]
        batch_id = f"nmap_batch_{i // executor.config.batch_size + 1}"
        task = executor.execute_nmap_batch.si(batch, batch_id, ports, script, **kwargs)
        batch_tasks.append(task)

    # Execute batches
    try:
        from reNgine.utilities.deadlock_prevention import safe_group_execution

        results = safe_group_execution(batch_tasks, executor.config.worker_timeout * len(batch_tasks))

        # Aggregate results
        return aggregate_distributed_results(results)
    except Exception as e:
        logger.error(f"Distributed nmap execution failed: {e}")
        return {"success": False, "error": str(e)}


def execute_httpx_distributed(
    urls: List[str],
    threads: int = 10,
    follow_redirect: bool = False,
    db_interface: Optional[DatabaseInterface] = None,
    **kwargs,
) -> Dict[str, Any]:
    """Execute httpx commands in a distributed manner"""
    if not validate_distributed_input(urls):
        return {"success": False, "error": "Invalid input"}

    executor = create_distributed_command_executor(db_interface=db_interface)

    # Create batch tasks for httpx
    batch_tasks = []
    for i in range(0, len(urls), executor.config.batch_size):
        batch = urls[i : i + executor.config.batch_size]
        batch_id = f"httpx_batch_{i // executor.config.batch_size + 1}"
        task = executor.execute_httpx_batch.si(batch, batch_id, threads, follow_redirect, **kwargs)
        batch_tasks.append(task)

    # Execute batches
    try:
        from reNgine.utilities.deadlock_prevention import safe_group_execution

        results = safe_group_execution(batch_tasks, executor.config.worker_timeout * len(batch_tasks))

        # Aggregate results
        return aggregate_distributed_results(results)
    except Exception as e:
        logger.error(f"Distributed httpx execution failed: {e}")
        return {"success": False, "error": str(e)}


def execute_subfinder_distributed(
    domains: List[str], sources: Optional[List[str]] = None, db_interface: Optional[DatabaseInterface] = None, **kwargs
) -> Dict[str, Any]:
    """Execute subfinder commands in a distributed manner"""
    if not validate_distributed_input(domains):
        return {"success": False, "error": "Invalid input"}

    executor = create_distributed_command_executor(db_interface=db_interface)

    # Create batch tasks for subfinder
    batch_tasks = []
    for i in range(0, len(domains), executor.config.batch_size):
        batch = domains[i : i + executor.config.batch_size]
        batch_id = f"subfinder_batch_{i // executor.config.batch_size + 1}"
        task = executor.execute_subfinder_batch.si(batch, batch_id, sources, **kwargs)
        batch_tasks.append(task)

    # Execute batches
    try:
        from reNgine.utilities.deadlock_prevention import safe_group_execution

        results = safe_group_execution(batch_tasks, executor.config.worker_timeout * len(batch_tasks))

        # Aggregate results
        return aggregate_distributed_results(results)
    except Exception as e:
        logger.error(f"Distributed subfinder execution failed: {e}")
        return {"success": False, "error": str(e)}
