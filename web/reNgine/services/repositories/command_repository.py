"""
Command Repository - Data access for command log operations.
Handles Command database operations from Secator runner data.
"""

from datetime import datetime
from typing import Any, Dict, Optional

from celery.utils.log import get_task_logger
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError
from django.utils import timezone

from reNgine.utilities.time import parse_datetime_iso
from startScan.models import Command, ScanActivity, ScanHistory


logger = get_task_logger(__name__)


class CommandRepository:
    """Repository for command log-related database operations."""

    def save_from_secator(
        self, runner_data: Dict[str, Any], scan_history_id: int, activity_id: Optional[int] = None
    ) -> Optional[Command]:
        """
        Save command log from Secator runner data.

        Args:
            runner_data: Secator runner data dictionary
            scan_history_id: ID of the scan history
            activity_id: Optional ID of the scan activity

        Returns:
            Command: Saved Command object or None
        """
        try:
            return self._process_secator_runner_data(runner_data, scan_history_id, activity_id)
        except ObjectDoesNotExist as e:
            logger.error(f"Object not found when saving command: {e}")
            return None
        except IntegrityError as e:
            logger.error(f"Integrity error saving command: {e}")
            return None
        except Exception as e:
            logger.error(f"Error saving command from Secator: {e}")
            return None

    def _process_secator_runner_data(
        self, runner_data: Dict[str, Any], scan_history_id: int, activity_id: Optional[int] = None
    ) -> Optional[Command]:
        """
        Process Secator runner data and create or update Command.

        Args:
            runner_data: Secator runner data dictionary
            scan_history_id: ID of the scan history
            activity_id: Optional ID of the scan activity

        Returns:
            Command: Created or updated Command object
        """
        # Extract command data from runner_data
        cmd = runner_data.get("cmd")
        output = runner_data.get("output")
        return_code = runner_data.get("return_code")
        start_time_str = runner_data.get("start_time")
        end_time_str = runner_data.get("end_time")
        elapsed = runner_data.get("elapsed")
        errors = runner_data.get("errors", [])
        warnings = runner_data.get("warnings", [])
        name = runner_data.get("name") or runner_data.get("config", {}).get("name")
        status = runner_data.get("status")
        cwd = runner_data.get("cwd")

        # Extract hierarchy fields
        runner_type = runner_data.get("config", {}).get("type")
        has_parent = runner_data.get("has_parent", False)
        has_children = runner_data.get("has_children", False)
        # workflow_name from run_opts.workflow_name or config.name if it's a workflow
        workflow_name = runner_data.get("run_opts", {}).get("workflow_name")
        if not workflow_name and runner_type == "workflow":
            workflow_name = runner_data.get("config", {}).get("name")
        # node_id from context.node_id or config.node_id
        node_id = runner_data.get("context", {}).get("node_id") or runner_data.get("config", {}).get("node_id")
        # ancestor_id from context.ancestor_id
        ancestor_id = runner_data.get("context", {}).get("ancestor_id")
        # scan_type from run_opts.scan_type
        scan_type = runner_data.get("run_opts", {}).get("scan_type")

        # Validate required fields
        if not cmd and not output:
            logger.warning("Command data missing both cmd and output fields")
            return None

        # Get scan history
        try:
            scan_history = ScanHistory.objects.get(id=scan_history_id)
        except ScanHistory.DoesNotExist:
            logger.error(f"ScanHistory with ID {scan_history_id} not found")
            return None

        # Get activity if provided
        activity = None
        if activity_id:
            try:
                activity = ScanActivity.objects.get(id=activity_id)
            except ScanActivity.DoesNotExist:
                logger.warning(f"ScanActivity with ID {activity_id} not found, continuing without activity link")

        # Parse start_time
        start_time = parse_datetime_iso(start_time_str)
        if not start_time:
            start_time = timezone.now()

        # Parse end_time
        end_time = parse_datetime_iso(end_time_str)

        # Store elapsed as float (Secator sends float values)
        elapsed_float = None
        if elapsed is not None:
            try:
                if isinstance(elapsed, (int, float)):
                    elapsed_float = float(elapsed)
            except (ValueError, TypeError) as e:
                logger.warning(f"Error converting elapsed '{elapsed}' to float: {e}")

        # Ensure errors and warnings are lists
        if not isinstance(errors, list):
            errors = [errors] if errors else []
        if not isinstance(warnings, list):
            warnings = [warnings] if warnings else []

        # Try to find existing command to update
        # Use scan_history + name + start_time as unique identifier
        existing_command = None
        if name and start_time:
            try:
                existing_command = Command.objects.filter(scan_history=scan_history, name=name, time=start_time).first()
            except Exception as e:
                logger.debug(f"Error checking for existing command: {e}")

        if existing_command:
            # Update existing command
            if cmd:
                existing_command.command = cmd
            if output:
                existing_command.output = output
            existing_command.return_code = return_code if return_code is not None else existing_command.return_code
            existing_command.end_time = end_time or existing_command.end_time
            existing_command.elapsed = elapsed_float if elapsed_float is not None else existing_command.elapsed
            existing_command.errors = errors or existing_command.errors
            existing_command.warnings = warnings or existing_command.warnings
            existing_command.status = status or existing_command.status
            existing_command.cwd = cwd or existing_command.cwd
            if runner_type:
                existing_command.runner_type = runner_type
            existing_command.has_parent = has_parent
            existing_command.has_children = has_children
            if workflow_name:
                existing_command.workflow_name = workflow_name
            if node_id:
                existing_command.node_id = node_id
            if ancestor_id:
                existing_command.ancestor_id = ancestor_id
            if scan_type:
                existing_command.scan_type = scan_type
            if activity:
                existing_command.activity = activity
            existing_command.save()
            logger.debug(f"Updated Command {existing_command.id} for runner {name}")
            return existing_command
        else:
            # Create new command
            command = Command.objects.create(
                scan_history=scan_history,
                activity=activity,
                command=cmd,
                return_code=return_code,
                output=output,
                time=start_time,
                end_time=end_time,
                elapsed=elapsed_float,
                errors=errors,
                warnings=warnings,
                name=name,
                status=status,
                cwd=cwd,
                runner_type=runner_type,
                has_parent=has_parent,
                has_children=has_children,
                workflow_name=workflow_name,
                node_id=node_id,
                ancestor_id=ancestor_id,
                scan_type=scan_type,
            )
            logger.info(f"Created Command {command.id} for runner {name}")
            return command

    def get_commands_for_scan(self, scan_history_id: int) -> list[Command]:
        """
        Get all commands for a scan history.

        Args:
            scan_history_id: ID of the scan history

        Returns:
            list: List of Command objects
        """
        try:
            return list(Command.objects.filter(scan_history_id=scan_history_id).order_by("time"))
        except Exception as e:
            logger.error(f"Error getting commands for scan {scan_history_id}: {e}")
            return []

    def get_commands_for_activity(self, activity_id: int) -> list[Command]:
        """
        Get all commands for a scan activity.

        Args:
            activity_id: ID of the scan activity

        Returns:
            list: List of Command objects
        """
        try:
            return list(Command.objects.filter(activity_id=activity_id).order_by("time"))
        except Exception as e:
            logger.error(f"Error getting commands for activity {activity_id}: {e}")
            return []
