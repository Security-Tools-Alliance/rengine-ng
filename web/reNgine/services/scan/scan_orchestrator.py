"""
Scan orchestration service - highest layer.
Coordinates scan execution using Secator or legacy engines.
"""

from typing import Any, Dict, List

from celery.utils.log import get_task_logger

from reNgine.secator.runner import SecatorRunner
from reNgine.services.repositories.scan_repository import ScanRepository


logger = get_task_logger(__name__)


class ScanOrchestrator:
    """
    Orchestrates scan execution.
    This is the top-level service called by Celery tasks.
    """

    def __init__(self):
        """Initialize the scan orchestrator."""
        self.secator_runner = SecatorRunner()
        self.scan_repo = ScanRepository()

    def execute_scan(
        self,
        scan_history_id: int,
        domain_id: int,
        execution_mode: str,
        targets: List[str],
        config: Dict[str, Any],
        profiles: Dict[str, str] = None,
    ):
        """
        Execute a scan using appropriate method.

        Args:
            scan_history_id: ID of scan history
            domain_id: ID of domain
            execution_mode: 'workflow', 'tasks', or 'scan'
            targets: List of targets
            config: Scan configuration
            profiles: Speed/stealth profiles

        Returns:
            dict: Scan execution results
        """
        try:
            if execution_mode == "workflow":
                return self._execute_workflow(scan_history_id, domain_id, targets, config, profiles)
            elif execution_mode == "tasks":
                return self._execute_tasks(scan_history_id, domain_id, targets, config, profiles)
            elif execution_mode == "scan":
                return self._execute_scan_type(scan_history_id, domain_id, targets, config, profiles)
            else:
                raise ValueError(f"Unknown execution mode: {execution_mode}")

        except ValueError as e:
            # Configuration or validation errors - these are expected and should be handled gracefully
            logger.error(f"Configuration error in scan execution: {e}")
            self.scan_repo.mark_scan_failed(scan_history_id, str(e))
            raise
        except Exception as e:
            # Unexpected errors - log with full context and re-raise
            logger.exception(f"Unexpected error executing scan {scan_history_id}: {e}")
            try:
                self.scan_repo.mark_scan_failed(scan_history_id, str(e))
            except Exception as db_error:
                logger.error(f"Failed to mark scan as failed in database: {db_error}")
            raise

    def _execute_workflow(
        self,
        scan_history_id: int,
        domain_id: int,
        targets: List[str],
        config: Dict[str, Any],
        profiles: Dict[str, str] = None,
    ):
        """Execute Secator workflow."""
        workflow_name = config.get("workflow_name")
        if not workflow_name:
            raise ValueError("workflow_name is required in config")

        return self.secator_runner.run_workflow(
            workflow_name=workflow_name,
            targets=targets,
            scan_history_id=scan_history_id,
            domain_id=domain_id,
            config=config,
            profiles=profiles,
        )

    def _execute_tasks(
        self,
        scan_history_id: int,
        domain_id: int,
        targets: List[str],
        config: Dict[str, Any],
        profiles: Dict[str, str] = None,
    ):
        """Execute multiple Secator tasks."""
        tasks = config.get("tasks", [])
        if not tasks:
            raise ValueError("tasks list is required in config")

        logger.info(f"Executing {len(tasks)} Secator tasks")

        return self.secator_runner.run_tasks(
            task_names=tasks,
            targets=targets,
            scan_history_id=scan_history_id,
            domain_id=domain_id,
            config=config,
            profiles=profiles,
        )

    def _execute_scan_type(
        self,
        scan_history_id: int,
        domain_id: int,
        targets: List[str],
        config: Dict[str, Any],
        profiles: Dict[str, str] = None,
    ):
        """Execute Secator scan type."""
        scan_type = config.get("scan_type")
        if not scan_type:
            raise ValueError("scan_type is required in config")

        logger.info(f"Executing Secator scan type: {scan_type}")
        return self.secator_runner.run_scan(
            scan_type=scan_type,
            targets=targets,
            scan_history_id=scan_history_id,
            domain_id=domain_id,
            config=config,
            profiles=profiles,
        )
