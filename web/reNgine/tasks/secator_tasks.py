"""
Secator Celery tasks for reNgine.

This module contains Celery tasks that integrate with Secator for orchestrated scanning.
Secator will handle the creation and orchestration of individual tool tasks.
"""

from typing import Any, Dict, List, Optional

from celery import shared_task
from celery.utils.log import get_task_logger

from reNgine.core.validators import is_valid_domain, is_valid_ip
from reNgine.secator import SecatorParser, SecatorRunner
from reNgine.services.scan.scan_orchestrator import ScanOrchestrator
from scanEngine.models import SecatorScan, SecatorTask, SecatorWorkflow
from startScan.models import ScanHistory


logger = get_task_logger(__name__)


@shared_task(bind=True)
def initiate_secator_scan(
    self, scan_history_id: int, scan_config_id: int, targets: List[str], domain_id: Optional[int]
) -> Dict[str, Any]:
    """
    Initiate a Secator-based scan using ScanOrchestrator.

    This task replaces the old initiate_scan for new Secator-based scans.
    Uses ScanOrchestrator to coordinate execution with proper hooks.

    Args:
        scan_history_id: ID of the ScanHistory record
        scan_config_id: ID of the SecatorScan configuration
        targets: List of target URLs/domains/IPs
        domain_id: ID of the domain

    Returns:
        Dictionary containing scan results and metadata
    """
    try:
        # Validate input parameters
        if domain_id is None:
            raise ValueError("domain_id is required and cannot be None")

        if not isinstance(domain_id, int) or domain_id <= 0:
            raise ValueError(f"domain_id must be a positive integer, got: {domain_id}")

        if not targets or not isinstance(targets, list):
            raise ValueError("targets must be a non-empty list")

        for t in targets:
            if not isinstance(t, str) or not t.strip():
                raise ValueError(f"Each target must be a non-empty string, got: {t!r}")
            t_stripped = t.strip()
            if not (is_valid_domain(t_stripped) or is_valid_ip(t_stripped)):
                raise ValueError(f"Target '{t}' is not a valid domain or IP address")

        if not isinstance(scan_history_id, int) or scan_history_id <= 0:
            raise ValueError(f"scan_history_id must be a positive integer, got: {scan_history_id}")

        if not isinstance(scan_config_id, int) or scan_config_id <= 0:
            raise ValueError(f"scan_config_id must be a positive integer, got: {scan_config_id}")

        logger.info(f"Starting Secator scan for ScanHistory {scan_history_id} with domain_id {domain_id}")

        scan_history = ScanHistory.objects.get(id=scan_history_id)
        scan_config = SecatorScan.objects.get(id=scan_config_id)

        scan_history.scan_status = 1
        scan_history.celery_ids = [self.request.id]
        scan_history.save()

        orchestrator = ScanOrchestrator()

        config = {}
        # TODO: Implement speed/stealth profiles configuration
        profiles = {}

        if scan_config.execution_mode == "workflow" and scan_config.workflow:
            config["workflow_name"] = scan_config.workflow.name
        elif scan_config.execution_mode == "tasks":
            config["tasks"] = [task.task_type for task in scan_config.tasks.all()]
        elif scan_config.execution_mode == "scan":
            config["scan_type"] = scan_config.secator_scan_type
        else:
            raise ValueError(f"Invalid execution mode: {scan_config.execution_mode}")

        result = orchestrator.execute_scan(
            scan_history_id=scan_history_id,
            domain_id=domain_id,
            execution_mode=scan_config.execution_mode,
            targets=targets,
            config=config,
            profiles=profiles,
        )

        if result.get("status") == "success":
            scan_history.scan_status = 2
            logger.info(f"Secator scan {scan_history_id} completed successfully")
        else:
            scan_history.scan_status = 3
            scan_history.error_message = result.get("error", "Unknown error")
            logger.error(f"Secator scan {scan_history_id} failed: {result.get('error')}")

        scan_history.save()

        return {
            "status": "success",
            "scan_history_id": scan_history_id,
            "result": result,
        }

    except Exception as e:
        logger.error(f"Error in initiate_secator_scan: {e}")

        try:
            scan_history = ScanHistory.objects.get(id=scan_history_id)
            scan_history.scan_status = 3
            scan_history.error_message = str(e)
            scan_history.save()
        except ScanHistory.DoesNotExist:
            logger.error(f"ScanHistory with id {scan_history_id} not found when trying to save error state")
        except Exception as save_error:
            logger.error(f"Database error when saving error state for scan_history_id {scan_history_id}: {save_error}")

        return {
            "status": "error",
            "scan_history_id": scan_history_id,
            "error": str(e),
        }


@shared_task(bind=True)
def run_secator_workflow(
    self, workflow_name: str, targets: List[str], config: Dict[str, Any], scan_history_id: Optional[int] = None
) -> Dict[str, Any]:
    """
    Run a specific Secator workflow.

    Args:
        workflow_name: Name of the Secator workflow to run
        targets: List of target URLs/domains/IPs
        config: Configuration dictionary
        scan_history_id: Optional scan history ID for tracking

    Returns:
        Dictionary containing execution results
    """
    try:
        logger.info(f"Running Secator workflow: {workflow_name}")

        runner = SecatorRunner()
        parser = SecatorParser()

        # Prepare callback for results
        def result_callback(result):
            """Callback to process Secator results."""
            try:
                if scan_history_id:
                    parsed_results = parser.parse_batch(result.get("results", []))
                    saved_count = parser.save_results(parsed_results, scan_history_id)
                    logger.info(f"Saved {saved_count} results from workflow {workflow_name}")
            except Exception as e:
                logger.error(f"Error processing workflow results: {e}")

        # Run the workflow
        result = runner.run_workflow(
            workflow_name=workflow_name,
            targets=targets,
            config=config,
            callback=result_callback,
            scan_history_id=scan_history_id,
        )

        return result

    except Exception as e:
        logger.error(f"Error running Secator workflow {workflow_name}: {e}")
        return {
            "status": "error",
            "workflow_name": workflow_name,
            "error": str(e),
        }


@shared_task(bind=True)
def run_secator_tasks(
    self, task_names: List[str], targets: List[str], config: Dict[str, Any], scan_history_id: Optional[int] = None
) -> Dict[str, Any]:
    """
    Run specific Secator tasks.

    Args:
        task_names: List of Secator task names to run
        targets: List of target URLs/domains/IPs
        config: Configuration dictionary
        scan_history_id: Optional scan history ID for tracking

    Returns:
        Dictionary containing execution results
    """
    try:
        logger.info(f"Running Secator tasks: {task_names}")

        runner = SecatorRunner()
        parser = SecatorParser()

        # Prepare callback for results
        def result_callback(result):
            """Callback to process Secator results."""
            try:
                if scan_history_id:
                    parsed_results = parser.parse_batch(result.get("results", []))
                    saved_count = parser.save_results(parsed_results, scan_history_id)
                    logger.info(f"Saved {saved_count} results from tasks {task_names}")
            except Exception as e:
                logger.error(f"Error processing task results: {e}")

        # Run the tasks
        result = runner.run_tasks(
            tasks=task_names,
            targets=targets,
            config=config,
            callback=result_callback,
            scan_history_id=scan_history_id,
        )

        return result

    except Exception as e:
        logger.error(f"Error running Secator tasks {task_names}: {e}")
        return {
            "status": "error",
            "task_names": task_names,
            "error": str(e),
        }


@shared_task
def load_secator_workflows() -> Dict[str, Any]:
    """
    Load built-in Secator workflows into the database.

    Returns:
        Dictionary containing loading results
    """
    try:
        logger.info("Loading Secator workflows")

        runner = SecatorRunner()
        workflows = runner.get_builtin_workflows()

        loaded_count = 0
        for workflow_data in workflows:
            workflow, created = SecatorWorkflow.objects.get_or_create(
                name=workflow_data["name"],
                defaults={
                    "description": workflow_data.get("description", ""),
                    "workflow_type": "builtin",
                    "yaml_configuration": workflow_data.get("yaml_config", ""),
                    "scan_type": workflow_data.get("scan_type", "bug_bounty"),
                    "is_active": True,
                },
            )

            if created:
                loaded_count += 1

        logger.info(f"Loaded {loaded_count} built-in Secator workflows")

        return {
            "status": "success",
            "loaded_count": loaded_count,
            "total_workflows": len(workflows),
        }

    except Exception as e:
        logger.error(f"Error loading Secator workflows: {e}")
        return {
            "status": "error",
            "error": str(e),
        }


@shared_task
def load_secator_tasks() -> Dict[str, Any]:
    """
    Load built-in Secator tasks into the database.

    Returns:
        Dictionary containing loading results
    """
    try:
        logger.info("Loading Secator tasks")

        runner = SecatorRunner()
        tasks = runner.get_builtin_tasks()

        loaded_count = 0
        for task_data in tasks:
            task, created = SecatorTask.objects.get_or_create(
                name=task_data["name"],
                task_type=task_data["type"],
                defaults={
                    "description": task_data.get("description", ""),
                    "is_builtin": True,
                    "yaml_configuration": task_data.get("yaml_config", ""),
                },
            )

            if created:
                loaded_count += 1

        logger.info(f"Loaded {loaded_count} built-in Secator tasks")

        return {
            "status": "success",
            "loaded_count": loaded_count,
            "total_tasks": len(tasks),
        }

    except Exception as e:
        logger.error(f"Error loading Secator tasks: {e}")
        return {
            "status": "error",
            "error": str(e),
        }
