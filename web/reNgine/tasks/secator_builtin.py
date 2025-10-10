"""
Celery tasks for executing Secator built-in workflows.

This module provides Celery tasks for running Secator's built-in workflows
within reNgine's distributed processing system.
"""

from typing import Any, Dict, Optional

from celery.utils.log import get_task_logger

from reNgine.celery import app
from reNgine.tasks import RengineTask
from reNgine.utilities.secator_integration.builtin_workflows import SecatorBuiltinWorkflowManager


logger = get_task_logger(__name__)


@app.task(name="execute_secator_builtin_workflow", queue="orchestrator_queue", base=RengineTask, bind=True)
def execute_secator_builtin_workflow(
    self,
    scan_history_id: int,
    domain_id: int,
    target: str,
    workflow_id: str,
    options: Optional[Dict[str, Any]] = None,
    ctx: Optional[Dict[str, Any]] = None,
    **kwargs,
) -> Dict[str, Any]:
    """
    Celery task to execute a Secator built-in workflow.

    Args:
        scan_history_id: ID of the associated ScanHistory record.
        domain_id: ID of the associated Domain record.
        target: The target to scan (domain, URL, IP, etc.).
        workflow_id: The ID of the Secator built-in workflow to execute.
        options: Optional workflow-specific options.
        ctx: Context dictionary containing additional information.
        **kwargs: Additional keyword arguments.

    Returns:
        A dictionary summarizing the execution result.
    """
    if ctx is None:
        ctx = {}

    # Add essential IDs to context for database operations
    ctx["scan_id"] = scan_history_id
    ctx["domain_id"] = domain_id

    logger.info(
        f"Executing Secator built-in workflow '{workflow_id}' for target '{target}' (Scan ID: {scan_history_id})"
    )

    try:
        # Initialize Secator built-in workflow manager
        manager = SecatorBuiltinWorkflowManager()

        # Execute the workflow
        result = manager.execute_builtin_workflow(workflow_id=workflow_id, target=target, ctx=ctx, options=options)

        if result.get("success"):
            logger.info(f"Secator built-in workflow '{workflow_id}' completed successfully for target '{target}'.")
            # TODO: Process and save results to database
            # This would involve calling the appropriate distributed processors
            # to save subdomains, endpoints, vulnerabilities, etc.
        else:
            logger.error(
                f"Secator built-in workflow '{workflow_id}' failed for target '{target}': {result.get('error')}"
            )

        return result

    except Exception as e:
        logger.error(
            f"An unexpected error occurred while executing Secator built-in workflow '{workflow_id}' for target '{target}': {e}",
            exc_info=True,
        )
        return {"success": False, "error": str(e)}


@app.task(name="list_secator_builtin_workflows", queue="orchestrator_queue", base=RengineTask, bind=True)
def list_secator_builtin_workflows(self, **kwargs) -> Dict[str, Any]:
    """
    Celery task to list all available Secator built-in workflows.

    Returns:
        A dictionary containing the list of available workflows.
    """
    try:
        manager = SecatorBuiltinWorkflowManager()
        workflows = manager.list_builtin_workflows()

        logger.info(f"Retrieved {len(workflows)} Secator built-in workflows")

        return {"success": True, "workflows": workflows, "count": len(workflows)}

    except Exception as e:
        logger.error(f"Error listing Secator built-in workflows: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@app.task(name="get_secator_builtin_workflow_info", queue="orchestrator_queue", base=RengineTask, bind=True)
def get_secator_builtin_workflow_info(self, workflow_id: str, **kwargs) -> Dict[str, Any]:
    """
    Celery task to get information about a specific Secator built-in workflow.

    Args:
        workflow_id: The ID of the built-in workflow.

    Returns:
        A dictionary containing workflow information.
    """
    try:
        manager = SecatorBuiltinWorkflowManager()
        workflow_info = manager.get_workflow_info(workflow_id)

        if workflow_info:
            logger.info(f"Retrieved information for Secator built-in workflow '{workflow_id}'")
            return {"success": True, "workflow": workflow_info}
        else:
            logger.warning(f"Secator built-in workflow '{workflow_id}' not found")
            return {"success": False, "error": f"Workflow '{workflow_id}' not found"}

    except Exception as e:
        logger.error(f"Error getting information for Secator built-in workflow '{workflow_id}': {e}", exc_info=True)
        return {"success": False, "error": str(e)}
