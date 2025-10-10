"""
Secator integration tasks for reNgine.

This module provides Celery tasks for executing Secator workflows
within the reNgine distributed processing system.
"""

import os
from typing import Any, Dict, Optional

from celery.utils.log import get_task_logger

from reNgine.celery import app
from reNgine.tasks import RengineTask
from reNgine.utilities.distributed.base import create_balanced_config
from reNgine.utilities.secator_integration import (
    SecatorDistributedProcessor,
    ensure_secator_initialized,
    get_workflow_manager,
)


logger = get_task_logger(__name__)


@app.task(name="execute_secator_workflow", queue="orchestrator_queue", base=RengineTask, bind=True)
def execute_secator_workflow(
    self,
    workflow_config: Dict[str, Any],
    target: str,
    ctx: Optional[Dict[str, Any]] = None,
    description: Optional[str] = None,
    **kwargs,
):
    """
    Execute a Secator workflow using reNgine's distributed processing.

    Args:
        workflow_config: Secator workflow configuration
        target: Target to scan (domain, IP, URL, etc.)
        ctx: Context containing scan information
        description: Task description
        **kwargs: Additional parameters

    Returns:
        Dict containing execution results
    """
    if ctx is None:
        ctx = {}

    logger.info(f"Starting Secator workflow execution for target: {target}")

    try:
        # Ensure Secator is initialized
        ensure_secator_initialized()

        # Create distributed configuration
        config = create_balanced_config()

        # Initialize processor
        processor = SecatorDistributedProcessor(config)

        # Execute workflow
        result = processor.execute_secator_workflow(
            workflow_config=workflow_config, target=target, ctx=ctx, batch_id=f"secator_workflow_{self.request.id}"
        )

        if result.is_successful:
            logger.info(f"Secator workflow completed successfully for target: {target}")
            return {
                "success": True,
                "workflow_name": workflow_config.get("name", "unknown"),
                "target": target,
                "results_count": result.data.get("results_count", 0),
                "saved_count": result.data.get("saved_count", 0),
                "processing_time": result.processing_time,
                "batch_id": result.batch_id,
            }
        else:
            logger.error(f"Secator workflow failed for target: {target}")
            return {
                "success": False,
                "error": result.errors,
                "target": target,
                "processing_time": result.processing_time,
            }

    except Exception as e:
        logger.error(f"Secator workflow execution failed for target {target}: {e}")
        return {"success": False, "error": str(e), "target": target}


@app.task(name="execute_secator_task", queue="run_command_queue", base=RengineTask, bind=True)
def execute_secator_task(
    self, task_name: str, target: str, ctx: Optional[Dict[str, Any]] = None, description: Optional[str] = None, **kwargs
):
    """
    Execute a single Secator task.

    Args:
        task_name: Name of the Secator task to execute
        target: Target to scan
        ctx: Context containing scan information
        description: Task description
        **kwargs: Additional task parameters

    Returns:
        Dict containing execution results
    """
    if ctx is None:
        ctx = {}

    logger.info(f"Starting Secator task execution: {task_name} for target: {target}")

    try:
        # Ensure Secator is initialized
        ensure_secator_initialized()

        # Create distributed configuration
        config = create_balanced_config()

        # Initialize processor
        processor = SecatorDistributedProcessor(config)

        # Execute task
        result = processor.execute_secator_task(task_name=task_name, target=target, ctx=ctx, **kwargs)

        if result.is_successful:
            logger.info(f"Secator task completed successfully: {task_name}")
            return {
                "success": True,
                "task_name": task_name,
                "target": target,
                "results_count": result.data.get("results_count", 0),
                "saved_count": result.data.get("saved_count", 0),
                "processing_time": result.processing_time,
                "batch_id": result.batch_id,
            }
        else:
            logger.error(f"Secator task failed: {task_name}")
            return {
                "success": False,
                "error": result.errors,
                "task_name": task_name,
                "target": target,
                "processing_time": result.processing_time,
            }

    except Exception as e:
        logger.error(f"Secator task execution failed: {task_name} for target {target}: {e}")
        return {"success": False, "error": str(e), "task_name": task_name, "target": target}


@app.task(name="migrate_scan_engine_to_secator", queue="orchestrator_queue", base=RengineTask, bind=True)
def migrate_scan_engine_to_secator(
    self, engine_id: int, ctx: Optional[Dict[str, Any]] = None, description: Optional[str] = None, **kwargs
):
    """
    Migrate a legacy scan engine to Secator workflow.

    Args:
        engine_id: ID of the scan engine to migrate
        ctx: Context information
        description: Task description
        **kwargs: Additional parameters

    Returns:
        Dict containing migration results
    """
    if ctx is None:
        ctx = {}

    logger.info(f"Starting migration of scan engine ID: {engine_id}")

    try:
        # Import here to avoid circular imports
        from scanEngine.models import EngineType

        # Get the engine
        try:
            engine = EngineType.objects.get(id=engine_id)
        except EngineType.DoesNotExist:
            return {"success": False, "error": f"Scan engine with ID {engine_id} not found"}

        # Check if engine can be migrated
        if not engine.yaml_configuration:
            return {"success": False, "error": "Engine has no YAML configuration to migrate"}

        # Get workflow manager
        workflow_manager = get_workflow_manager()

        # Convert the engine
        from reNgine.utilities.secator_integration.converter import ReNgineToSecatorConverter

        converter = ReNgineToSecatorConverter()

        # Parse legacy configuration
        import yaml

        legacy_config = yaml.safe_load(engine.yaml_configuration)

        # Convert to Secator workflow
        secator_workflow = converter.convert_scan_engine_content(
            legacy_config, engine.engine_name.lower().replace(" ", "_")
        )

        # Save the workflow
        workflow_filename = f"{engine.engine_name.lower().replace(' ', '_')}.yaml"
        workflow_path = (
            f"/home/psyray/Documents/Secu/soft/rengine/rengine-git/web/config/secator_workflows/{workflow_filename}"
        )

        workflow_manager.save_workflow(secator_workflow, workflow_path)

        logger.info(f"Successfully migrated scan engine: {engine.engine_name}")

        return {
            "success": True,
            "engine_id": engine_id,
            "engine_name": engine.engine_name,
            "workflow_name": secator_workflow.get("name", ""),
            "workflow_file": workflow_path,
            "tasks_count": len(secator_workflow.get("tasks", {})),
        }

    except Exception as e:
        logger.error(f"Failed to migrate scan engine ID {engine_id}: {e}")
        return {"success": False, "error": str(e), "engine_id": engine_id}


@app.task(name="convert_all_legacy_engines", queue="orchestrator_queue", base=RengineTask, bind=True)
def convert_all_legacy_engines(
    self,
    source_dir: str,
    target_dir: str,
    ctx: Optional[Dict[str, Any]] = None,
    description: Optional[str] = None,
    **kwargs,
):
    """
    Convert all legacy scan engines to Secator workflows.

    Args:
        source_dir: Directory containing legacy scan engine files
        target_dir: Directory to save converted workflows
        ctx: Context information
        description: Task description
        **kwargs: Additional parameters

    Returns:
        Dict containing conversion results
    """
    if ctx is None:
        ctx = {}

    logger.info(f"Starting conversion of all legacy engines from {source_dir} to {target_dir}")

    try:
        # Get workflow manager
        workflow_manager = get_workflow_manager()

        # Convert all engines
        conversion_results = workflow_manager.convert_all_legacy_scan_engines(source_dir, target_dir)

        # Calculate summary
        successful_conversions = sum(1 for r in conversion_results if r.get("success", False))
        total_conversions = len(conversion_results)

        logger.info(f"Conversion completed: {successful_conversions}/{total_conversions} engines converted")

        return {
            "success": True,
            "total_engines": total_conversions,
            "successful_conversions": successful_conversions,
            "failed_conversions": total_conversions - successful_conversions,
            "conversion_results": conversion_results,
        }

    except Exception as e:
        logger.error(f"Failed to convert legacy engines: {e}")
        return {"success": False, "error": str(e)}


@app.task(name="secator_workflow_orchestrator", queue="orchestrator_queue", base=RengineTask, bind=True)
def secator_workflow_orchestrator(
    self,
    workflow_name: str,
    target: str,
    ctx: Optional[Dict[str, Any]] = None,
    description: Optional[str] = None,
    **kwargs,
):
    """
    Orchestrate a complete Secator workflow execution.

    This task coordinates the execution of a Secator workflow,
    including result processing and database integration.

    Args:
        workflow_name: Name of the Secator workflow to execute
        target: Target to scan
        ctx: Context containing scan information
        description: Task description
        **kwargs: Additional parameters

    Returns:
        Dict containing orchestration results
    """
    if ctx is None:
        ctx = {}

    logger.info(f"Starting Secator workflow orchestration: {workflow_name} for target: {target}")

    try:
        # Ensure Secator is initialized
        ensure_secator_initialized()

        # Get workflow manager
        workflow_manager = get_workflow_manager()

        # Load workflow
        workflow_config = workflow_manager.get_workflow(workflow_name)
        if not workflow_config:
            # Try to load from file
            workflow_path = f"/home/psyray/Documents/Secu/soft/rengine/rengine-git/web/config/secator_workflows/{workflow_name}.yaml"
            if os.path.exists(workflow_path):
                workflow_config = workflow_manager.load_workflow(workflow_path)
            else:
                return {"success": False, "error": f"Workflow not found: {workflow_name}"}

        # Execute workflow
        workflow_result = execute_secator_workflow.delay(
            workflow_config=workflow_config, target=target, ctx=ctx, description=description, **kwargs
        )

        # Wait for completion
        result = workflow_result.get(timeout=3600)  # 1 hour timeout

        logger.info(f"Secator workflow orchestration completed: {workflow_name}")

        return {"success": True, "workflow_name": workflow_name, "target": target, "execution_result": result}

    except Exception as e:
        logger.error(f"Secator workflow orchestration failed: {workflow_name} for target {target}: {e}")
        return {"success": False, "error": str(e), "workflow_name": workflow_name, "target": target}


# Legacy task wrappers for backward compatibility
@app.task(name="secator_subdomain_discovery", queue="run_command_queue", base=RengineTask, bind=True)
def secator_subdomain_discovery(self, target: str, ctx: Optional[Dict[str, Any]] = None, **kwargs):
    """Legacy wrapper for subdomain discovery using Secator."""
    return execute_secator_task.delay(task_name="subfinder", target=target, ctx=ctx, **kwargs)


@app.task(name="secator_port_scan", queue="run_command_queue", base=RengineTask, bind=True)
def secator_port_scan(self, target: str, ctx: Optional[Dict[str, Any]] = None, **kwargs):
    """Legacy wrapper for port scanning using Secator."""
    return execute_secator_task.delay(task_name="naabu", target=target, ctx=ctx, **kwargs)


@app.task(name="secator_vulnerability_scan", queue="run_command_queue", base=RengineTask, bind=True)
def secator_vulnerability_scan(self, target: str, ctx: Optional[Dict[str, Any]] = None, **kwargs):
    """Legacy wrapper for vulnerability scanning using Secator."""
    return execute_secator_task.delay(task_name="nuclei", target=target, ctx=ctx, **kwargs)
