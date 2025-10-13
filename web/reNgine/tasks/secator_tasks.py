"""
Secator Celery tasks for reNgine.

This module contains Celery tasks that integrate with Secator for orchestrated scanning.
Secator will handle the creation and orchestration of individual tool tasks.
"""

import logging
from typing import Dict, Any, List, Optional
from celery import shared_task
from django.conf import settings

from reNgine.secator import SecatorRunner, SecatorParser, SecatorConfigConverter
from startScan.models import ScanHistory, SubScan
from scanEngine.models import SecatorScan, SecatorWorkflow, SecatorTask

logger = logging.getLogger(__name__)


@shared_task(bind=True)
def initiate_secator_scan(self, scan_history_id: int, scan_config_id: int, targets: List[str]) -> Dict[str, Any]:
    """
    Initiate a Secator-based scan.
    
    This task replaces the old initiate_scan for new Secator-based scans.
    Secator will orchestrate the individual tool tasks automatically.
    
    Args:
        scan_history_id: ID of the ScanHistory record
        scan_config_id: ID of the SecatorScan configuration
        targets: List of target URLs/domains/IPs
        
    Returns:
        Dictionary containing scan results and metadata
    """
    try:
        logger.info(f"Starting Secator scan for ScanHistory {scan_history_id}")
        
        # Get scan history and configuration
        scan_history = ScanHistory.objects.get(id=scan_history_id)
        scan_config = SecatorScan.objects.get(id=scan_config_id)
        
        # Update scan status
        scan_history.scan_status = 1  # Running
        scan_history.celery_ids = [self.request.id]
        scan_history.save()
        
        # Initialize Secator components
        runner = SecatorRunner()
        parser = SecatorParser()
        config_converter = SecatorConfigConverter()
        
        # Convert configuration to Secator format
        secator_config = config_converter.convert(scan_config)
        
        # Prepare callback for results
        def result_callback(result):
            """Callback to process Secator results."""
            try:
                # Parse results and save to database
                parsed_results = parser.parse_batch(result.get("results", []))
                saved_count = parser.save_results(parsed_results, scan_history_id)
                
                logger.info(f"Saved {saved_count} results from Secator scan")
                
            except Exception as e:
                logger.error(f"Error processing Secator results: {e}")
        
        # Execute scan based on configuration
        if scan_config.execution_mode == "workflow" and scan_config.workflow:
            # Run workflow
            result = runner.run_workflow(
                workflow_name=scan_config.workflow.name,
                targets=targets,
                config=secator_config,
                callback=result_callback,
                scan_history_id=scan_history_id,
            )
        elif scan_config.execution_mode == "tasks":
            # Run individual tasks
            task_names = [task.task_type for task in scan_config.tasks.all()]
            result = runner.run_tasks(
                tasks=task_names,
                targets=targets,
                config=secator_config,
                callback=result_callback,
                scan_history_id=scan_history_id,
            )
        else:
            raise ValueError(f"Invalid execution mode: {scan_config.execution_mode}")
        
        # Update scan status based on result
        if result["status"] == "success":
            scan_history.scan_status = 2  # Success
            logger.info(f"Secator scan {scan_history_id} completed successfully")
        else:
            scan_history.scan_status = 3  # Failed
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
        
        # Update scan status to failed
        try:
            scan_history = ScanHistory.objects.get(id=scan_history_id)
            scan_history.scan_status = 3  # Failed
            scan_history.error_message = str(e)
            scan_history.save()
        except Exception:
            pass
        
        return {
            "status": "error",
            "scan_history_id": scan_history_id,
            "error": str(e),
        }


@shared_task(bind=True)
def run_secator_workflow(self, workflow_name: str, targets: List[str], config: Dict[str, Any], scan_history_id: Optional[int] = None) -> Dict[str, Any]:
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
def run_secator_tasks(self, task_names: List[str], targets: List[str], config: Dict[str, Any], scan_history_id: Optional[int] = None) -> Dict[str, Any]:
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
                }
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
                }
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
