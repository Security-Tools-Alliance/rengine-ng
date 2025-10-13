"""
SecatorRunner - Interface to Secator library for orchestrated scanning.

This class provides the main interface between reNgine and Secator,
allowing reNgine to use Secator as a library for managing scan workflows.
Secator will orchestrate Celery tasks automatically.
"""

import logging
from typing import List, Dict, Any, Optional, Callable
from django.conf import settings

logger = logging.getLogger(__name__)


class SecatorRunner:
    """
    Interface to Secator - Secator orchestrates Celery tasks.
    
    This class provides methods to run Secator workflows and tasks,
    with Secator handling the creation and orchestration of Celery tasks.
    """

    def __init__(self):
        """Initialize the SecatorRunner."""
        self.secator_config = self._load_secator_config()

    def _load_secator_config(self) -> Dict[str, Any]:
        """Load Secator configuration from settings."""
        return {
            "celery": {
                "broker_url": getattr(settings, "CELERY_BROKER_URL", "redis://redis:6379/0"),
                "result_backend": getattr(settings, "CELERY_RESULT_BACKEND", "redis://redis:6379/0"),
            },
            "workflows_location": "/home/rengine/.secator/workflows",
            "reports_folder": "/home/rengine/scan_results",
            "global": {
                "timeout": 300,
                "concurrency": 20,
                "rate_limit": 150,
            },
        }

    def run_workflow(
        self,
        workflow_name: str,
        targets: List[str],
        config: Dict[str, Any],
        callback: Optional[Callable] = None,
        scan_history_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Run a Secator workflow.
        
        Args:
            workflow_name: Name of the Secator workflow to run
            targets: List of target URLs/domains/IPs
            config: Configuration dictionary for the workflow
            callback: Optional callback function for results
            scan_history_id: Optional scan history ID for tracking
            
        Returns:
            Dictionary containing execution results and metadata
        """
        try:
            logger.info(f"Starting Secator workflow: {workflow_name} for targets: {targets}")
            
            # Import Secator here to avoid import issues during Django startup
            try:
                import secator
            except ImportError as e:
                logger.error("Failed to import 'secator' library. Please ensure it is installed and available in your environment.")
                raise

            # Prepare Secator configuration
            secator_config = self._prepare_secator_config(config)
            
            # Run the workflow using Secator in distributed mode
            # Secator will automatically create and orchestrate Celery tasks via Redis
            result = secator.run_workflow(
                workflow_name=workflow_name,
                targets=targets,
                config=secator_config,
                callback=self._create_callback(callback, scan_history_id),
                sync=False,  # Use distributed mode with Celery workers
            )
            
            logger.info(f"Secator workflow {workflow_name} completed successfully")
            return {
                "status": "success",
                "workflow_name": workflow_name,
                "targets": targets,
                "result": result,
                "scan_history_id": scan_history_id,
            }
            
        except Exception as e:
            logger.error(f"Error running Secator workflow {workflow_name}: {e}")
            return {
                "status": "error",
                "workflow_name": workflow_name,
                "targets": targets,
                "error": str(e),
                "scan_history_id": scan_history_id,
            }

    def run_task(
        self,
        task_name: str,
        targets: List[str],
        config: Dict[str, Any],
        callback: Optional[Callable] = None,
        scan_history_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Run a single Secator task.
        
        Args:
            task_name: Name of the Secator task to run
            targets: List of target URLs/domains/IPs
            config: Configuration dictionary for the task
            callback: Optional callback function for results
            scan_history_id: Optional scan history ID for tracking
            
        Returns:
            Dictionary containing execution results and metadata
        """
        try:
            logger.info(f"Starting Secator task: {task_name} for targets: {targets}")
            
            # Import Secator here to avoid import issues during Django startup
            import secator
            
            # Prepare Secator configuration
            secator_config = self._prepare_secator_config(config)
            
            # Run the task using Secator in distributed mode
            # Secator will automatically create and orchestrate Celery tasks via Redis
            result = secator.run_task(
                task_name=task_name,
                targets=targets,
                config=secator_config,
                callback=self._create_callback(callback, scan_history_id),
                sync=False,  # Use distributed mode with Celery workers
            )
            
            logger.info(f"Secator task {task_name} completed successfully")
            return {
                "status": "success",
                "task_name": task_name,
                "targets": targets,
                "result": result,
                "scan_history_id": scan_history_id,
            }
            
        except Exception as e:
            logger.error(f"Error running Secator task {task_name}: {e}")
            return {
                "status": "error",
                "task_name": task_name,
                "targets": targets,
                "error": str(e),
                "scan_history_id": scan_history_id,
            }

    def run_tasks(
        self,
        tasks: List[str],
        targets: List[str],
        config: Dict[str, Any],
        callback: Optional[Callable] = None,
        scan_history_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Run multiple Secator tasks in sequence.
        
        Args:
            tasks: List of Secator task names to run
            targets: List of target URLs/domains/IPs
            config: Configuration dictionary for the tasks
            callback: Optional callback function for results
            scan_history_id: Optional scan history ID for tracking
            
        Returns:
            Dictionary containing execution results and metadata
        """
        try:
            logger.info(f"Starting Secator tasks: {tasks} for targets: {targets}")
            
            # Import Secator here to avoid import issues during Django startup
            import secator
            
            # Prepare Secator configuration
            secator_config = self._prepare_secator_config(config)
            
            # Run the tasks using Secator in distributed mode
            # Secator will automatically create and orchestrate Celery tasks via Redis
            result = secator.run_tasks(
                tasks=tasks,
                targets=targets,
                config=secator_config,
                callback=self._create_callback(callback, scan_history_id),
                sync=False,  # Use distributed mode with Celery workers
            )
            
            logger.info(f"Secator tasks {tasks} completed successfully")
            return {
                "status": "success",
                "tasks": tasks,
                "targets": targets,
                "result": result,
                "scan_history_id": scan_history_id,
            }
            
        except Exception as e:
            logger.error(f"Error running Secator tasks {tasks}: {e}")
            return {
                "status": "error",
                "tasks": tasks,
                "targets": targets,
                "error": str(e),
                "scan_history_id": scan_history_id,
            }

    def get_builtin_workflows(self) -> List[Dict[str, Any]]:
        """
        Get list of built-in Secator workflows.
        
        Returns:
            List of dictionaries containing workflow information
        """
        try:
            # Import Secator here to avoid import issues during Django startup
            import secator
            
            workflows = secator.get_builtin_workflows()
            return workflows
            
        except Exception as e:
            logger.error(f"Error getting built-in workflows: {e}")
            return []

    def get_builtin_tasks(self) -> List[Dict[str, Any]]:
        """
        Get list of built-in Secator tasks.
        
        Returns:
            List of dictionaries containing task information
        """
        try:
            # Import Secator here to avoid import issues during Django startup
            import secator
            
            tasks = secator.get_builtin_tasks()
            return tasks
            
        except Exception as e:
            logger.error(f"Error getting built-in tasks: {e}")
            return []

    def _prepare_secator_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare Secator configuration by merging with default config.
        
        Args:
            config: Configuration dictionary from reNgine
            
        Returns:
            Merged configuration dictionary for Secator
        """
        import copy
        # Start with default Secator config
        secator_config = copy.deepcopy(self.secator_config)
        
        # Merge with provided config
        if config:
            secator_config.update(config)
        
        return secator_config

    def _create_callback(
        self, 
        callback: Optional[Callable], 
        scan_history_id: Optional[int]
    ) -> Optional[Callable]:
        """
        Create a callback function that includes scan history tracking.
        
        Args:
            callback: Original callback function
            scan_history_id: Scan history ID for tracking
            
        Returns:
            Enhanced callback function
        """
        if not callback:
            return None
        
        def enhanced_callback(result):
            """Enhanced callback with scan history tracking."""
            try:
                # Add scan history ID to result if available
                if scan_history_id:
                    result["scan_history_id"] = scan_history_id
                
                # Call original callback
                callback(result)
                
            except Exception as e:
                logger.error(f"Error in callback: {e}")
        
        return enhanced_callback
