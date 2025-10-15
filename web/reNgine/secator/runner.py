"""
SecatorRunner - Interface to Secator library for orchestrated scanning.

This class provides the main interface between reNgine and Secator,
allowing reNgine to use Secator as a library for managing scan workflows.
Secator will orchestrate Celery tasks automatically with lifecycle hooks.

Precedence of configuration:
    If both `config` and `profiles` specify the same keys, the value from `profiles` will take precedence over `config`.
"""

from typing import Any, Callable, Dict, List, Optional

from celery.utils.log import get_task_logger
from django.conf import settings

from reNgine.secator.drivers.rengine_driver import ReNgineDriver


logger = get_task_logger(__name__)


class SecatorRunner:
    """
    Interface to Secator - Secator orchestrates Celery tasks with hooks.

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
        scan_history_id: int,
        domain_id: int,
        config: Dict[str, Any] = None,
        profiles: Dict[str, str] = None,
    ) -> Dict[str, Any]:
        """
        Run a Secator workflow with dynamic hooks.

        Args:
            workflow_name: Name of the Secator workflow to run
            targets: List of target URLs/domains/IPs
            scan_history_id: ID of the scan history
            domain_id: ID of the domain
            config: Configuration dictionary for the workflow
            profiles: Speed/stealth profiles

        Returns:
            Dictionary containing execution results and metadata
        """
        try:
            logger.info(f"Starting Secator workflow: {workflow_name} for targets: {targets}")

            try:
                from secator.runners import Workflow
                from secator.template import TemplateLoader
            except ImportError:
                logger.error("Failed to import Secator library")
                raise

            driver = ReNgineDriver(
                scan_history_id=scan_history_id,
                domain_id=domain_id,
                notification_config=config.get("notifications", {}) if config else {},
            )

            # When both config and profiles specify the same keys, the value from profiles takes precedence.
            secator_config = self._prepare_secator_config(config, profiles)
            template = TemplateLoader(name=workflow_name)

            workflow = Workflow(template, targets=targets, hooks=driver.get_hooks_config(), **secator_config)

            result = workflow.run()

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

            return secator.get_builtin_workflows()
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

            return secator.get_builtin_tasks()
        except Exception as e:
            logger.error(f"Error getting built-in tasks: {e}")
            return []

    def _prepare_secator_config(self, config: Dict[str, Any] = None, profiles: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Prepare Secator configuration by merging with default config and profiles.

        This method merges all keys from both config and profiles dictionaries.
        If the same key exists in both, the value from profiles will overwrite the value from config.

        Special key mappings:
        - 'threads' and 'concurrency' both map to 'global.concurrency'
        - 'threads' takes precedence over 'concurrency' when both are present and threads has a valid value
        - 'threads' is considered invalid if None, empty string, or False (falls back to 'concurrency')
        - 'rate_limit' maps to 'global.rate_limit'
        - 'timeout' maps to 'global.timeout'
        - 'speed' maps to 'speed_profile'
        - 'stealth' maps to 'stealth_profile'

        Args:
            config: Configuration dictionary from reNgine. All keys are supported.
            profiles: Speed/stealth profiles. All keys are supported.

        Returns:
            Merged configuration dictionary for Secator, containing all keys from both config and profiles.
        """
        import copy

        secator_config = copy.deepcopy(self.secator_config)

        # Merge config dictionary - all keys are supported
        if config:
            # Handle special cases that need to be mapped to nested structure
            if "rate_limit" in config:
                secator_config["global"]["rate_limit"] = config["rate_limit"]
            if "threads" in config or "concurrency" in config:
                # Priority: 'threads' takes precedence over 'concurrency' when both are set
                # If 'threads' is explicitly set and not None/empty/false, use it; otherwise use 'concurrency'
                if (
                    "threads" in config
                    and config["threads"] is not None
                    and config["threads"] != ""
                    and config["threads"] is not False
                ):
                    secator_config["global"]["concurrency"] = config["threads"]
                else:
                    secator_config["global"]["concurrency"] = config.get("concurrency", 20)
            if "timeout" in config:
                secator_config["global"]["timeout"] = config["timeout"]

            # Merge all other config keys directly
            for key, value in config.items():
                if key not in ["rate_limit", "threads", "concurrency", "timeout"]:
                    secator_config[key] = value

        # Merge profiles dictionary - all keys are supported
        if profiles:
            # Handle special cases that need to be mapped to specific keys
            if "speed" in profiles:
                secator_config["speed_profile"] = profiles["speed"]
            if "stealth" in profiles:
                secator_config["stealth_profile"] = profiles["stealth"]

            # Merge all other profile keys directly
            for key, value in profiles.items():
                if key not in ["speed", "stealth"]:
                    secator_config[key] = value

        return secator_config
