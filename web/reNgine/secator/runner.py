"""
SecatorRunner - Interface to Secator library for orchestrated scanning.

This class provides the main interface between reNgine and Secator,
allowing reNgine to use Secator as a library for managing scan workflows.
Secator will orchestrate Celery tasks automatically with lifecycle hooks.

Precedence of configuration:
    If both `config` and `profiles` specify the same keys, the value from `profiles` will take precedence over `config`.
"""

import logging
import os
from typing import Any, Dict, List

from secator.runners import Scan, Task, Workflow
from secator.template import TemplateLoader

from reNgine.secator.drivers.rengine_driver import ReNgineDriver
from reNgine.settings import RENGINE_RESULTS
from targetApp.models import Domain


logger = logging.getLogger(__name__)


class SecatorRunner:
    """
    Interface to Secator - Secator orchestrates Celery tasks with hooks.

    This class provides methods to run Secator workflows and tasks,
    with Secator handling the creation and orchestration of Celery tasks.
    """

    def __init__(self):
        """Initialize the SecatorRunner."""
        self.secator_config = self._load_secator_config()
        logger.info(f"🔧 SecatorRunner initialized with config: {self.secator_config}")

    def _load_secator_config(self) -> Dict[str, Any]:
        """Load Secator configuration from settings."""
        from reNgine.settings import RENGINE_RESULTS

        return {
            "workflows_location": "/home/rengine/.secator/workflows",
            "reports_folder": RENGINE_RESULTS,
            "sync": False,  # Force async mode for Celery workers
            "global": {
                "timeout": 300,
                "concurrency": 20,
                "rate_limit": 150,
                "enable_duplicate_check": False,  # Disable deduplication to avoid Record hash error
            },
        }

    def _load_workflow_template(self, workflow_name: str):
        """
        Load workflow template from builtin or custom source.

        Args:
            workflow_name: Name/alias of the workflow

        Returns:
            TemplateLoader configuration object
        """
        from scanEngine.models import SecatorWorkflow

        try:
            workflow_obj = SecatorWorkflow.objects.get(alias=workflow_name)

            if workflow_obj.workflow_type == "builtin":
                template = TemplateLoader(name=f"workflows/{workflow_name}")
                logger.info(f"Loaded built-in workflow template: {workflow_name}")
            else:
                template = TemplateLoader(workflow_obj.yaml_configuration)
                logger.info(f"Loaded custom workflow template: {workflow_name}")

            return template
        except Exception as e:
            logger.error(f"Failed to load workflow template '{workflow_name}': {e}")
            raise Exception(f"Could not load workflow template '{workflow_name}': {e}")

    def _load_scan_template(self, scan_name_or_alias: str):
        """
        Load scan template from builtin or custom source.

        Args:
            scan_name_or_alias: Name or alias of the scan

        Returns:
            TemplateLoader configuration object
        """
        from scanEngine.models import SecatorScan

        try:
            scan_obj = SecatorScan.objects.get(alias=scan_name_or_alias)

            if scan_obj.scan_config_type == "builtin":
                template = TemplateLoader(name=f"scan/{scan_name_or_alias}")
                logger.info(f"Loaded built-in scan template: {scan_name_or_alias}")
            else:
                template = TemplateLoader(scan_obj.yaml_configuration)
                logger.info(f"Loaded custom scan template: {scan_name_or_alias}")

            return template
        except Exception as e:
            logger.error(f"Failed to load scan template '{scan_name_or_alias}': {e}")
            raise Exception(f"Could not load scan template '{scan_name_or_alias}': {e}")

    def _execute_runner(
        self,
        runner_class,
        config,
        targets: List[str],
        scan_history_id: int,
        domain_id: int,
        run_config: Dict[str, Any] = None,
        profiles: Dict[str, str] = None,
    ) -> Dict[str, Any]:
        """
        Execute a Secator runner (Workflow, Scan, or Task) with common logic.

        Args:
            runner_class: Secator runner class (Workflow, Scan, or Task)
            config: Template configuration
            targets: List of targets
            scan_history_id: ID of scan history
            domain_id: ID of domain
            run_config: Configuration dictionary
            profiles: Speed/stealth profiles

        Returns:
            Dict containing execution results
        """
        try:
            # Reset any potential Secator global state
            logger.info(f"🔧 Starting fresh scan execution for scan {scan_history_id}")

            # Get domain and setup results directory
            domain = Domain.objects.get(id=domain_id)
            domain_results_dir = os.path.join(RENGINE_RESULTS, domain.name)
            os.makedirs(domain_results_dir, exist_ok=True)

            # Prepare configuration
            if run_config is None:
                run_config = {}
            run_config.setdefault("output_dir", domain_results_dir)
            run_config["domain_name"] = domain.name

            # Create driver for hooks
            driver = ReNgineDriver(
                scan_history_id=scan_history_id,
                domain_id=domain_id,
                notification_config=run_config.get("notifications", {}),
                rengine_context=run_config.get("rengine_context", {}),
            )

            # Prepare Secator config
            secator_config = self._prepare_secator_config(run_config, profiles)

            # Force reset sync to False to ensure async mode
            secator_config["sync"] = False
            logger.info(f"🔧 Secator config sync value: {secator_config.get('sync', 'NOT SET')}")
            logger.info(f"🔧 Full secator config: {secator_config}")

            # Get hooks configuration before creating runner
            hooks_config = driver.get_hooks_config()
            logger.info(f"🔧 Hooks configuration: {list(hooks_config.keys())}")

            # Create runner with hooks
            try:
                logger.info("🔧 Creating runner with hooks")

                # Force sync=False in run_opts to override any cached config
                run_opts = secator_config.copy()
                run_opts["sync"] = False
                logger.info(f"🔧 Final run_opts sync: {run_opts.get('sync')}")

                runner = runner_class(config, inputs=targets, run_opts=run_opts)
                logger.info("🔧 Runner created successfully with hooks")
                logger.info(f"🔧 Runner hooks: {runner.hooks if hasattr(runner, 'hooks') else 'No hooks attribute'}")
                logger.info(f"🔧 Runner sync mode: {getattr(runner, 'sync', 'NOT SET')}")

            except Exception as e:
                logger.error(f"Error creating runner with hooks: {e}")
                raise Exception(f"Could not create runner: {e}")

            try:
                result = runner.run()
                logger.info("🔧 Runner execution completed")

            except Exception as e:
                logger.error(f"Error running runner: {e}")
                raise Exception(f"Could not run runner: {e}")

            logger.info(f"Secator {runner_class.__name__} executed successfully")

            return {
                "status": "success",
                "runner_type": runner_class.__name__,
                "targets": targets,
                "result": result,
                "scan_history_id": scan_history_id,
            }

        except Exception as e:
            logger.error(f"Error running {runner_class.__name__}: {e}")
            return {
                "status": "error",
                "runner_type": runner_class.__name__,
                "targets": targets,
                "error": str(e),
                "scan_history_id": scan_history_id,
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
        """Run a Secator workflow."""
        try:
            logger.info(f"Starting Secator workflow: {workflow_name} for targets: {targets}")

            template = self._load_workflow_template(workflow_name)

            result = self._execute_runner(
                runner_class=Workflow,
                config=template,
                targets=targets,
                scan_history_id=scan_history_id,
                domain_id=domain_id,
                run_config=config,
                profiles=profiles,
            )

            if result["status"] == "success":
                logger.info(f"Secator workflow {workflow_name} completed successfully")

            return result

        except Exception as e:
            logger.error(f"Error running Secator workflow {workflow_name}: {e}")
            return {
                "status": "error",
                "workflow_name": workflow_name,
                "targets": targets,
                "error": str(e),
                "scan_history_id": scan_history_id,
            }

    def run_tasks(
        self,
        task_names: List[str],
        targets: List[str],
        scan_history_id: int,
        domain_id: int,
        config: Dict[str, Any] = None,
        profiles: Dict[str, str] = None,
    ) -> Dict[str, Any]:
        """
        Run multiple Secator tasks sequentially.

        Args:
            task_names: List of task names to execute
            targets: List of targets
            scan_history_id: ID of scan history
            domain_id: ID of domain
            config: Configuration dictionary
            profiles: Speed/stealth profiles

        Returns:
            Dict containing aggregated results from all tasks
        """
        try:
            logger.info(f"Starting {len(task_names)} Secator tasks for targets: {targets}")

            task_results = []
            all_success = True

            for task_name in task_names:
                try:
                    logger.info(f"Executing task: {task_name}")

                    template = TemplateLoader({"type": "task", "name": task_name})

                    result = self._execute_runner(
                        runner_class=Task,
                        config=template,
                        targets=targets,
                        scan_history_id=scan_history_id,
                        domain_id=domain_id,
                        run_config=config,
                        profiles=profiles,
                    )

                    task_results.append({"task_name": task_name, "result": result})

                    if result.get("status") != "success":
                        all_success = False
                        logger.warning(f"Task {task_name} failed: {result.get('error', 'Unknown error')}")
                    else:
                        logger.info(f"Task {task_name} completed successfully")

                except Exception as task_error:
                    logger.error(f"Error executing task {task_name}: {task_error}")
                    task_results.append(
                        {
                            "task_name": task_name,
                            "result": {
                                "status": "error",
                                "error": str(task_error),
                                "targets": targets,
                                "scan_history_id": scan_history_id,
                            },
                        }
                    )
                    all_success = False

            return {
                "status": "success" if all_success else "partial" if task_results else "error",
                "task_names": task_names,
                "tasks_executed": len(task_results),
                "results": task_results,
                "targets": targets,
                "scan_history_id": scan_history_id,
            }

        except Exception as e:
            logger.error(f"Error running Secator tasks: {e}")
            return {
                "status": "error",
                "task_names": task_names,
                "targets": targets,
                "error": str(e),
                "scan_history_id": scan_history_id,
            }

    def run_task(
        self,
        task_name: str,
        targets: List[str],
        scan_history_id: int,
        domain_id: int,
        config: Dict[str, Any] = None,
        profiles: Dict[str, str] = None,
    ) -> Dict[str, Any]:
        """
        Run a single Secator task.

        This is a convenience method that delegates to run_tasks.
        """
        result = self.run_tasks(
            task_names=[task_name],
            targets=targets,
            scan_history_id=scan_history_id,
            domain_id=domain_id,
            config=config,
            profiles=profiles,
        )

        if result["status"] == "error":
            return result

        task_result = result["results"][0]["result"] if result["results"] else {}

        return {
            "status": task_result.get("status", "error"),
            "task_name": task_name,
            "targets": targets,
            "result": task_result.get("result"),
            "error": task_result.get("error"),
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
        logger.info(f"🔧 Base secator config: {secator_config}")

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

            # Force async mode - override any sync setting from config
            secator_config["sync"] = False

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

        secator_config["sync"] = False
        logger.info(f"🔧 Final prepared secator config: {secator_config}")
        return secator_config

    def run_scan(
        self,
        scan_type: str,
        targets: List[str],
        scan_history_id: int,
        domain_id: int,
        config: Dict[str, Any] = None,
        profiles: Dict[str, str] = None,
    ) -> Dict[str, Any]:
        """
        Run a Secator scan type using Scan runner.

        Args:
            scan_type: Type of scan alias (domain, host, network, subdomain, url) for builtin or custom
            targets: List of targets
            scan_history_id: ID of scan history
            domain_id: ID of domain
            config: Configuration dictionary
            profiles: Speed/stealth profiles

        Returns:
            Dict containing scan results
        """
        try:
            logger.info(f"Starting Secator scan: {scan_type} for targets: {targets}")

            template = self._load_scan_template(scan_type)

            result = self._execute_runner(
                runner_class=Scan,
                config=template,
                targets=targets,
                scan_history_id=scan_history_id,
                domain_id=domain_id,
                run_config=config,
                profiles=profiles,
            )

            if result["status"] == "success":
                logger.info(f"Secator scan {scan_type} completed successfully")

            return result

        except Exception as e:
            logger.error(f"Error running Secator scan {scan_type}: {e}")
            return {
                "status": "error",
                "scan_type": scan_type,
                "targets": targets,
                "error": str(e),
                "scan_history_id": scan_history_id,
            }
