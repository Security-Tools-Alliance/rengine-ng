"""
SecatorRunner - Interface to Secator library for orchestrated scanning.

This class provides the main interface between reNgine and Secator,
allowing reNgine to use Secator as a library for managing scan workflows.
Secator will orchestrate Celery tasks automatically with lifecycle hooks.

Precedence of configuration:
    If both `config` and `profiles` specify the same keys, the value from `profiles` will take precedence over `config`.
"""

import os
from typing import Any, Dict, List

from secator.runners import Scan, Task, Workflow
from secator.template import TemplateLoader

from reNgine.settings import SECATOR_RESULTS
from reNgine.utilities.logger import get_runner_logger
from targetApp.models import Domain


class SecatorRunner:
    """
    Interface to Secator - Secator orchestrates Celery tasks with hooks.

    This class provides methods to run Secator workflows and tasks,
    with Secator handling the creation and orchestration of Celery tasks.
    """

    def __init__(self):
        """Initialize the SecatorRunner."""
        self.secator_config = self._load_secator_config()
        self.runner_logger = get_runner_logger()

    def _load_secator_config(self) -> Dict[str, Any]:
        """Load Secator configuration from settings."""
        from reNgine.settings import SECATOR_RESULTS

        return {
            "workflows_location": "/home/rengine/.secator/workflows",
            "reports_folder": SECATOR_RESULTS,
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
            workflow_obj = SecatorWorkflow.objects.get(name=workflow_name)

            if workflow_obj.workflow_type == "builtin":
                template = TemplateLoader(name=f"workflows/{workflow_name}")
            else:
                template = TemplateLoader(workflow_obj.yaml_configuration)

            return template
        except Exception as e:
            self.runner_logger.log_runner_error(
                "Workflow", e, {"runner_name": workflow_name, "action": "LOAD_TEMPLATE"}
            )
            raise Exception(f"Could not load workflow template '{workflow_name}': {e}") from e

    def _load_scan_template(self, scan_name: str):
        """
        Load scan template from builtin or custom source.

        Args:
            scan_name: Name of the scan

        Returns:
            TemplateLoader configuration object
        """
        from scanEngine.models import SecatorScan

        try:
            scan_obj = SecatorScan.objects.get(name=scan_name)

            if scan_obj.scan_config_type == "builtin":
                template = TemplateLoader(name=f"scan/{scan_name}")
            else:
                template = TemplateLoader(scan_obj.yaml_configuration)

            return template
        except Exception as e:
            self.runner_logger.log_runner_error("Scan", e, {"runner_name": scan_name, "action": "LOAD_TEMPLATE"})
            raise Exception(f"Could not load scan template '{scan_name}': {e}") from e

    def _execute_runner(
        self,
        runner_class,
        config,
        targets: List[str],
        scan_history_id: int,
        domain_id: int,
        run_config: Dict[str, Any] = None,
        profiles: Dict[str, str] = None,
        runner_name: str = None,
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
            runner_name: Optional runner name for logging

        Returns:
            Dict containing execution results
        """
        runner_type = runner_class.__name__
        runner_name = runner_name or getattr(config, "name", None) or "unknown"

        try:
            # Log targets
            self.runner_logger.log_targets(targets, runner_type)

            # Get domain and setup results directory
            domain = Domain.objects.get(id=domain_id)

            # Get project and create workspace path
            from reNgine.core.validators import sanitize_path_component

            domain_name_sanitized = sanitize_path_component(domain.name)
            if project := domain.project:
                project_slug_sanitized = sanitize_path_component(project.slug)
                workspace = f"{project_slug_sanitized}/{domain_name_sanitized}"
            else:
                # Fallback if no project (should not happen in normal operation)
                workspace = domain_name_sanitized
                self.runner_logger.log_warning(
                    f"No project for domain {domain.name}, using domain name as workspace",
                    {"prefix": self.runner_logger.PREFIX, "action": "WORKSPACE", "domain": domain.name},
                )

            domain_results_dir = os.path.join(SECATOR_RESULTS, domain_name_sanitized)
            os.makedirs(domain_results_dir, exist_ok=True)

            # Prepare configuration
            if run_config is None:
                run_config = {}
            run_config.setdefault("output_dir", domain_results_dir)
            run_config["domain_name"] = domain.name
            run_config["workspace"] = workspace  # Add workspace to config

            # Prepare Secator config
            base_config = self.secator_config.copy()
            secator_config = self._prepare_secator_config(run_config, profiles)
            self.runner_logger.log_config_preparation(base_config, secator_config, profiles)

            # Force reset sync to False to ensure async mode
            secator_config["sync"] = False

            # Import and activate Secator API hooks
            try:
                from secator.hooks.api import HOOKS

                api_hooks = HOOKS
            except ImportError as e:
                self.runner_logger.log_warning(
                    f"Could not import Secator API hooks: {e}. API hooks will not be available.",
                    {"prefix": self.runner_logger.PREFIX, "action": "IMPORT"},
                )
                api_hooks = {}

            # Create runner with hooks
            try:
                # Force sync=False in run_opts to override any cached config
                run_opts = secator_config.copy()
                run_opts["sync"] = False

                # Prepare context with scan_history_id and domain_id for Secator API hooks
                context = {
                    "scan_history_id": scan_history_id,
                    "domain_id": domain_id,
                }

                # Log context and hooks
                self.runner_logger.log_context(context)
                self.runner_logger.log_hooks(api_hooks)

                # Pass API hooks to runner if available
                hooks = api_hooks or {}

                # Log run options
                self.runner_logger.log_run_opts(run_opts)

                # Extract config dict if it's a TemplateLoader
                config_dict = None
                if hasattr(config, "config"):
                    config_dict = config.config
                elif isinstance(config, dict):
                    config_dict = config

                # Log runner creation
                self.runner_logger.log_runner_creation(
                    runner_type=runner_type,
                    runner_name=runner_name,
                    targets=targets,
                    scan_history_id=scan_history_id,
                    domain_id=domain_id,
                    config=config_dict,
                    run_opts=run_opts,
                    context=context,
                    hooks=hooks,
                )

                runner = runner_class(config, inputs=targets, hooks=hooks, run_opts=run_opts, context=context)

            except Exception as e:
                self.runner_logger.log_runner_error(runner_type, e, {"runner_name": runner_name})
                raise Exception(f"Could not create runner: {e}") from e

            try:
                # Log execution start
                self.runner_logger.log_runner_execution_start(runner_type, runner_name)

                result = runner.run()

                # Log execution end
                self.runner_logger.log_runner_execution_end(
                    runner_type=runner_type,
                    runner_name=runner_name,
                    status="success",
                    result=result,
                )

            except Exception as e:
                self.runner_logger.log_runner_execution_end(
                    runner_type=runner_type,
                    runner_name=runner_name,
                    status="error",
                    result=None,
                )
                self.runner_logger.log_runner_error(runner_type, e, {"runner_name": runner_name})
                raise Exception(f"Could not run runner: {e}") from e

            return {
                "status": "success",
                "runner_type": runner_class.__name__,
                "targets": targets,
                "result": result,
                "scan_history_id": scan_history_id,
            }

        except Exception as e:
            self.runner_logger.log_runner_error(
                runner_type,
                e,
                {"runner_name": runner_name, "scan_history_id": scan_history_id, "domain_id": domain_id},
            )
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
            template = self._load_workflow_template(workflow_name)

            result = self._execute_runner(
                runner_class=Workflow,
                config=template,
                targets=targets,
                scan_history_id=scan_history_id,
                domain_id=domain_id,
                run_config=config,
                profiles=profiles,
                runner_name=workflow_name,
            )

            return result

        except Exception as e:
            self.runner_logger.log_runner_error("Workflow", e, {"runner_name": workflow_name})
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
            task_results = []
            all_success = True

            for task_name in task_names:
                try:
                    template = TemplateLoader({"type": "task", "name": task_name})

                    result = self._execute_runner(
                        runner_class=Task,
                        config=template,
                        targets=targets,
                        scan_history_id=scan_history_id,
                        domain_id=domain_id,
                        run_config=config,
                        profiles=profiles,
                        runner_name=task_name,
                    )

                    task_results.append({"task_name": task_name, "result": result})

                    if result.get("status") != "success":
                        all_success = False
                        self.runner_logger.log_warning(
                            f"Task {task_name} failed: {result.get('error', 'Unknown error')}",
                            {"prefix": self.runner_logger.PREFIX, "action": "TASK", "task_name": task_name},
                        )

                except Exception as task_error:
                    self.runner_logger.log_runner_error("Task", task_error, {"runner_name": task_name})
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
            self.runner_logger.log_runner_error("Tasks", e, {"task_names": task_names})
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
            self.runner_logger.log_runner_error("Workflow", e, {"action": "GET_BUILTIN"})
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
            self.runner_logger.log_runner_error("Task", e, {"action": "GET_BUILTIN"})
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
        - Profiles are collected into a 'profiles' list that Secator expects

        Args:
            config: Configuration dictionary from reNgine. All keys are supported.
            profiles: Speed/stealth/general/network profiles. Values are profile names.

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

            # Force async mode - override any sync setting from config
            secator_config["sync"] = False

        # Merge profiles dictionary - Secator expects a 'profiles' list with profile names (str) or TemplateLoader instances
        profile_list = []
        if profiles:
            # Collect profile names from speed, evasion, general, and network
            profile_keys = ["speed", "evasion", "general", "network"]
            # Map old "stealth" key to "evasion" for backward compatibility
            if "stealth" in profiles and "evasion" not in profiles:
                profiles["evasion"] = profiles.pop("stealth")

            # Track seen profile names to avoid duplicates and improve performance
            seen_profile_names = set()
            for p in profile_list:
                if isinstance(p, str):
                    seen_profile_names.add(p)
                elif hasattr(p, "name") and p.name:
                    seen_profile_names.add(p.name)
                else:
                    # Profile object without name attribute - use repr as fallback to avoid None collisions
                    # This should not happen in normal operation, but prevents silent merging of distinct entries
                    self.runner_logger.log_warning(
                        f"Profile object in profile_list lacks 'name' attribute: {type(p).__name__}. "
                        f"Using repr as identifier to avoid collisions.",
                        {"prefix": self.runner_logger.PREFIX, "action": "PROFILE"},
                    )
                    seen_profile_names.add(repr(p))

            for key in profile_keys:
                if key in profiles and profiles[key]:
                    profile_name = profiles[key]

                    # Check if this is a custom profile (not a builtin name)
                    try:
                        from scanEngine.models import SecatorProfile

                        # Try to find custom profile by name
                        custom_profile = SecatorProfile.objects.filter(
                            name=profile_name, profile_type="custom", is_active=True
                        ).first()

                        if custom_profile:
                            # This is a custom profile - create TemplateLoader instance
                            profile_opts = custom_profile._parse_opts()

                            # Merge opts into secator_config (profile opts override config)
                            if profile_opts:
                                for opt_key, opt_value in profile_opts.items():
                                    secator_config[opt_key] = opt_value

                            # Build profile config dict for TemplateLoader
                            profile_config_dict = {
                                "type": "profile",
                                "name": custom_profile.name,
                                "category": custom_profile.category,
                                "description": custom_profile.description or "",
                            }
                            if custom_profile.enforce:
                                profile_config_dict["enforce"] = True
                            if profile_opts:
                                profile_config_dict["opts"] = profile_opts

                            # Create TemplateLoader instance for custom profile
                            profile_loader = TemplateLoader(input=profile_config_dict)

                            # Check if profile name already added before appending
                            if custom_profile.name not in seen_profile_names:
                                profile_list.append(profile_loader)
                                seen_profile_names.add(custom_profile.name)
                        else:
                            # Builtin profile - just add the name as string (Secator will resolve it)
                            if profile_name not in seen_profile_names:
                                profile_list.append(profile_name)
                                seen_profile_names.add(profile_name)
                    except Exception as e:
                        # If error loading custom profile, fall back to builtin
                        self.runner_logger.log_warning(
                            f"Error loading profile '{profile_name}': {e}, treating as builtin",
                            {"prefix": self.runner_logger.PREFIX, "action": "PROFILE", "profile_name": profile_name},
                        )
                        if profile_name not in seen_profile_names:
                            profile_list.append(profile_name)
                            seen_profile_names.add(profile_name)

            # Set the profiles list in secator_config
            if profile_list:
                secator_config["profiles"] = profile_list

        secator_config["sync"] = False
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
            template = self._load_scan_template(scan_type)

            result = self._execute_runner(
                runner_class=Scan,
                config=template,
                targets=targets,
                scan_history_id=scan_history_id,
                domain_id=domain_id,
                run_config=config,
                profiles=profiles,
                runner_name=scan_type,
            )

            return result

        except Exception as e:
            self.runner_logger.log_runner_error("Scan", e, {"runner_name": scan_type})
            return {
                "status": "error",
                "scan_type": scan_type,
                "targets": targets,
                "error": str(e),
                "scan_history_id": scan_history_id,
            }
