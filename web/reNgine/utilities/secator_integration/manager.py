"""
Secator workflow manager for reNgine integration.

This module manages Secator workflows, providing functionality to load,
save, and execute workflows within the reNgine ecosystem.
"""

import os
import time
from typing import Any, Dict, List, Optional

from celery.utils.log import get_task_logger
import yaml

from .config import ensure_secator_initialized
from .converter import ReNgineToSecatorConverter


logger = get_task_logger(__name__)


class SecatorWorkflowManager:
    """
    Manager for Secator workflows in reNgine.

    This class provides functionality to manage Secator workflows,
    including loading, saving, and converting from legacy scan engines.
    """

    def __init__(self):
        self.converter = ReNgineToSecatorConverter()
        self._workflows_cache: Dict[str, Dict[str, Any]] = {}
        self._initialized = False

    def initialize(self) -> None:
        """Initialize the workflow manager."""
        if not self._initialized:
            ensure_secator_initialized()
            self._initialized = True
            logger.info("Secator workflow manager initialized")

    def load_workflow(self, workflow_path: str) -> Dict[str, Any]:
        """
        Load a Secator workflow from file.

        Args:
            workflow_path: Path to the workflow YAML file

        Returns:
            Dict containing the workflow configuration
        """
        try:
            with open(workflow_path, "r", encoding="utf-8") as f:
                workflow = yaml.safe_load(f)

            # Validate workflow structure
            self._validate_workflow(workflow)

            # Cache the workflow
            workflow_name = workflow.get("name", os.path.basename(workflow_path))
            self._workflows_cache[workflow_name] = workflow

            logger.info(f"Loaded Secator workflow: {workflow_name}")
            return workflow

        except Exception as e:
            logger.error(f"Failed to load workflow from {workflow_path}: {e}")
            raise

    def save_workflow(self, workflow: Dict[str, Any], workflow_path: str) -> None:
        """
        Save a Secator workflow to file.

        Args:
            workflow: Workflow configuration
            workflow_path: Path to save the workflow
        """
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(workflow_path), exist_ok=True)

            # Validate workflow structure
            self._validate_workflow(workflow)

            # Save workflow
            with open(workflow_path, "w", encoding="utf-8") as f:
                yaml.dump(workflow, f, default_flow_style=False, sort_keys=False)

            # Cache the workflow
            workflow_name = workflow.get("name", os.path.basename(workflow_path))
            self._workflows_cache[workflow_name] = workflow

            logger.info(f"Saved Secator workflow: {workflow_name}")

        except Exception as e:
            logger.error(f"Failed to save workflow to {workflow_path}: {e}")
            raise

    def get_workflow(self, workflow_name: str) -> Optional[Dict[str, Any]]:
        """
        Get a cached workflow by name.

        Args:
            workflow_name: Name of the workflow

        Returns:
            Workflow configuration or None if not found
        """
        return self._workflows_cache.get(workflow_name)

    def list_workflows(self, workflow_dir: str) -> List[Dict[str, Any]]:
        """
        List all available workflows in a directory.

        Args:
            workflow_dir: Directory containing workflow files

        Returns:
            List of workflow information
        """
        workflows = []

        try:
            if not os.path.exists(workflow_dir):
                return workflows

            for filename in os.listdir(workflow_dir):
                if filename.endswith(".yaml") and not filename.startswith("."):
                    workflow_path = os.path.join(workflow_dir, filename)

                    try:
                        workflow = self.load_workflow(workflow_path)
                        workflows.append(
                            {
                                "name": workflow.get("name", filename),
                                "description": workflow.get("description", ""),
                                "tags": workflow.get("tags", []),
                                "input_types": workflow.get("input_types", []),
                                "file_path": workflow_path,
                                "filename": filename,
                            }
                        )
                    except Exception as e:
                        logger.warning(f"Failed to load workflow {filename}: {e}")
                        continue

            logger.info(f"Found {len(workflows)} workflows in {workflow_dir}")
            return workflows

        except Exception as e:
            logger.error(f"Failed to list workflows in {workflow_dir}: {e}")
            return []

    def convert_legacy_scan_engine(self, scan_engine_path: str, output_dir: str) -> Dict[str, Any]:
        """
        Convert a legacy reNgine scan engine to Secator workflow.

        Args:
            scan_engine_path: Path to the legacy scan engine file
            output_dir: Directory to save the converted workflow

        Returns:
            Dict containing conversion information
        """
        try:
            # Convert the scan engine
            secator_workflow = self.converter.convert_scan_engine_file(scan_engine_path)

            # Generate output filename
            filename = os.path.basename(scan_engine_path)
            output_path = os.path.join(output_dir, filename)

            # Save the converted workflow
            self.save_workflow(secator_workflow, output_path)

            logger.info(f"Converted legacy scan engine: {filename}")

            return {
                "success": True,
                "source_file": scan_engine_path,
                "output_file": output_path,
                "workflow_name": secator_workflow.get("name", ""),
                "tasks_count": len(secator_workflow.get("tasks", {})),
            }

        except Exception as e:
            logger.error(f"Failed to convert legacy scan engine {scan_engine_path}: {e}")
            return {"success": False, "source_file": scan_engine_path, "error": str(e)}

    def convert_all_legacy_scan_engines(self, source_dir: str, output_dir: str) -> List[Dict[str, Any]]:
        """
        Convert all legacy scan engines in a directory to Secator workflows.

        Args:
            source_dir: Directory containing legacy scan engine files
            output_dir: Directory to save converted workflows

        Returns:
            List of conversion results
        """
        conversion_results = []

        try:
            if not os.path.exists(source_dir):
                logger.warning(f"Source directory does not exist: {source_dir}")
                return conversion_results

            # Ensure output directory exists
            os.makedirs(output_dir, exist_ok=True)

            for filename in os.listdir(source_dir):
                if filename.endswith(".yaml") and not filename.startswith("."):
                    source_path = os.path.join(source_dir, filename)

                    # Convert the scan engine
                    result = self.convert_legacy_scan_engine(source_path, output_dir)
                    conversion_results.append(result)

            successful_conversions = sum(1 for r in conversion_results if r.get("success", False))
            logger.info(f"Converted {successful_conversions}/{len(conversion_results)} legacy scan engines")

            return conversion_results

        except Exception as e:
            logger.error(f"Failed to convert legacy scan engines: {e}")
            return []

    def create_workflow_from_template(
        self, template_name: str, custom_config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create a workflow from a predefined template.

        Args:
            template_name: Name of the template to use
            custom_config: Custom configuration to override template defaults

        Returns:
            Dict containing the created workflow
        """
        try:
            # Get template
            template = self._get_workflow_template(template_name)
            if not template:
                raise ValueError(f"Unknown workflow template: {template_name}")

            # Apply custom configuration
            if custom_config:
                template = self._merge_configurations(template, custom_config)

            # Generate unique name
            template["name"] = f"{template_name}_{int(time.time())}"

            logger.info(f"Created workflow from template: {template_name}")
            return template

        except Exception as e:
            logger.error(f"Failed to create workflow from template {template_name}: {e}")
            raise

    def _validate_workflow(self, workflow: Dict[str, Any]) -> None:
        """
        Validate workflow structure.

        Args:
            workflow: Workflow configuration to validate
        """
        required_fields = ["type", "name", "tasks"]

        for field in required_fields:
            if field not in workflow:
                raise ValueError(f"Missing required field: {field}")

        if workflow["type"] != "workflow":
            raise ValueError("Invalid workflow type")

        if not isinstance(workflow["tasks"], dict):
            raise ValueError("Tasks must be a dictionary")

        if not workflow["tasks"]:
            raise ValueError("Workflow must have at least one task")

    def _get_workflow_template(self, template_name: str) -> Optional[Dict[str, Any]]:
        """
        Get a predefined workflow template.

        Args:
            template_name: Name of the template

        Returns:
            Template configuration or None if not found
        """
        templates = {
            "bug_bounty_basic": {
                "type": "workflow",
                "name": "bug_bounty_basic",
                "description": "Basic bug bounty reconnaissance workflow",
                "tags": ["bug_bounty", "recon"],
                "input_types": ["domain"],
                "tasks": {
                    "subfinder": {"description": "Subdomain discovery", "rate_limit": 30, "timeout": 5},
                    "naabu": {
                        "description": "Port scanning",
                        "rate_limit": 150,
                        "ports": "top-1000",
                        "targets_": [{"type": "subdomain", "field": "host"}],
                    },
                    "httpx": {
                        "description": "HTTP probing",
                        "targets_": [
                            {"type": "port", "field": "host:port", "condition": "item.port in [80, 443, 8080, 8443]"}
                        ],
                    },
                },
            },
            "internal_network_basic": {
                "type": "workflow",
                "name": "internal_network_basic",
                "description": "Basic internal network reconnaissance workflow",
                "tags": ["internal", "network"],
                "input_types": ["ip_range"],
                "tasks": {
                    "naabu": {"description": "Port scanning", "rate_limit": 150, "ports": "top-1000"},
                    "nmap": {
                        "description": "Service detection",
                        "targets_": [{"type": "port", "field": "host:port"}],
                        "script": "banner,version,discovery",
                    },
                },
            },
            "vulnerability_scan_basic": {
                "type": "workflow",
                "name": "vulnerability_scan_basic",
                "description": "Basic vulnerability scanning workflow",
                "tags": ["vulnerability", "security"],
                "input_types": ["url"],
                "tasks": {
                    "nuclei": {
                        "description": "Vulnerability scanning",
                        "rate_limit": 150,
                        "timeout": 5,
                        "targets_": [{"type": "url", "field": "url", "condition": "item.status_code == 200"}],
                    }
                },
            },
        }

        return templates.get(template_name)

    def _merge_configurations(self, base_config: Dict[str, Any], custom_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge custom configuration with base configuration.

        Args:
            base_config: Base configuration
            custom_config: Custom configuration to merge

        Returns:
            Merged configuration
        """
        import copy

        merged = copy.deepcopy(base_config)

        for key, value in custom_config.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = self._merge_configurations(merged[key], value)
            else:
                merged[key] = value

        return merged

    def get_workflow_statistics(self, workflow_dir: str) -> Dict[str, Any]:
        """
        Get statistics about workflows in a directory.

        Args:
            workflow_dir: Directory containing workflow files

        Returns:
            Dict containing workflow statistics
        """
        try:
            workflows = self.list_workflows(workflow_dir)

            if not workflows:
                return {
                    "total_workflows": 0,
                    "workflows_by_tag": {},
                    "workflows_by_input_type": {},
                    "average_tasks_per_workflow": 0,
                }

            # Calculate statistics
            total_workflows = len(workflows)

            # Count by tags
            workflows_by_tag = {}
            for workflow in workflows:
                for tag in workflow.get("tags", []):
                    workflows_by_tag[tag] = workflows_by_tag.get(tag, 0) + 1

            # Count by input types
            workflows_by_input_type = {}
            for workflow in workflows:
                for input_type in workflow.get("input_types", []):
                    workflows_by_input_type[input_type] = workflows_by_input_type.get(input_type, 0) + 1

            # Calculate average tasks per workflow
            total_tasks = 0
            for workflow in workflows:
                workflow_config = self.get_workflow(workflow["name"])
                if workflow_config:
                    total_tasks += len(workflow_config.get("tasks", {}))

            average_tasks = total_tasks / total_workflows if total_workflows > 0 else 0

            return {
                "total_workflows": total_workflows,
                "workflows_by_tag": workflows_by_tag,
                "workflows_by_input_type": workflows_by_input_type,
                "average_tasks_per_workflow": round(average_tasks, 2),
            }

        except Exception as e:
            logger.error(f"Failed to get workflow statistics: {e}")
            return {}


# Global workflow manager instance
_workflow_manager = None


def get_workflow_manager() -> SecatorWorkflowManager:
    """Get the global workflow manager instance."""
    global _workflow_manager
    if _workflow_manager is None:
        _workflow_manager = SecatorWorkflowManager()
        _workflow_manager.initialize()
    return _workflow_manager
