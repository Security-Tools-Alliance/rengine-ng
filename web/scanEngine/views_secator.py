"""
Secator integration views for scan engine management.

This module provides Django views for managing Secator workflows,
including migration from legacy scan engines and workflow visualization.
"""

import json
import os
from typing import Any, Dict, List

from celery.utils.log import get_task_logger
from django.conf import settings
from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from reNgine.tasks.secator_integration import convert_all_legacy_engines, migrate_scan_engine_to_secator
from reNgine.utilities.secator_integration import get_workflow_manager

from .models import EngineType


logger = get_task_logger(__name__)


class SecatorWorkflowListView(View):
    """View for listing Secator workflows."""

    def get(self, request):
        """Display list of Secator workflows."""
        try:
            workflow_manager = get_workflow_manager()
            workflows_dir = os.path.join(settings.BASE_DIR, "config", "secator_workflows")

            # Get workflows from directory
            workflows = workflow_manager.list_workflows(workflows_dir)

            # Get workflow statistics
            statistics = workflow_manager.get_workflow_statistics(workflows_dir)

            context = {"workflows": workflows, "statistics": statistics, "workflows_dir": workflows_dir}

            return render(request, "scanEngine/secator_workflow_list.html", context)

        except Exception as e:
            messages.error(request, f"Error loading workflows: {e}")
            return render(
                request, "scanEngine/secator_workflow_list.html", {"workflows": [], "statistics": {}, "error": str(e)}
            )


class SecatorWorkflowDetailView(View):
    """View for displaying Secator workflow details."""

    def get(self, request, workflow_name):
        """Display workflow details and visualization."""
        try:
            workflow_manager = get_workflow_manager()

            # Get workflow configuration
            workflow_config = workflow_manager.get_workflow(workflow_name)
            if not workflow_config:
                # Try to load from file
                workflow_path = os.path.join(settings.BASE_DIR, "config", "secator_workflows", f"{workflow_name}.yaml")
                if os.path.exists(workflow_path):
                    workflow_config = workflow_manager.load_workflow(workflow_path)
                else:
                    messages.error(request, f"Workflow not found: {workflow_name}")
                    return redirect("secator_workflow_list")

            # Get visualization data
            visualization_data = self._get_workflow_visualization_data(workflow_config)

            context = {
                "workflow_name": workflow_name,
                "workflow_config": workflow_config,
                "visualization_data": visualization_data,
                "workflow_json": json.dumps(workflow_config, indent=2),
            }

            return render(request, "scanEngine/secator_workflow_detail.html", context)

        except Exception as e:
            messages.error(request, f"Error loading workflow: {e}")
            return redirect("secator_workflow_list")

    def _get_workflow_visualization_data(self, workflow_config: Dict[str, Any]) -> Dict[str, Any]:
        """Get visualization data for workflow."""
        tasks = workflow_config.get("tasks", {})

        return {
            "name": workflow_config.get("name", ""),
            "description": workflow_config.get("description", ""),
            "tags": workflow_config.get("tags", []),
            "input_types": workflow_config.get("input_types", []),
            "tasks": [
                {
                    "name": task_name,
                    "description": task_config.get("description", ""),
                    "rate_limit": task_config.get("rate_limit"),
                    "timeout": task_config.get("timeout"),
                    "targets": task_config.get("targets_", []),
                    "dependencies": self._get_task_dependencies(task_name, tasks),
                }
                for task_name, task_config in tasks.items()
            ],
        }

    def _get_task_dependencies(self, task_name: str, tasks: Dict[str, Any]) -> List[str]:
        """Get task dependencies based on targets."""
        dependencies = []
        task_config = tasks.get(task_name, {})
        targets = task_config.get("targets_", [])

        for target in targets:
            target_type = target.get("type", "")
            if target_type in ["subdomain", "port", "url"]:
                # Find tasks that produce this type of output
                for other_task_name, other_task_config in tasks.items():
                    if other_task_name != task_name:
                        # Simple heuristic: tasks earlier in the workflow likely produce outputs
                        if other_task_name in ["subfinder", "naabu", "httpx"]:
                            dependencies.append(other_task_name)

        return list(set(dependencies))


class SecatorMigrationView(View):
    """View for migrating legacy scan engines to Secator workflows."""

    def get(self, request):
        """Display migration interface."""
        try:
            # Get all legacy scan engines
            legacy_engines = EngineType.objects.all()

            # Get migration status for each engine
            migration_status = []
            for engine in legacy_engines:
                status = {
                    "engine": engine,
                    "can_migrate": bool(engine.yaml_configuration),
                    "has_secator_equivalent": self._check_secator_equivalent(engine),
                }
                migration_status.append(status)

            context = {"legacy_engines": legacy_engines, "migration_status": migration_status}

            return render(request, "scanEngine/secator_migration.html", context)

        except Exception as e:
            messages.error(request, f"Error loading migration interface: {e}")
            return render(
                request,
                "scanEngine/secator_migration.html",
                {"legacy_engines": [], "migration_status": [], "error": str(e)},
            )

    def _check_secator_equivalent(self, engine: EngineType) -> bool:
        """Check if engine has a Secator equivalent."""
        try:
            workflow_name = engine.engine_name.lower().replace(" ", "_")
            workflow_path = os.path.join(settings.BASE_DIR, "config", "secator_workflows", f"{workflow_name}.yaml")
            return os.path.exists(workflow_path)
        except Exception:
            return False


@method_decorator(csrf_exempt, name="dispatch")
class SecatorMigrationAPIView(View):
    """API view for handling Secator migration requests."""

    def post(self, request):
        """Handle migration request."""
        try:
            data = json.loads(request.body)
            action = data.get("action")

            if action == "migrate_single":
                return self._migrate_single_engine(data)
            elif action == "migrate_all":
                return self._migrate_all_engines(data)
            elif action == "convert_directory":
                return self._convert_directory(data)
            else:
                return JsonResponse({"success": False, "error": f"Unknown action: {action}"})

        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)})

    def _migrate_single_engine(self, data: Dict[str, Any]) -> JsonResponse:
        """Migrate a single scan engine."""
        try:
            engine_id = data.get("engine_id")
            if not engine_id:
                return JsonResponse({"success": False, "error": "Engine ID is required"})

            # Start migration task
            task = migrate_scan_engine_to_secator.delay(engine_id)

            return JsonResponse({"success": True, "message": "Migration started", "task_id": task.id})

        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)})

    def _migrate_all_engines(self, data: Dict[str, Any]) -> JsonResponse:
        """Migrate all scan engines."""
        try:
            # Get all engines that can be migrated
            engines = EngineType.objects.filter(yaml_configuration__isnull=False)

            if not engines.exists():
                return JsonResponse({"success": False, "error": "No engines available for migration"})

            # Start migration tasks for each engine
            task_ids = []
            for engine in engines:
                task = migrate_scan_engine_to_secator.delay(engine.id)
                task_ids.append(task.id)

            return JsonResponse(
                {"success": True, "message": f"Migration started for {len(engines)} engines", "task_ids": task_ids}
            )

        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)})

    def _convert_directory(self, data: Dict[str, Any]) -> JsonResponse:
        """Convert all engines in a directory."""
        try:
            source_dir = data.get("source_dir")
            target_dir = data.get("target_dir")

            if not source_dir or not target_dir:
                return JsonResponse({"success": False, "error": "Source and target directories are required"})

            # Start conversion task
            task = convert_all_legacy_engines.delay(source_dir, target_dir)

            return JsonResponse({"success": True, "message": "Directory conversion started", "task_id": task.id})

        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)})


class SecatorWorkflowEditorView(View):
    """View for editing Secator workflows."""

    def get(self, request, workflow_name=None):
        """Display workflow editor."""
        try:
            workflow_config = None
            if workflow_name:
                workflow_manager = get_workflow_manager()
                workflow_config = workflow_manager.get_workflow(workflow_name)

                if not workflow_config:
                    # Try to load from file
                    workflow_path = os.path.join(
                        settings.BASE_DIR, "config", "secator_workflows", f"{workflow_name}.yaml"
                    )
                    if os.path.exists(workflow_path):
                        workflow_config = workflow_manager.load_workflow(workflow_path)

            # Get available templates
            templates = self._get_available_templates()

            context = {
                "workflow_name": workflow_name,
                "workflow_config": workflow_config,
                "workflow_json": json.dumps(workflow_config, indent=2) if workflow_config else "{}",
                "templates": templates,
            }

            return render(request, "scanEngine/secator_workflow_editor.html", context)

        except Exception as e:
            messages.error(request, f"Error loading workflow editor: {e}")
            return render(
                request,
                "scanEngine/secator_workflow_editor.html",
                {
                    "workflow_name": workflow_name,
                    "workflow_config": None,
                    "workflow_json": "{}",
                    "templates": [],
                    "error": str(e),
                },
            )

    def post(self, request, workflow_name=None):
        """Save workflow changes."""
        try:
            data = json.loads(request.body)
            action = data.get("action")

            if action == "save_workflow":
                return self._save_workflow(data)
            elif action == "create_from_template":
                return self._create_from_template(data)
            else:
                return JsonResponse({"success": False, "error": f"Unknown action: {action}"})

        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)})

    def _save_workflow(self, data: Dict[str, Any]) -> JsonResponse:
        """Save workflow configuration."""
        try:
            workflow_config = data.get("workflow_config")
            workflow_name = data.get("workflow_name")

            if not workflow_config or not workflow_name:
                return JsonResponse({"success": False, "error": "Workflow configuration and name are required"})

            # Validate workflow structure
            if not workflow_config.get("type") == "workflow":
                return JsonResponse({"success": False, "error": "Invalid workflow type"})

            if not workflow_config.get("tasks"):
                return JsonResponse({"success": False, "error": "Workflow must have at least one task"})

            # Save workflow
            workflow_manager = get_workflow_manager()
            workflow_path = os.path.join(settings.BASE_DIR, "config", "secator_workflows", f"{workflow_name}.yaml")

            workflow_manager.save_workflow(workflow_config, workflow_path)

            return JsonResponse({"success": True, "message": f"Workflow {workflow_name} saved successfully"})

        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)})

    def _create_from_template(self, data: Dict[str, Any]) -> JsonResponse:
        """Create workflow from template."""
        try:
            template_name = data.get("template_name")
            custom_config = data.get("custom_config", {})

            if not template_name:
                return JsonResponse({"success": False, "error": "Template name is required"})

            # Create workflow from template
            workflow_manager = get_workflow_manager()
            workflow = workflow_manager.create_workflow_from_template(template_name, custom_config)

            return JsonResponse(
                {"success": True, "workflow": workflow, "message": f"Workflow created from template: {template_name}"}
            )

        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)})

    def _get_available_templates(self) -> List[Dict[str, Any]]:
        """Get available workflow templates."""
        return [
            {
                "name": "bug_bounty_basic",
                "description": "Basic bug bounty reconnaissance workflow",
                "tags": ["bug_bounty", "recon"],
            },
            {
                "name": "internal_network_basic",
                "description": "Basic internal network reconnaissance workflow",
                "tags": ["internal", "network"],
            },
            {
                "name": "vulnerability_assessment",
                "description": "Comprehensive vulnerability assessment workflow",
                "tags": ["vulnerability", "security"],
            },
        ]


class SecatorWorkflowVisualizationView(View):
    """View for workflow visualization."""

    def get(self, request, workflow_name):
        """Display workflow visualization."""
        try:
            workflow_manager = get_workflow_manager()

            # Get workflow configuration
            workflow_config = workflow_manager.get_workflow(workflow_name)
            if not workflow_config:
                # Try to load from file
                workflow_path = os.path.join(settings.BASE_DIR, "config", "secator_workflows", f"{workflow_name}.yaml")
                if os.path.exists(workflow_path):
                    workflow_config = workflow_manager.load_workflow(workflow_path)
                else:
                    messages.error(request, f"Workflow not found: {workflow_name}")
                    return redirect("secator_workflow_list")

            # Generate visualization data
            visualization_data = self._generate_visualization_data(workflow_config)

            context = {
                "workflow_name": workflow_name,
                "workflow_config": workflow_config,
                "visualization_data": json.dumps(visualization_data),
            }

            return render(request, "scanEngine/secator_workflow_visualization.html", context)

        except Exception as e:
            messages.error(request, f"Error generating visualization: {e}")
            return redirect("secator_workflow_list")

    def _generate_visualization_data(self, workflow_config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate data for workflow visualization."""
        tasks = workflow_config.get("tasks", {})

        # Create nodes for each task
        nodes = []
        edges = []

        for i, (task_name, task_config) in enumerate(tasks.items()):
            node = {
                "id": task_name,
                "label": task_name,
                "description": task_config.get("description", ""),
                "rate_limit": task_config.get("rate_limit"),
                "timeout": task_config.get("timeout"),
                "x": i * 200,
                "y": 100,
            }
            nodes.append(node)

            # Create edges based on targets
            targets = task_config.get("targets_", [])
            for target in targets:
                target_type = target.get("type", "")
                if target_type in ["subdomain", "port", "url"]:
                    # Find source task for this target type
                    for source_task_name in tasks.keys():
                        if source_task_name != task_name:
                            # Simple heuristic for dependencies
                            if (
                                (target_type == "subdomain" and source_task_name == "subfinder")
                                or (target_type == "port" and source_task_name == "naabu")
                                or (target_type == "url" and source_task_name == "httpx")
                            ):
                                edges.append({"from": source_task_name, "to": task_name, "label": target_type})
                                break

        return {
            "nodes": nodes,
            "edges": edges,
            "workflow_info": {
                "name": workflow_config.get("name", ""),
                "description": workflow_config.get("description", ""),
                "tags": workflow_config.get("tags", []),
                "input_types": workflow_config.get("input_types", []),
            },
        }
