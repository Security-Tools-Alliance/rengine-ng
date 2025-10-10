"""
Secator Workflow Management Views.

This module provides Django views for managing Secator workflows,
including visualization, editing, and execution management.
"""

import json
import os
from typing import Any, Dict

from celery.utils.log import get_task_logger
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
import yaml

from reNgine.utilities.secator_integration.builtin_workflows import SecatorBuiltinWorkflowManager
from reNgine.utilities.secator_integration.manager import SecatorWorkflowManager

from .models import ScanEngine


logger = get_task_logger(__name__)


@method_decorator(login_required, name="dispatch")
class SecatorWorkflowListView(View):
    """View for listing and managing Secator workflows."""

    def get(self, request):
        """Display list of Secator workflows with filtering options."""
        try:
            # Get workflow managers
            workflow_manager = SecatorWorkflowManager()
            builtin_manager = SecatorBuiltinWorkflowManager()

            # Get custom workflows
            workflows_dir = os.path.join(settings.BASE_DIR, "config", "secator_workflows")
            custom_workflows = workflow_manager.list_workflows(workflows_dir)
            # Ensure custom workflows have workflow_id and workflow_type
            for workflow in custom_workflows:
                workflow["workflow_id"] = workflow.get("name", os.path.splitext(workflow.get("filename", "unknown"))[0])
                workflow["workflow_type"] = "custom"

            # Get built-in workflows
            builtin_workflows = builtin_manager.list_builtin_workflows()
            # Ensure built-in workflows have workflow_id and workflow_type
            for workflow in builtin_workflows:
                workflow["workflow_id"] = workflow.get("id", "unknown")
                workflow["workflow_type"] = "builtin"

            # Get scan engines using Secator workflows
            secator_engines = ScanEngine.objects.filter(workflow_mode="secator")

            # Filter parameters
            workflow_type = request.GET.get("type", "all")  # all, custom, builtin, engines
            search_query = request.GET.get("search", "")

            # Filter workflows based on type
            if workflow_type == "custom":
                workflows = custom_workflows
            elif workflow_type == "builtin":
                workflows = builtin_workflows
            elif workflow_type == "engines":
                workflows = []
                for engine in secator_engines:
                    if engine.secator_builtin_workflow:
                        # Find corresponding builtin workflow
                        for builtin in builtin_workflows:
                            if builtin["id"] == engine.secator_builtin_workflow:
                                workflows.append(
                                    {
                                        "name": engine.name,
                                        "description": engine.description,
                                        "type": "builtin_engine",
                                        "workflow_id": builtin["id"],
                                        "engine_id": engine.id,
                                        "input_type": builtin["input_type"],
                                        "use_cases": builtin["use_cases"],
                                        "tools": builtin["tools"],
                                    }
                                )
                                break
                    elif engine.custom_secator_workflow_file:
                        # Find corresponding custom workflow
                        for custom in custom_workflows:
                            if custom["filename"] == os.path.basename(engine.custom_secator_workflow_file.name):
                                # Use filename without extension as workflow_id if name is empty
                                workflow_id = custom.get("name") or os.path.splitext(custom["filename"])[0]
                                workflows.append(
                                    {
                                        "name": engine.name,
                                        "description": engine.description,
                                        "type": "custom_engine",
                                        "workflow_id": workflow_id,
                                        "engine_id": engine.id,
                                        "input_type": custom.get("input_types", []),
                                        "tags": custom.get("tags", []),
                                    }
                                )
                                break
            else:  # all
                workflows = custom_workflows + builtin_workflows

            # Ensure all workflows have valid workflow_id and workflow_type
            for workflow in workflows:
                if not workflow.get("workflow_id"):
                    if workflow.get("name"):
                        workflow["workflow_id"] = workflow["name"].replace(" ", "_").lower()
                    else:
                        workflow["workflow_id"] = "unknown_workflow"

                # Ensure workflow_type is set
                if not workflow.get("workflow_type"):
                    if "id" in workflow:  # Built-in workflow
                        workflow["workflow_type"] = "builtin"
                    elif "filename" in workflow:  # Custom workflow
                        workflow["workflow_type"] = "custom"
                    else:
                        workflow["workflow_type"] = "unknown"

            # Apply search filter
            if search_query:
                workflows = [
                    w
                    for w in workflows
                    if search_query.lower() in w.get("name", "").lower()
                    or search_query.lower() in w.get("description", "").lower()
                ]

            # Pagination
            paginator = Paginator(workflows, 12)
            page_number = request.GET.get("page")
            page_obj = paginator.get_page(page_number)

            context = {
                "page_obj": page_obj,
                "workflow_type": workflow_type,
                "search_query": search_query,
                "custom_count": len(custom_workflows),
                "builtin_count": len(builtin_workflows),
                "engine_count": secator_engines.count(),
                "total_count": len(custom_workflows) + len(builtin_workflows) + secator_engines.count(),
            }

            return render(request, "scanEngine/secator_workflows/list_ajax.html", context)

        except Exception as e:
            logger.error(f"Error in SecatorWorkflowListView: {e}")
            messages.error(request, f"Error loading workflows: {str(e)}")
            return render(request, "scanEngine/secator_workflows/list.html", {"page_obj": None})


@method_decorator(login_required, name="dispatch")
class SecatorWorkflowDetailView(View):
    """View for displaying and editing a specific Secator workflow."""

    def get(self, request, workflow_id, workflow_type="custom"):
        """Display workflow details and visualization."""
        try:
            workflow_manager = SecatorWorkflowManager()
            builtin_manager = SecatorBuiltinWorkflowManager()

            workflow_data = None
            workflow_config = None

            if workflow_type == "builtin":
                # Get built-in workflow
                workflow_data = builtin_manager.get_workflow_info(workflow_id)
                if not workflow_data:
                    messages.error(request, f"Built-in workflow '{workflow_id}' not found.")
                    return redirect("secator_workflow_list")

                # Create a mock workflow config for visualization
                workflow_config = {
                    "name": workflow_data["name"],
                    "description": workflow_data["description"],
                    "type": "builtin",
                    "workflow_id": workflow_id,
                    "workflow_type": "builtin",
                    "input_type": workflow_data["input_type"],
                    "use_cases": workflow_data["use_cases"],
                    "tools": workflow_data["tools"],
                }

            elif workflow_type == "custom":
                # Get custom workflow
                workflows_dir = os.path.join(settings.BASE_DIR, "config", "secator_workflows")
                workflow_path = os.path.join(workflows_dir, f"{workflow_id}.yaml")

                if not os.path.exists(workflow_path):
                    messages.error(request, f"Custom workflow '{workflow_id}' not found.")
                    return redirect("secator_workflow_list")

                workflow_config = workflow_manager.load_workflow(workflow_path)
                workflow_data = workflow_config
                # Ensure workflow_id and workflow_type are set
                workflow_config["workflow_id"] = workflow_id
                workflow_config["workflow_type"] = "custom"

            elif workflow_type == "engine":
                # Get workflow from scan engine
                engine = get_object_or_404(ScanEngine, id=workflow_id)
                if engine.workflow_mode != "secator":
                    messages.error(request, "This scan engine does not use Secator workflows.")
                    return redirect("secator_workflow_list")

                if engine.secator_builtin_workflow:
                    workflow_data = builtin_manager.get_workflow_info(engine.secator_builtin_workflow)
                    workflow_config = {
                        "name": engine.name,
                        "description": engine.description,
                        "type": "builtin_engine",
                        "workflow_id": engine.secator_builtin_workflow,
                        "workflow_type": "builtin_engine",
                        "engine_id": engine.id,
                        "input_type": workflow_data["input_type"],
                        "use_cases": workflow_data["use_cases"],
                        "tools": workflow_data["tools"],
                    }
                elif engine.custom_secator_workflow_file:
                    workflow_path = engine.custom_secator_workflow_file.path
                    workflow_config = workflow_manager.load_workflow(workflow_path)
                    workflow_data = workflow_config
                    workflow_config["engine_id"] = engine.id
                    workflow_config["type"] = "custom_engine"
                    workflow_config["workflow_id"] = workflow_id
                    workflow_config["workflow_type"] = "custom_engine"

            if not workflow_config:
                messages.error(request, "Workflow configuration not found.")
                return redirect("secator_workflow_list")

            # Generate workflow visualization data
            visualization_data = self._generate_workflow_visualization(workflow_config)

            context = {
                "workflow": workflow_config,
                "workflow_data": workflow_data,
                "workflow_type": workflow_type,
                "visualization": json.dumps(visualization_data),
                "can_edit": workflow_type in ["custom", "engine"]
                and request.user.has_perm("scanEngine.modify_scan_configurations"),
            }

            return render(request, "scanEngine/secator_workflows/detail.html", context)

        except Exception as e:
            logger.error(f"Error in SecatorWorkflowDetailView: {e}")
            messages.error(request, f"Error loading workflow: {str(e)}")
            return redirect("secator_workflow_list")

    def _generate_workflow_visualization(self, workflow_config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate visualization data for workflow execution flow."""
        try:
            if workflow_config.get("type") == "builtin" or workflow_config.get("type") == "builtin_engine":
                # For built-in workflows, create a simple linear flow
                tools = workflow_config.get("tools", [])
                return {
                    "type": "linear",
                    "nodes": [
                        {"id": f"tool_{i}", "name": tool, "type": "tool", "position": {"x": i * 200, "y": 100}}
                        for i, tool in enumerate(tools)
                    ],
                    "edges": [
                        {"id": f"edge_{i}", "source": f"tool_{i}", "target": f"tool_{i + 1}", "type": "sequential"}
                        for i in range(len(tools) - 1)
                    ],
                }
            else:
                # For custom workflows, parse the tasks structure
                tasks = workflow_config.get("tasks", {})
                nodes = []
                edges = []

                # Create nodes for each task
                for i, (task_name, task_config) in enumerate(tasks.items()):
                    nodes.append(
                        {
                            "id": task_name,
                            "name": task_name,
                            "type": "task",
                            "tool": task_config.get("tool", "unknown"),
                            "position": {"x": i * 200, "y": 100},
                            "config": task_config,
                        }
                    )

                # Create sequential edges
                task_names = list(tasks.keys())
                for i in range(len(task_names) - 1):
                    edges.append(
                        {"id": f"edge_{i}", "source": task_names[i], "target": task_names[i + 1], "type": "sequential"}
                    )

                return {"type": "custom", "nodes": nodes, "edges": edges}

        except Exception as e:
            logger.error(f"Error generating workflow visualization: {e}")
            return {"type": "error", "message": str(e)}


@method_decorator(login_required, name="dispatch")
class SecatorWorkflowEditView(View):
    """View for editing Secator workflow configurations."""

    def get(self, request, workflow_id, workflow_type="custom"):
        """Display workflow editing form."""
        try:
            workflow_manager = SecatorWorkflowManager()

            if workflow_type == "custom":
                workflows_dir = os.path.join(settings.BASE_DIR, "config", "secator_workflows")
                workflow_path = os.path.join(workflows_dir, f"{workflow_id}.yaml")

                if not os.path.exists(workflow_path):
                    messages.error(request, f"Custom workflow '{workflow_id}' not found.")
                    return redirect("secator_workflow_list")

                workflow_config = workflow_manager.load_workflow(workflow_path)

            elif workflow_type == "engine":
                engine = get_object_or_404(ScanEngine, id=workflow_id)
                if engine.workflow_mode != "secator" or not engine.custom_secator_workflow_file:
                    messages.error(request, "This scan engine does not have a custom Secator workflow.")
                    return redirect("secator_workflow_list")

                workflow_path = engine.custom_secator_workflow_file.path
                workflow_config = workflow_manager.load_workflow(workflow_path)
                workflow_config["engine_id"] = engine.id

            else:
                messages.error(request, "Invalid workflow type for editing.")
                return redirect("secator_workflow_list")

            context = {
                "workflow": workflow_config,
                "workflow_type": workflow_type,
                "workflow_yaml": yaml.dump(workflow_config, default_flow_style=False, sort_keys=False),
            }

            return render(request, "scanEngine/secator_workflows/edit.html", context)

        except Exception as e:
            logger.error(f"Error in SecatorWorkflowEditView GET: {e}")
            messages.error(request, f"Error loading workflow for editing: {str(e)}")
            return redirect("secator_workflow_list")

    def post(self, request, workflow_id, workflow_type="custom"):
        """Save workflow configuration changes."""
        try:
            if not request.user.has_perm("scanEngine.modify_scan_configurations"):
                messages.error(request, "You don't have permission to modify scan configurations.")
                return redirect("secator_workflow_list")

            workflow_manager = SecatorWorkflowManager()

            # Get the updated YAML content
            workflow_yaml = request.POST.get("workflow_yaml", "")
            if not workflow_yaml:
                messages.error(request, "No workflow configuration provided.")
                return redirect("secator_workflow_list")

            # Parse and validate YAML
            try:
                workflow_config = yaml.safe_load(workflow_yaml)
            except yaml.YAMLError as e:
                messages.error(request, f"Invalid YAML format: {str(e)}")
                return redirect("secator_workflow_list")

            # Validate workflow structure
            if "name" not in workflow_config or "type" not in workflow_config:
                messages.error(request, "Workflow must have 'name' and 'type' fields.")
                return redirect("secator_workflow_list")

            if workflow_type == "custom":
                # Save custom workflow
                workflows_dir = os.path.join(settings.BASE_DIR, "config", "secator_workflows")
                workflow_path = os.path.join(workflows_dir, f"{workflow_id}.yaml")
                workflow_manager.save_workflow(workflow_config, workflow_path)

            elif workflow_type == "engine":
                # Save engine workflow
                engine = get_object_or_404(ScanEngine, id=workflow_id)
                if engine.custom_secator_workflow_file:
                    workflow_path = engine.custom_secator_workflow_file.path
                    workflow_manager.save_workflow(workflow_config, workflow_path)

                    # Update engine description if name changed
                    if workflow_config.get("name") != engine.name:
                        engine.description = f"Custom Secator workflow: {workflow_config.get('name')}"
                        engine.save()

            messages.success(request, "Workflow configuration saved successfully.")
            return redirect("secator_workflow_detail", workflow_id=workflow_id, workflow_type=workflow_type)

        except Exception as e:
            logger.error(f"Error in SecatorWorkflowEditView POST: {e}")
            messages.error(request, f"Error saving workflow: {str(e)}")
            return redirect("secator_workflow_list")


@method_decorator(login_required, name="dispatch")
class SecatorWorkflowCreateView(View):
    """View for creating new Secator workflows."""

    def get(self, request):
        """Display workflow creation form."""
        if not request.user.has_perm("scanEngine.modify_scan_configurations"):
            messages.error(request, "You don't have permission to create scan configurations.")
            return redirect("secator_workflow_list")

        # Get template workflows for reference
        builtin_manager = SecatorBuiltinWorkflowManager()
        builtin_workflows = builtin_manager.list_builtin_workflows()

        context = {
            "builtin_workflows": builtin_workflows,
            "template_workflows": self._get_template_workflows(),
        }

        return render(request, "scanEngine/secator_workflows/create.html", context)

    def post(self, request):
        """Create new workflow."""
        try:
            if not request.user.has_perm("scanEngine.modify_scan_configurations"):
                messages.error(request, "You don't have permission to create scan configurations.")
                return redirect("secator_workflow_list")

            workflow_manager = SecatorWorkflowManager()

            # Get form data
            workflow_name = request.POST.get("workflow_name", "").strip()
            workflow_description = request.POST.get("workflow_description", "").strip()
            template_type = request.POST.get("template_type", "blank")

            if not workflow_name:
                messages.error(request, "Workflow name is required.")
                return redirect("secator_workflow_create")

            # Create workflow configuration
            if template_type == "blank":
                workflow_config = {
                    "name": workflow_name,
                    "description": workflow_description,
                    "type": "workflow",
                    "tasks": {},
                }
            elif template_type == "builtin":
                builtin_id = request.POST.get("builtin_template", "")
                builtin_manager = SecatorBuiltinWorkflowManager()
                builtin_metadata = builtin_manager.get_builtin_workflow_metadata(builtin_id)

                if builtin_metadata:
                    workflow_config = {
                        "name": workflow_name,
                        "description": workflow_description,
                        "type": "workflow",
                        "input_types": [builtin_metadata["input_type"]],
                        "tags": builtin_metadata["use_cases"],
                        "tasks": self._create_tasks_from_builtin(builtin_metadata),
                    }
                else:
                    messages.error(request, "Selected built-in template not found.")
                    return redirect("secator_workflow_create")
            else:
                # Use predefined template
                template_config = self._get_template_workflows().get(template_type, {})
                workflow_config = {
                    "name": workflow_name,
                    "description": workflow_description,
                    "type": "workflow",
                    **template_config,
                }

            # Save workflow
            workflows_dir = os.path.join(settings.BASE_DIR, "config", "secator_workflows")
            os.makedirs(workflows_dir, exist_ok=True)

            # Create safe filename
            safe_name = "".join(c for c in workflow_name if c.isalnum() or c in (" ", "-", "_")).rstrip()
            safe_name = safe_name.replace(" ", "_")
            workflow_path = os.path.join(workflows_dir, f"{safe_name}.yaml")

            workflow_manager.save_workflow(workflow_config, workflow_path)

            messages.success(request, f"Workflow '{workflow_name}' created successfully.")
            return redirect("secator_workflow_detail", workflow_id=safe_name, workflow_type="custom")

        except Exception as e:
            logger.error(f"Error in SecatorWorkflowCreateView POST: {e}")
            messages.error(request, f"Error creating workflow: {str(e)}")
            return redirect("secator_workflow_create")

    def _get_template_workflows(self) -> Dict[str, Dict[str, Any]]:
        """Get predefined workflow templates."""
        return {
            "subdomain_discovery": {
                "input_types": ["domain"],
                "tags": ["reconnaissance", "subdomain"],
                "tasks": {
                    "subfinder": {"tool": "subfinder", "args": ["-d", "{{target}}", "-silent"]},
                    "assetfinder": {"tool": "assetfinder", "args": ["-subs-only", "{{target}}"]},
                    "dnsx": {"tool": "dnsx", "args": ["-l", "{{subfinder.output}}", "-silent"]},
                },
            },
            "url_discovery": {
                "input_types": ["url"],
                "tags": ["web", "discovery"],
                "tasks": {
                    "katana": {"tool": "katana", "args": ["-u", "{{target}}", "-silent"]},
                    "gau": {"tool": "gau", "args": ["{{target}}"]},
                },
            },
            "vulnerability_scan": {
                "input_types": ["url"],
                "tags": ["vulnerability", "security"],
                "tasks": {
                    "nuclei": {"tool": "nuclei", "args": ["-u", "{{target}}", "-silent"]},
                    "httpx": {"tool": "httpx", "args": ["-l", "{{nuclei.output}}", "-silent"]},
                },
            },
        }

    def _create_tasks_from_builtin(self, builtin_metadata: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Create task configuration from built-in workflow metadata."""
        tasks = {}
        tools = builtin_metadata.get("tools", [])

        for i, tool in enumerate(tools):
            tasks[tool] = {"tool": tool, "args": ["{{target}}"]}

        return tasks


@method_decorator(login_required, name="dispatch")
class SecatorWorkflowDeleteView(View):
    """View for deleting Secator workflows."""

    def post(self, request, workflow_id, workflow_type="custom"):
        """Delete workflow."""
        try:
            if not request.user.has_perm("scanEngine.modify_scan_configurations"):
                messages.error(request, "You don't have permission to delete scan configurations.")
                return redirect("secator_workflow_list")

            if workflow_type == "custom":
                workflows_dir = os.path.join(settings.BASE_DIR, "config", "secator_workflows")
                workflow_path = os.path.join(workflows_dir, f"{workflow_id}.yaml")

                if os.path.exists(workflow_path):
                    os.remove(workflow_path)
                    messages.success(request, f"Workflow '{workflow_id}' deleted successfully.")
                else:
                    messages.error(request, f"Workflow '{workflow_id}' not found.")

            elif workflow_type == "engine":
                engine = get_object_or_404(ScanEngine, id=workflow_id)
                if engine.custom_secator_workflow_file:
                    # Delete the file
                    engine.custom_secator_workflow_file.delete()
                    # Reset engine to legacy mode
                    engine.workflow_mode = "legacy"
                    engine.custom_secator_workflow_file = None
                    engine.secator_workflow_name = None
                    engine.secator_builtin_workflow = None
                    engine.save()
                    messages.success(request, f"Custom workflow for engine '{engine.name}' deleted successfully.")
                else:
                    messages.error(request, "This engine does not have a custom workflow to delete.")
            else:
                messages.error(request, "Invalid workflow type for deletion.")

            return redirect("secator_workflow_list")

        except Exception as e:
            logger.error(f"Error in SecatorWorkflowDeleteView: {e}")
            messages.error(request, f"Error deleting workflow: {str(e)}")
            return redirect("secator_workflow_list")


@method_decorator(login_required, name="dispatch")
class SecatorWorkflowTaskConfigView(View):
    """View for configuring individual workflow tasks."""

    def get(self, request, workflow_id, task_id, workflow_type="custom"):
        """Display task configuration form."""
        try:
            workflow_manager = SecatorWorkflowManager()

            # Load workflow
            if workflow_type == "custom":
                workflows_dir = os.path.join(settings.BASE_DIR, "config", "secator_workflows")
                workflow_path = os.path.join(workflows_dir, f"{workflow_id}.yaml")
                workflow_config = workflow_manager.load_workflow(workflow_path)
            elif workflow_type == "engine":
                engine = get_object_or_404(ScanEngine, id=workflow_id)
                workflow_path = engine.custom_secator_workflow_file.path
                workflow_config = workflow_manager.load_workflow(workflow_path)
            else:
                messages.error(request, "Invalid workflow type.")
                return redirect("secator_workflow_list")

            # Get task configuration
            tasks = workflow_config.get("tasks", {})
            if task_id not in tasks:
                messages.error(request, f"Task '{task_id}' not found in workflow.")
                return redirect("secator_workflow_detail", workflow_id=workflow_id, workflow_type=workflow_type)

            task_config = tasks[task_id]

            context = {
                "workflow_id": workflow_id,
                "workflow_type": workflow_type,
                "task_id": task_id,
                "task_config": task_config,
                "workflow_name": workflow_config.get("name", "Unknown"),
            }

            return render(request, "scanEngine/secator_workflows/task_config.html", context)

        except Exception as e:
            logger.error(f"Error in SecatorWorkflowTaskConfigView GET: {e}")
            messages.error(request, f"Error loading task configuration: {str(e)}")
            return redirect("secator_workflow_list")

    def post(self, request, workflow_id, task_id, workflow_type="custom"):
        """Save task configuration changes."""
        try:
            if not request.user.has_perm("scanEngine.modify_scan_configurations"):
                messages.error(request, "You don't have permission to modify scan configurations.")
                return redirect("secator_workflow_list")

            workflow_manager = SecatorWorkflowManager()

            # Load workflow
            if workflow_type == "custom":
                workflows_dir = os.path.join(settings.BASE_DIR, "config", "secator_workflows")
                workflow_path = os.path.join(workflows_dir, f"{workflow_id}.yaml")
                workflow_config = workflow_manager.load_workflow(workflow_path)
            elif workflow_type == "engine":
                engine = get_object_or_404(ScanEngine, id=workflow_id)
                workflow_path = engine.custom_secator_workflow_file.path
                workflow_config = workflow_manager.load_workflow(workflow_path)
            else:
                messages.error(request, "Invalid workflow type.")
                return redirect("secator_workflow_list")

            # Update task configuration
            tasks = workflow_config.get("tasks", {})
            if task_id not in tasks:
                messages.error(request, f"Task '{task_id}' not found in workflow.")
                return redirect("secator_workflow_detail", workflow_id=workflow_id, workflow_type=workflow_type)

            # Get updated task configuration from form
            tool = request.POST.get("tool", "").strip()
            args_text = request.POST.get("args", "").strip()
            description = request.POST.get("description", "").strip()

            if not tool:
                messages.error(request, "Tool name is required.")
                return redirect(
                    "secator_workflow_task_config",
                    workflow_id=workflow_id,
                    task_id=task_id,
                    workflow_type=workflow_type,
                )

            # Parse arguments
            args = []
            if args_text:
                args = [arg.strip() for arg in args_text.split() if arg.strip()]

            # Update task configuration
            tasks[task_id] = {"tool": tool, "args": args, "description": description}

            # Save workflow
            workflow_manager.save_workflow(workflow_config, workflow_path)

            messages.success(request, f"Task '{task_id}' configuration updated successfully.")
            return redirect("secator_workflow_detail", workflow_id=workflow_id, workflow_type=workflow_type)

        except Exception as e:
            logger.error(f"Error in SecatorWorkflowTaskConfigView POST: {e}")
            messages.error(request, f"Error saving task configuration: {str(e)}")
            return redirect("secator_workflow_list")


@method_decorator(csrf_exempt, name="dispatch")
class SecatorWorkflowAPIView(View):
    """API view for workflow operations."""

    def get(self, request):
        """Get workflow data as JSON."""
        try:
            action = request.GET.get("action")

            if action == "list":
                # Get parameters for filtering and pagination
                workflow_type = request.GET.get("type", "all")
                search_query = request.GET.get("search", "")
                page = int(request.GET.get("page", 1))
                per_page = int(request.GET.get("per_page", 12))

                # Get workflow managers
                workflow_manager = SecatorWorkflowManager()
                builtin_manager = SecatorBuiltinWorkflowManager()

                # Get custom workflows
                workflows_dir = os.path.join(settings.BASE_DIR, "config", "secator_workflows")
                custom_workflows = workflow_manager.list_workflows(workflows_dir)
                # Ensure custom workflows have workflow_id and workflow_type
                for workflow in custom_workflows:
                    workflow["workflow_id"] = workflow.get(
                        "name", os.path.splitext(workflow.get("filename", "unknown"))[0]
                    )
                    workflow["workflow_type"] = "custom"

                # Get built-in workflows
                builtin_workflows = builtin_manager.list_builtin_workflows()
                # Ensure built-in workflows have workflow_id and workflow_type
                for workflow in builtin_workflows:
                    workflow["workflow_id"] = workflow.get("id", "unknown")
                    workflow["workflow_type"] = "builtin"

                # Get scan engines using Secator workflows
                secator_engines = ScanEngine.objects.filter(workflow_mode="secator")

                # Filter workflows based on type
                if workflow_type == "custom":
                    workflows = custom_workflows
                elif workflow_type == "builtin":
                    workflows = builtin_workflows
                elif workflow_type == "engines":
                    workflows = []
                    for engine in secator_engines:
                        if engine.secator_builtin_workflow:
                            # Find corresponding builtin workflow
                            for builtin in builtin_workflows:
                                if builtin["id"] == engine.secator_builtin_workflow:
                                    workflows.append(
                                        {
                                            "name": engine.name,
                                            "description": engine.description,
                                            "type": "builtin_engine",
                                            "workflow_id": builtin["id"],
                                            "engine_id": engine.id,
                                            "input_type": builtin["input_type"],
                                            "use_cases": builtin["use_cases"],
                                            "tools": builtin["tools"],
                                        }
                                    )
                                    break
                        elif engine.custom_secator_workflow_file:
                            # Find corresponding custom workflow
                            for custom in custom_workflows:
                                if custom["filename"] == os.path.basename(engine.custom_secator_workflow_file.name):
                                    # Use filename without extension as workflow_id if name is empty
                                    workflow_id = custom.get("name") or os.path.splitext(custom["filename"])[0]
                                    workflows.append(
                                        {
                                            "name": engine.name,
                                            "description": engine.description,
                                            "type": "custom_engine",
                                            "workflow_id": workflow_id,
                                            "engine_id": engine.id,
                                            "input_type": custom.get("input_types", []),
                                            "tags": custom.get("tags", []),
                                        }
                                    )
                                    break
                else:  # all
                    workflows = custom_workflows + builtin_workflows

                # Apply search filter
                if search_query:
                    workflows = [
                        w
                        for w in workflows
                        if search_query.lower() in w.get("name", "").lower()
                        or search_query.lower() in w.get("description", "").lower()
                        or any(search_query.lower() in tag.lower() for tag in w.get("tags", []))
                    ]

                # Sort workflows
                workflows.sort(key=lambda x: x.get("name", "").lower())

                # Pagination
                paginator = Paginator(workflows, per_page)
                page_obj = paginator.get_page(page)

                # Prepare response data
                workflows_data = []
                for workflow in page_obj:
                    workflow_data = {
                        "name": workflow.get("name", ""),
                        "description": workflow.get("description", ""),
                        "workflow_type": workflow.get("workflow_type", ""),
                        "workflow_id": workflow.get("workflow_id", ""),
                        "input_type": workflow.get("input_type", ""),
                        "tags": workflow.get("tags", []),
                        "use_cases": workflow.get("use_cases", []),
                        "tools": workflow.get("tools", []),
                        "can_edit": workflow.get("workflow_type") in ["custom", "custom_engine"]
                        and request.user.has_perm("scanEngine.modify_scan_configurations"),
                    }
                    workflows_data.append(workflow_data)

                return JsonResponse(
                    {
                        "status": "success",
                        "workflows": workflows_data,
                        "pagination": {
                            "current_page": page_obj.number,
                            "total_pages": paginator.num_pages,
                            "total_count": paginator.count,
                            "has_previous": page_obj.has_previous(),
                            "has_next": page_obj.has_next(),
                            "previous_page": page_obj.previous_page_number() if page_obj.has_previous() else None,
                            "next_page": page_obj.next_page_number() if page_obj.has_next() else None,
                        },
                        "filters": {
                            "type": workflow_type,
                            "search": search_query,
                        },
                        "counts": {
                            "custom": len(custom_workflows),
                            "builtin": len(builtin_workflows),
                            "engines": secator_engines.count(),
                            "total": len(custom_workflows) + len(builtin_workflows) + secator_engines.count(),
                        },
                    }
                )

            else:
                # Original single workflow get functionality
                workflow_id = request.GET.get("workflow_id")
                workflow_type = request.GET.get("type", "custom")

                if not workflow_id:
                    return JsonResponse({"error": "workflow_id is required"}, status=400)

                workflow_manager = SecatorWorkflowManager()
                builtin_manager = SecatorBuiltinWorkflowManager()

                if workflow_type == "builtin":
                    workflow_data = builtin_manager.get_workflow_info(workflow_id)
                    if not workflow_data:
                        return JsonResponse({"error": "Built-in workflow not found"}, status=404)
                    return JsonResponse(workflow_data)

                elif workflow_type == "custom":
                    workflows_dir = os.path.join(settings.BASE_DIR, "config", "secator_workflows")
                    workflow_path = os.path.join(workflows_dir, f"{workflow_id}.yaml")

                    if not os.path.exists(workflow_path):
                        return JsonResponse({"error": "Custom workflow not found"}, status=404)

                    workflow_config = workflow_manager.load_workflow(workflow_path)
                    return JsonResponse(workflow_config)

                else:
                    return JsonResponse({"error": "Invalid workflow type"}, status=400)

        except Exception as e:
            logger.error(f"Error in SecatorWorkflowAPIView GET: {e}")
            return JsonResponse({"error": str(e)}, status=500)

    def post(self, request):
        """Execute workflow or perform other operations."""
        try:
            action = request.POST.get("action")

            if action == "execute":
                # This would trigger workflow execution
                # For now, just return success
                return JsonResponse({"status": "success", "message": "Workflow execution started"})

            elif action == "validate":
                # Validate workflow configuration
                workflow_yaml = request.POST.get("workflow_yaml", "")
                try:
                    workflow_config = yaml.safe_load(workflow_yaml)
                    if "name" not in workflow_config or "type" not in workflow_config:
                        return JsonResponse({"valid": False, "error": "Missing required fields"})
                    return JsonResponse({"valid": True})
                except yaml.YAMLError as e:
                    return JsonResponse({"valid": False, "error": str(e)})

            else:
                return JsonResponse({"error": "Invalid action"}, status=400)

        except Exception as e:
            logger.error(f"Error in SecatorWorkflowAPIView POST: {e}")
            return JsonResponse({"error": str(e)}, status=500)
