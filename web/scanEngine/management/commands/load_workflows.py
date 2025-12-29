"""
Django management command to load Secator workflows (built-in and custom).
"""

import os

from django.conf import settings
from secator.loader import get_configs_by_type
import yaml

from scanEngine.models import SecatorWorkflow

from .secator_loader_base import SecatorLoaderBase


class Command(SecatorLoaderBase):
    help = "Load Secator workflows (built-in and custom) into the database"

    def add_arguments(self, parser):
        parser.add_argument(
            "--builtin-only",
            action="store_true",
            help="Load only built-in workflows",
        )
        parser.add_argument(
            "--custom-only",
            action="store_true",
            help="Load only custom workflows",
        )

    def handle(self, *args, **options):
        builtin_only = options["builtin_only"]
        custom_only = options["custom_only"]

        self.stdout.write("Loading Secator workflows...")

        if not custom_only:
            self.load_builtin_workflows()

        if not builtin_only:
            self.load_custom_workflows()

        self.stdout.write(self.style.SUCCESS("Workflow loading completed successfully!"))

    def load_builtin_workflows(self):
        """Load built-in Secator workflows"""
        self.stdout.write("Loading built-in Secator workflows...")

        created_count = 0
        updated_count = 0
        failed_count = 0

        try:
            # Get workflows directly from secator library
            workflows = get_configs_by_type("workflow")

            if not workflows:
                self.stdout.write(self.style.WARNING("No workflows found in secator"))
                return

            for workflow_loader in workflows:
                try:
                    # Extract workflow information from TemplateLoader
                    workflow_alias = getattr(workflow_loader, "alias", None)
                    workflow_name = workflow_loader.name
                    workflow_description = getattr(workflow_loader, "description", "") or ""
                    workflow_path = getattr(workflow_loader, "_path", None)

                    if not workflow_path:
                        self.stdout.write(self.style.WARNING(f"Workflow {workflow_name} has no path, skipping"))
                        failed_count += 1
                        continue

                    # Read YAML configuration from file
                    try:
                        with open(workflow_path, "r", encoding="utf-8") as f:
                            yaml_config = f.read()
                    except Exception as e:
                        self.stdout.write(
                            self.style.ERROR(f"Failed to read YAML file for workflow {workflow_name}: {e}")
                        )
                        failed_count += 1
                        continue

                    # Parse YAML to extract metadata
                    try:
                        workflow_data = yaml.safe_load(yaml_config)
                    except yaml.YAMLError as e:
                        self.stdout.write(self.style.ERROR(f"Invalid YAML for workflow {workflow_name}: {e}"))
                        failed_count += 1
                        continue

                    if not workflow_data:
                        self.stdout.write(self.style.WARNING(f"Empty YAML for workflow: {workflow_name}"))
                        failed_count += 1
                        continue

                    # Use description from YAML if available, otherwise use loader description
                    description = (
                        workflow_data.get("description", workflow_description) or f"Built-in {workflow_name} workflow"
                    )
                    # Get long_description from YAML or TemplateLoader
                    long_description = workflow_data.get("long_description") or getattr(workflow_loader, "long_description", None)

                    # Determine scan type based on workflow content
                    scan_type = self._determine_scan_type_from_yaml(workflow_data)

                    # Get display name from WORKFLOW_NAME_CHOICES using workflow_name (TemplateLoader name)
                    # (will be formatted automatically via get_display_name() if empty)
                    display_name = dict(SecatorWorkflow.WORKFLOW_NAME_CHOICES).get(workflow_name)

                    # Use name (TemplateLoader name) as unique key - this is the only identifier for Secator
                    workflow, created = SecatorWorkflow.objects.get_or_create(
                        name=workflow_name,
                        defaults={
                            "alias": workflow_alias,
                            "display_name": display_name,
                            "long_description": long_description,
                            "description": description,
                            "yaml_configuration": yaml_config,
                            "scan_type": scan_type,
                            "workflow_type": "builtin",
                            "is_active": True,
                        },
                    )

                    if created:
                        # For built-in workflows, use bypass_builtin_constraints to allow save
                        workflow.save(bypass_builtin_constraints=True)
                        created_count += 1
                        self.stdout.write(f"Created built-in workflow: {workflow.get_display_name()}")
                    else:
                        # Update existing workflow using update() to bypass save() constraints
                        SecatorWorkflow.objects.filter(pk=workflow.pk).update(
                            alias=workflow_alias,
                            display_name=display_name,
                            description=description,
                            long_description=long_description,
                            yaml_configuration=yaml_config,
                            scan_type=scan_type,
                        )
                        updated_count += 1
                        self.stdout.write(f"Updated built-in workflow: {display_name}")

                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(
                            f"Error processing workflow {getattr(workflow_loader, 'name', 'unknown')}: {e}"
                        )
                    )
                    failed_count += 1

            self.stdout.write(
                f"Loaded {created_count} new built-in workflows, updated {updated_count} existing workflows"
            )
            if failed_count > 0:
                self.stdout.write(self.style.WARNING(f"Failed to load {failed_count} workflows"))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Failed to get workflows from secator: {e}"))

    def load_custom_workflows(self):
        """Load custom workflows from config/workflows/ directory"""
        self.stdout.write("Loading custom workflows...")

        workflows_dir = os.path.join(settings.BASE_DIR, "config", "workflows")

        if not os.path.exists(workflows_dir):
            self.stdout.write(self.style.WARNING(f"Workflows directory not found: {workflows_dir}"))
            return

        created_count = 0
        updated_count = 0
        for filename in sorted(os.listdir(workflows_dir)):
            if not filename.endswith(".yaml") and not filename.endswith(".yml"):
                continue

            filepath = os.path.join(workflows_dir, filename)

            try:
                with open(filepath, "r") as f:
                    workflow_data = yaml.safe_load(f)

                if not workflow_data or "name" not in workflow_data:
                    self.stdout.write(self.style.WARNING(f"Invalid workflow file: {filename}"))
                    continue

                workflow_name = workflow_data["name"]
                workflow, created = SecatorWorkflow.objects.get_or_create(
                    name=workflow_name,
                    defaults={
                        "description": workflow_data.get("description", ""),
                        "long_description": workflow_data.get("long_description", None),
                        "workflow_type": "custom",
                        "yaml_configuration": yaml.dump(workflow_data),
                        "scan_type": workflow_data.get("scan_type", "internet"),
                        "is_active": True,
                    },
                )

                if created:
                    # Custom workflows don't need bypass_builtin_constraints
                    workflow.save()
                    created_count += 1
                    self.stdout.write(f"Created custom workflow: {workflow_name}")
                else:
                    # Always update existing custom workflows using update()
                    SecatorWorkflow.objects.filter(pk=workflow.pk).update(
                        description=workflow_data.get("description", ""),
                        long_description=workflow_data.get("long_description", None),
                        yaml_configuration=yaml.dump(workflow_data),
                        scan_type=workflow_data.get("scan_type", "internet"),
                    )
                    updated_count += 1
                    self.stdout.write(f"Updated custom workflow: {workflow_name}")

            except FileNotFoundError:
                self.stdout.write(self.style.ERROR(f"Workflow file not found: {filename}"))
            except PermissionError:
                self.stdout.write(self.style.ERROR(f"Permission denied reading workflow file: {filename}"))
            except yaml.YAMLError as e:
                self.stdout.write(self.style.ERROR(f"Invalid YAML syntax in workflow file {filename}: {e}"))
            except UnicodeDecodeError as e:
                self.stdout.write(self.style.ERROR(f"Encoding error in workflow file {filename}: {e}"))
            except KeyError as e:
                self.stdout.write(self.style.ERROR(f"Missing required field in workflow file {filename}: {e}"))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Unexpected error loading workflow {filename}: {e}"))

        self.stdout.write(
            f"Loaded {created_count} new custom workflows, updated {updated_count} existing custom workflows"
        )
