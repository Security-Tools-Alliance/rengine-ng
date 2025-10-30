"""
Django management command to load Secator workflows (built-in and custom).
"""

import os

from django.conf import settings
import yaml

from scanEngine.models import SecatorWorkflow

from .secator_loader_base import SecatorLoaderBase


class Command(SecatorLoaderBase):
    help = "Load Secator workflows (built-in and custom) into the database"

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help="Force reload even if workflows already exist",
        )
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
        force = options["force"]
        builtin_only = options["builtin_only"]
        custom_only = options["custom_only"]

        self.stdout.write("Loading Secator workflows...")

        if not custom_only:
            self.load_builtin_workflows(force)

        if not builtin_only:
            self.load_custom_workflows(force)

        self.stdout.write(self.style.SUCCESS("Workflow loading completed successfully!"))

    def get_secator_workflow_yaml(self, workflow_alias: str) -> str:
        """Get YAML configuration for a Secator workflow"""
        return self._get_secator_yaml_config(["w", workflow_alias, "--yaml"], workflow_alias)

    def load_builtin_workflows(self, force):
        """Load built-in Secator workflows"""
        self.stdout.write("Loading built-in Secator workflows...")

        created_count = 0
        failed_count = 0

        # Get workflow aliases from the model choices
        workflow_aliases = [choice[0] for choice in SecatorWorkflow.WORKFLOW_ALIAS_CHOICES]

        for alias in workflow_aliases:
            self.stdout.write(f"Loading workflow: {alias}")

            # Get YAML configuration from Secator
            yaml_config = self.get_secator_workflow_yaml(alias)

            if not yaml_config:
                self.stdout.write(self.style.WARNING(f"Failed to get YAML for workflow: {alias}"))
                failed_count += 1
                continue

            try:
                # Parse YAML to extract metadata
                workflow_data = yaml.safe_load(yaml_config)

                if not workflow_data:
                    self.stdout.write(self.style.WARNING(f"Empty YAML for workflow: {alias}"))
                    failed_count += 1
                    continue

                # Extract workflow information
                # Use the display name from WORKFLOW_ALIAS_CHOICES instead of the technical name
                display_name = dict(SecatorWorkflow.WORKFLOW_ALIAS_CHOICES).get(alias, alias.replace("_", " ").title())
                description = workflow_data.get("description", f"Built-in {display_name} workflow")

                # Determine scan type based on workflow content
                scan_type = self._determine_scan_type_from_yaml(workflow_data)

                # Create or update workflow
                workflow, created = SecatorWorkflow.objects.get_or_create(
                    alias=alias,
                    workflow_type="builtin",
                    defaults={
                        "name": display_name,
                        "description": description,
                        "yaml_configuration": yaml_config,
                        "scan_type": scan_type,
                        "is_active": True,
                    },
                )

                if created:
                    created_count += 1
                    self.stdout.write(f"Created built-in workflow: {display_name}")
                elif force:
                    # Update existing workflow
                    workflow.name = display_name
                    workflow.description = description
                    workflow.yaml_configuration = yaml_config
                    workflow.scan_type = scan_type
                    workflow.save(bypass_builtin_constraints=True)
                    self.stdout.write(f"Updated built-in workflow: {display_name}")
                else:
                    self.stdout.write(f"Built-in workflow already exists: {display_name} (skipped)")

            except yaml.YAMLError as e:
                self.stdout.write(self.style.ERROR(f"Invalid YAML for workflow {alias}: {e}"))
                failed_count += 1
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error processing workflow {alias}: {e}"))
                failed_count += 1

        self.stdout.write(f"Loaded {created_count} built-in workflows")
        if failed_count > 0:
            self.stdout.write(self.style.WARNING(f"Failed to load {failed_count} workflows"))

    def load_custom_workflows(self, force):
        """Load custom workflows from config/workflows/ directory"""
        self.stdout.write("Loading custom workflows...")

        workflows_dir = os.path.join(settings.BASE_DIR, "config", "workflows")

        if not os.path.exists(workflows_dir):
            self.stdout.write(self.style.WARNING(f"Workflows directory not found: {workflows_dir}"))
            return

        created_count = 0
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
                        "workflow_type": "custom",
                        "yaml_configuration": yaml.dump(workflow_data),
                        "scan_type": workflow_data.get("scan_type", "internet"),
                        "is_active": True,
                    },
                )

                if created:
                    created_count += 1
                    self.stdout.write(f"Created custom workflow: {workflow_name}")
                elif force:
                    workflow.description = workflow_data.get("description", "")
                    workflow.yaml_configuration = yaml.dump(workflow_data)
                    workflow.scan_type = workflow_data.get("scan_type", "internet")
                    workflow.save()
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

        self.stdout.write(f"Loaded {created_count} custom workflows")
