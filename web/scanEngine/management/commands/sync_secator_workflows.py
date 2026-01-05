"""
Django management command to sync Secator workflows from database to filesystem.
This ensures that Secator can find and load the workflow templates.
"""

from pathlib import Path

from django.core.management.base import BaseCommand
import yaml

from scanEngine.models import SecatorWorkflow


class Command(BaseCommand):
    help = "Sync Secator workflows from database to filesystem for Secator to load"

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help="Force sync even if files already exist",
        )

    def handle(self, *args, **options):
        force = options["force"]

        self.stdout.write("Syncing Secator workflows to filesystem...")

        # Create necessary directories
        secator_configs_dir = Path("/home/rengine/.secator/workflows")
        secator_templates_dir = Path("/home/rengine/.secator/templates")

        secator_configs_dir.mkdir(parents=True, exist_ok=True)
        secator_templates_dir.mkdir(parents=True, exist_ok=True)

        # Get all workflows from database
        workflows = SecatorWorkflow.objects.filter(is_active=True)
        synced_count = 0

        for workflow in workflows:
            try:
                # Parse YAML configuration
                config = yaml.safe_load(workflow.yaml_configuration)
                if not config:
                    self.stdout.write(
                        self.style.WARNING(f"Skipping workflow '{workflow.name}' - invalid YAML configuration")
                    )
                    continue

                # Create filename
                filename = f"{workflow.name}.yaml"

                # Write to Secator configs directory
                configs_file = secator_configs_dir / filename
                if not configs_file.exists() or force:
                    with open(configs_file, "w") as f:
                        yaml.dump(config, f, default_flow_style=False)
                    synced_count += 1
                    self.stdout.write(f"Synced workflow: {workflow.name} -> {configs_file}")

                # Write to Secator templates directory (backup location)
                templates_file = secator_templates_dir / filename
                if not templates_file.exists() or force:
                    with open(templates_file, "w") as f:
                        yaml.dump(config, f, default_flow_style=False)

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error syncing workflow '{workflow.name}': {e}"))

        self.stdout.write(self.style.SUCCESS(f"Successfully synced {synced_count} workflows to filesystem"))
