import hashlib
import os

from django.conf import settings
from django.core.management.base import BaseCommand
import yaml

from scanEngine.models import EngineType


class Command(BaseCommand):
    help = "Force update default scan engines from config/default_scan_engines/ folder"

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help="Force update all default engines (overwrites existing ones)",
        )
        parser.add_argument(
            "--check-modified",
            action="store_true",
            help="Check if engines have been modified and skip modified ones",
        )

    def is_engine_modified(self, engine, yaml_content):
        """Check if an engine has been modified by comparing YAML content"""
        if not engine.default_engine:
            return True  # Custom engines are considered modified

        # Calculate hash of current YAML content
        current_hash = hashlib.md5(engine.yaml_configuration.encode("utf-8")).hexdigest()
        new_hash = hashlib.md5(yaml_content.encode("utf-8")).hexdigest()

        return current_hash != new_hash

    def handle(self, *args, **options):
        """Update default engines from config files"""

        engines_dir = os.path.join(settings.BASE_DIR, "config", "default_scan_engines")

        if not os.path.exists(engines_dir):
            self.stdout.write(self.style.ERROR(f"Default engines directory not found: {engines_dir}"))
            return

        # Check if we should respect user modifications
        check_modified = options.get("check_modified", False)

        if not options["force"] and not check_modified:
            self.stdout.write(
                self.style.WARNING(
                    "This command will update/overwrite existing default engines.\n"
                    "Use --force to overwrite all engines or --check-modified to preserve user modifications."
                )
            )
            return

        updated_count = 0
        created_count = 0
        skipped_count = 0
        yaml_files = [f for f in os.listdir(engines_dir) if f.endswith(".yaml")]

        self.stdout.write("🔍 Updating default scan engines...")

        for yaml_file in yaml_files:
            engine_name = os.path.splitext(yaml_file)[0]
            file_path = os.path.join(engines_dir, yaml_file)

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    yaml_content = f.read()

                # Determine scan type from engine's YAML configuration
                scan_type = "bug_bounty"  # Default fallback
                try:
                    engine_config = yaml.safe_load(yaml_content)
                    if isinstance(engine_config, dict) and "scan_type" in engine_config:
                        scan_type = engine_config["scan_type"]
                except Exception as e:
                    self.stdout.write(self.style.WARNING(f"Could not parse scan_type from {engine_name}: {e}"))

                # Check if engine exists
                try:
                    existing_engine = EngineType.objects.get(engine_name=engine_name)

                    # Check if we should respect modifications
                    if check_modified and self.is_engine_modified(existing_engine, yaml_content):
                        skipped_count += 1
                        self.stdout.write(self.style.WARNING(f"⚠ Skipped {engine_name} (modified by user)"))
                    else:
                        # Update the engine
                        existing_engine.yaml_configuration = yaml_content
                        existing_engine.scan_type = scan_type
                        existing_engine.default_engine = True
                        existing_engine.save()
                        updated_count += 1
                        self.stdout.write(self.style.SUCCESS(f"↻ Updated engine: {engine_name}"))

                except EngineType.DoesNotExist:
                    # Create new engine
                    EngineType.objects.create(
                        engine_name=engine_name,
                        yaml_configuration=yaml_content,
                        default_engine=True,
                        scan_type=scan_type,
                    )
                    created_count += 1
                    self.stdout.write(self.style.SUCCESS(f"✓ Created engine: {engine_name}"))

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"✗ Failed to process {yaml_file}: {str(e)}"))

        self.stdout.write(
            self.style.SUCCESS(
                f"\n📊 Summary: {created_count} created, {updated_count} updated, {skipped_count} skipped (modified)"
            )
        )
