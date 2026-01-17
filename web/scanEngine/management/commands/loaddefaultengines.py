import hashlib
import os

from django.conf import settings
from django.core.management.base import BaseCommand
import yaml

from scanEngine.models import EngineType


class Command(BaseCommand):
    help = "Load default scan engines from config/default_scan_engines/ folder"

    def get_file_hash(self, file_path):
        """Calculate MD5 hash of a file"""
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception:
            return None

    def is_engine_modified(self, engine, yaml_content):
        """Check if an engine has been modified by comparing YAML content"""
        if not engine.default_engine:
            return True  # Custom engines are considered modified

        # Calculate hash of current YAML content
        current_hash = hashlib.md5(engine.yaml_configuration.encode("utf-8")).hexdigest()
        new_hash = hashlib.md5(yaml_content.encode("utf-8")).hexdigest()

        return current_hash != new_hash

    def handle(self, *args, **kwargs):
        """Load default engines, updating only unmodified ones"""

        # Load engines from config/default_scan_engines/
        engines_dir = os.path.join(settings.BASE_DIR, "config", "default_scan_engines")

        if not os.path.exists(engines_dir):
            self.stdout.write(self.style.ERROR(f"Default engines directory not found: {engines_dir}"))
            return

        loaded_count = 0
        updated_count = 0
        skipped_count = 0
        yaml_files = [f for f in os.listdir(engines_dir) if f.endswith(".yaml")]

        self.stdout.write("🔍 Checking default scan engines...")

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

                    # Check if engine has been modified
                    if self.is_engine_modified(existing_engine, yaml_content):
                        skipped_count += 1
                        self.stdout.write(self.style.WARNING(f"⚠ Skipped {engine_name} (modified by user)"))
                    else:
                        # Update unmodified engine
                        existing_engine.yaml_configuration = yaml_content
                        existing_engine.scan_type = scan_type
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
                    loaded_count += 1
                    self.stdout.write(self.style.SUCCESS(f"✓ Loaded engine: {engine_name}"))

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"✗ Failed to process {yaml_file}: {str(e)}"))

        self.stdout.write(
            self.style.SUCCESS(
                f"\n📊 Summary: {loaded_count} loaded, {updated_count} updated, {skipped_count} skipped (modified)"
            )
        )
