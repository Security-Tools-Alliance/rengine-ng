"""
Django management command to load Secator scans into the database.
"""

import os

from django.conf import settings
from secator.loader import get_configs_by_type
import yaml

from scanEngine.models import SecatorScan

from .secator_loader_base import SecatorLoaderBase


class Command(SecatorLoaderBase):
    help = "Load Secator scans into the database"

    def add_arguments(self, parser):
        parser.add_argument(
            "--builtin-only",
            action="store_true",
            help="Load only built-in scans",
        )
        parser.add_argument(
            "--custom-only",
            action="store_true",
            help="Load only custom scans",
        )

    def handle(self, *args, **options):
        builtin_only = options["builtin_only"]
        custom_only = options["custom_only"]

        self.stdout.write("Loading Secator scans...")

        if not custom_only:
            self.load_builtin_scans()

        if not builtin_only:
            self.load_custom_scans()

        self.stdout.write(self.style.SUCCESS("Scan loading completed successfully!"))

    def load_builtin_scans(self):
        """Load built-in Secator scans"""
        self.stdout.write("Loading built-in Secator scans...")

        created_count = 0
        updated_count = 0
        failed_count = 0

        try:
            # Get scans directly from secator library
            scans = get_configs_by_type("scan")

            if not scans:
                self.stdout.write(self.style.WARNING("No scans found in secator"))
                return

            for scan_loader in scans:
                try:
                    # Extract scan information from TemplateLoader
                    scan_name = scan_loader.name
                    scan_description = getattr(scan_loader, "description", "") or ""
                    scan_path = getattr(scan_loader, "_path", None)

                    if not scan_path:
                        self.stdout.write(self.style.WARNING(f"Scan {scan_name} has no path, skipping"))
                        failed_count += 1
                        continue

                    # Read YAML configuration from file
                    try:
                        with open(scan_path, "r", encoding="utf-8") as f:
                            yaml_config = f.read()
                    except (OSError, IOError) as e:
                        # I/O-related issues (missing file, permission error, etc.) are expected
                        self.stdout.write(
                            self.style.ERROR(
                                f"Failed to read YAML file for scan {scan_name} at {scan_path}: {e}"
                            )
                        )
                        failed_count += 1
                        continue
                    except Exception as e:
                        self.stdout.write(self.style.ERROR(f"Failed to read YAML file for scan {scan_name}: {e}"))
                        failed_count += 1
                        continue

                    # Parse YAML to extract metadata
                    try:
                        scan_data = yaml.safe_load(yaml_config)
                    except yaml.YAMLError as e:
                        self.stdout.write(self.style.ERROR(f"Invalid YAML for scan {scan_name}: {e}"))
                        failed_count += 1
                        continue

                    if not scan_data:
                        self.stdout.write(self.style.WARNING(f"Empty YAML for scan: {scan_name}"))
                        failed_count += 1
                        continue

                    # Use description from YAML if available, otherwise use loader description
                    description = scan_data.get("description", scan_description) or f"Built-in {scan_name}"
                    # Get long_description from YAML or TemplateLoader
                    long_description = scan_data.get("long_description") or getattr(scan_loader, "long_description", None)

                    # Determine scan type based on scan content
                    scan_type = self._determine_scan_type_from_yaml(scan_data)

                    # Use scan_loader.name directly as name (unique identifier for Secator)
                    scan, created = SecatorScan.objects.get_or_create(
                        name=scan_name,
                        defaults={
                            "description": description,
                            "long_description": long_description,
                            "yaml_configuration": yaml_config,
                            "scan_type": scan_type,
                            "scan_config_type": "builtin",
                            "is_default": scan_name == "domain",  # Domain scan is default
                            "is_active": True,
                        },
                    )

                    if created:
                        # For built-in scans, use bypass_builtin_constraints to allow save
                        scan.save(bypass_builtin_constraints=True)
                        created_count += 1
                        self.stdout.write(f"Created built-in scan: {scan_name}")
                    else:
                        # Update existing scan using update() to bypass save() constraints
                        SecatorScan.objects.filter(pk=scan.pk).update(
                            description=description,
                            long_description=long_description,
                            yaml_configuration=yaml_config,
                            scan_type=scan_type,
                            is_default=scan_name == "domain",  # Domain scan is default
                        )
                        updated_count += 1
                        self.stdout.write(f"Updated built-in scan: {scan_name}")

                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(f"Error processing scan {getattr(scan_loader, 'name', 'unknown')}: {e}")
                    )
                    failed_count += 1

            self.stdout.write(f"Loaded {created_count} new built-in scans, updated {updated_count} existing scans")
            if failed_count > 0:
                self.stdout.write(self.style.WARNING(f"Failed to load {failed_count} scans"))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Failed to get scans from secator: {e}"))

    def load_custom_scans(self):
        """Load custom scans from config/scans/ directory"""
        self.stdout.write("Loading custom scans...")

        scans_dir = os.path.join(settings.BASE_DIR, "config", "scans")

        if not os.path.exists(scans_dir):
            self.stdout.write(self.style.WARNING(f"Scans directory not found: {scans_dir}"))
            return

        created_count = 0
        updated_count = 0
        for filename in sorted(os.listdir(scans_dir)):
            if not filename.endswith(".yaml") and not filename.endswith(".yml"):
                continue

            filepath = os.path.join(scans_dir, filename)

            try:
                with open(filepath, "r") as f:
                    scan_data = yaml.safe_load(f)

                if not scan_data or "name" not in scan_data:
                    self.stdout.write(self.style.WARNING(f"Invalid scan file: {filename}"))
                    continue

                scan_name = scan_data["name"]
                scan, created = SecatorScan.objects.get_or_create(
                    name=scan_name,
                    scan_config_type="custom",
                    defaults={
                        "description": scan_data.get("description", ""),
                        "long_description": scan_data.get("long_description", None),
                        "yaml_configuration": yaml.dump(scan_data),
                        "scan_type": scan_data.get("scan_type", "internet"),
                        "is_default": False,
                        "is_active": True,
                    },
                )

                if created:
                    # Custom scans don't need bypass_builtin_constraints
                    scan.save()
                    created_count += 1
                    self.stdout.write(f"Created custom scan: {scan_name}")
                else:
                    # Always update existing custom scans using update()
                    SecatorScan.objects.filter(pk=scan.pk).update(
                        description=scan_data.get("description", ""),
                        long_description=scan_data.get("long_description", None),
                        yaml_configuration=yaml.dump(scan_data),
                        scan_type=scan_data.get("scan_type", "internet"),
                    )
                    updated_count += 1
                    self.stdout.write(f"Updated custom scan: {scan_name}")

            except FileNotFoundError:
                self.stdout.write(self.style.ERROR(f"Scan file not found: {filename}"))
            except PermissionError:
                self.stdout.write(self.style.ERROR(f"Permission denied reading scan file: {filename}"))
            except yaml.YAMLError as e:
                self.stdout.write(self.style.ERROR(f"Invalid YAML syntax in scan file {filename}: {e}"))
            except UnicodeDecodeError as e:
                self.stdout.write(self.style.ERROR(f"Encoding error in scan file {filename}: {e}"))
            except KeyError as e:
                self.stdout.write(self.style.ERROR(f"Missing required field in scan file {filename}: {e}"))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Unexpected error loading scan {filename}: {e}"))

        self.stdout.write(f"Loaded {created_count} new custom scans, updated {updated_count} existing custom scans")
