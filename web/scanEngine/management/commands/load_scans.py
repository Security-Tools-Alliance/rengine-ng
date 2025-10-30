"""
Django management command to load Secator scans into the database.
"""

import os

from django.conf import settings
import yaml

from scanEngine.models import SecatorScan

from .secator_loader_base import SecatorLoaderBase


class Command(SecatorLoaderBase):
    help = "Load Secator scans into the database"

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help="Force reload even if scans already exist",
        )
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
        force = options["force"]
        builtin_only = options["builtin_only"]
        custom_only = options["custom_only"]

        self.stdout.write("Loading Secator scans...")

        if not custom_only:
            self.load_builtin_scans(force)

        if not builtin_only:
            self.load_custom_scans(force)

        self.stdout.write(self.style.SUCCESS("Scan loading completed successfully!"))

    def load_builtin_scans(self, force):
        """Load built-in Secator scans"""
        self.stdout.write("Loading built-in Secator scans...")

        created_count = 0
        failed_count = 0

        # Get scan aliases from the model choices
        scan_aliases = [choice[0] for choice in SecatorScan.SCAN_ALIAS_CHOICES]

        for alias in scan_aliases:
            self.stdout.write(f"Loading scan: {alias}")

            # Get YAML configuration from Secator
            yaml_config = self._get_secator_yaml_config(["s", alias, "--yaml"], alias)

            if not yaml_config:
                self.stdout.write(self.style.WARNING(f"Failed to get YAML for scan: {alias}"))
                failed_count += 1
                continue

            try:
                # Parse YAML to extract metadata
                scan_data = yaml.safe_load(yaml_config)

                if not scan_data:
                    self.stdout.write(self.style.WARNING(f"Empty YAML for scan: {alias}"))
                    failed_count += 1
                    continue

                # Extract scan information
                # Use the display name from SCAN_ALIAS_CHOICES
                display_name = dict(SecatorScan.SCAN_ALIAS_CHOICES).get(alias, alias.replace("_", " ").title())
                description = scan_data.get("description", f"Built-in {display_name}")

                # Determine scan type based on scan content
                scan_type = self._determine_scan_type_from_yaml(scan_data)

                # Create or update scan
                scan, created = SecatorScan.objects.get_or_create(
                    alias=alias,
                    scan_config_type="builtin",
                    defaults={
                        "name": display_name,
                        "description": description,
                        "yaml_configuration": yaml_config,
                        "scan_type": scan_type,
                        "is_default": alias == "domain",  # Domain scan is default
                        "is_active": True,
                    },
                )

                if created:
                    created_count += 1
                    self.stdout.write(f"Created built-in scan: {display_name}")
                elif force:
                    # Update existing scan
                    scan.name = display_name
                    scan.description = description
                    scan.yaml_configuration = yaml_config
                    scan.scan_type = scan_type
                    scan.save(bypass_builtin_constraints=True)
                    self.stdout.write(f"Updated built-in scan: {display_name}")
                else:
                    self.stdout.write(f"Built-in scan already exists: {display_name} (skipped)")

            except yaml.YAMLError as e:
                self.stdout.write(self.style.ERROR(f"Invalid YAML for scan {alias}: {e}"))
                failed_count += 1
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error processing scan {alias}: {e}"))
                failed_count += 1

        self.stdout.write(f"Loaded {created_count} built-in scans")
        if failed_count > 0:
            self.stdout.write(self.style.WARNING(f"Failed to load {failed_count} scans"))

    def load_custom_scans(self, force):
        """Load custom scans from config/scans/ directory"""
        self.stdout.write("Loading custom scans...")

        scans_dir = os.path.join(settings.BASE_DIR, "config", "scans")

        if not os.path.exists(scans_dir):
            self.stdout.write(self.style.WARNING(f"Scans directory not found: {scans_dir}"))
            return

        created_count = 0
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
                        "yaml_configuration": yaml.dump(scan_data),
                        "scan_type": scan_data.get("scan_type", "internet"),
                        "is_default": False,
                        "is_active": True,
                    },
                )

                if created:
                    created_count += 1
                    self.stdout.write(f"Created custom scan: {scan_name}")
                elif force:
                    scan.description = scan_data.get("description", "")
                    scan.yaml_configuration = yaml.dump(scan_data)
                    scan.scan_type = scan_data.get("scan_type", "internet")
                    scan.save()
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

        self.stdout.write(f"Loaded {created_count} custom scans")
