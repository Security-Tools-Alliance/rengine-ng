"""
Django management command to migrate existing EngineType configurations to SecatorScan.
This command preserves all existing EngineType data for backward compatibility.
"""

from django.core.management.base import BaseCommand
from django.db import transaction

from scanEngine.models import EngineType, SecatorScan, SecatorWorkflow


class Command(BaseCommand):
    help = "Migrate existing EngineType configurations to SecatorScan while preserving legacy data"

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be migrated without making changes",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]

        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN MODE - No changes will be made"))

        self.stdout.write("Starting migration of EngineType to SecatorScan...")

        # Mark all existing EngineType as legacy
        self.migrate_engine_types(dry_run)

        # Create default SecatorScan configurations
        self.create_default_secator_scans(dry_run)

        # Update existing ScanHistory to mark as legacy
        self.update_scan_history_legacy_flag(dry_run)

        self.stdout.write(self.style.SUCCESS("Migration completed successfully!"))

    def migrate_engine_types(self, dry_run):
        """Mark all existing EngineType as legacy"""
        self.stdout.write("Marking existing EngineType as legacy...")

        engine_types = EngineType.objects.all()
        count = engine_types.count()

        if count == 0:
            self.stdout.write("No EngineType found to migrate.")
            return

        if not dry_run:
            with transaction.atomic():
                engine_types.update(is_legacy=True)

        self.stdout.write(f"Marked {count} EngineType as legacy")

    def create_default_secator_scans(self, dry_run):
        """Create default SecatorScan configurations based on common scan types"""
        self.stdout.write("Creating default SecatorScan configurations...")

        default_scans = [
            {
                "name": "Internet Passive Recon",
                "description": "Passive reconnaissance for Internet targets",
                "scan_type": "internet",
                "execution_mode": "workflow",
                "scan_config_type": "builtin",
                "workflow_name": "Subdomain Recon",
            },
            {
                "name": "Internet Active Recon",
                "description": "Active reconnaissance with vulnerability scanning",
                "scan_type": "internet",
                "execution_mode": "workflow",
                "scan_config_type": "builtin",
                "workflow_name": "URL Vulnerability",
            },
            {
                "name": "Internal Network Scan",
                "description": "Internal network reconnaissance",
                "scan_type": "internal_network",
                "execution_mode": "workflow",
                "scan_config_type": "builtin",
                "workflow_name": "Host Recon",
            },
            {
                "name": "WordPress Security Scan",
                "description": "WordPress-specific vulnerability scanning",
                "scan_type": "internet",
                "execution_mode": "workflow",
                "scan_config_type": "builtin",
                "workflow_name": "WordPress",
            },
            {
                "name": "URL Discovery and Crawling",
                "description": "Discover and crawl URLs from targets",
                "scan_type": "internet",
                "execution_mode": "workflow",
                "scan_config_type": "builtin",
                "workflow_name": "URL Crawl",
            },
        ]

        created_count = 0
        for scan_config in default_scans:
            if not dry_run:
                # Create workflow first if it doesn't exist
                workflow, workflow_created = SecatorWorkflow.objects.get_or_create(
                    name=scan_config["workflow_name"],
                    defaults={
                        "description": f"Built-in {scan_config['workflow_name']} workflow",
                        "workflow_type": "builtin",
                        "yaml_configuration": self.get_builtin_workflow_yaml(scan_config["workflow_name"]),
                        "scan_type": scan_config["scan_type"],
                    },
                )

                # Create SecatorScan
                secator_scan, scan_created = SecatorScan.objects.get_or_create(
                    name=scan_config["name"],
                    defaults={
                        "description": scan_config["description"],
                        "scan_type": scan_config["scan_type"],
                        "workflow": workflow,
                        "execution_mode": scan_config["execution_mode"],
                        "scan_config_type": scan_config["scan_config_type"],
                        "is_default": True,
                    },
                )

                if scan_created:
                    created_count += 1
            else:
                # In dry run mode, check if the scan configuration would actually be created
                SecatorWorkflow.objects.filter(name=scan_config["workflow_name"]).exists()

                scan_exists = SecatorScan.objects.filter(name=scan_config["name"]).exists()

                # Only count as "would be created" if it doesn't already exist
                if not scan_exists:
                    created_count += 1

        self.stdout.write(f"Created {created_count} default SecatorScan configurations")

    def get_builtin_workflow_yaml(self, workflow_name):
        """Get YAML configuration for built-in Secator workflows"""
        builtin_workflows = {
            "Subdomain Recon": """
name: subdomain_recon
description: Subdomain discovery workflow
tasks:
  - subfinder
  - dnsx
""",
            "URL Vulnerability": """
name: url_vuln
description: URL vulnerability scanning workflow
tasks:
  - nuclei
  - dalfox
  - bbot
""",
            "Host Recon": """
name: host_recon
description: Host reconnaissance workflow
tasks:
  - naabu
  - nmap
""",
            "WordPress": """
name: wordpress
description: WordPress vulnerability scanning workflow
tasks:
  - wpscan
  - wpprobe
""",
            "URL Crawl": """
name: url_crawl
description: URL crawling workflow
tasks:
  - katana
  - gospider
  - httpx
""",
        }

        return builtin_workflows.get(workflow_name, "")

    def update_scan_history_legacy_flag(self, dry_run):
        """Update existing ScanHistory to mark as legacy"""
        self.stdout.write("Updating existing ScanHistory to mark as legacy...")

        from startScan.models import ScanHistory

        # All existing scans use EngineType, so they are legacy
        legacy_scans = ScanHistory.objects.filter(is_legacy_scan=False)
        count = legacy_scans.count()

        if count == 0:
            self.stdout.write("No ScanHistory found to update.")
            return

        if not dry_run:
            with transaction.atomic():
                legacy_scans.update(is_legacy_scan=True)

        self.stdout.write(f"Updated {count} ScanHistory records as legacy")
