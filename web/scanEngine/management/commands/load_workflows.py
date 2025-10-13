"""
Django management command to load Secator workflows (built-in and custom).
"""

import os
import yaml
from django.core.management.base import BaseCommand
from django.conf import settings
from scanEngine.models import SecatorWorkflow, SecatorTask, SecatorScan


class Command(BaseCommand):
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
        
        self.create_default_scan_configs(force)

        self.stdout.write(
            self.style.SUCCESS("Workflow loading completed successfully!")
        )

    def load_builtin_workflows(self, force):
        """Load built-in Secator workflows"""
        self.stdout.write("Loading built-in Secator workflows...")
        
        builtin_workflows = [
            {
                "name": "cidr_recon",
                "description": "Local network reconnaissance",
                "scan_type": "internal",
                "yaml_config": """
name: cidr_recon
description: Local network reconnaissance
tasks:
  - naabu
  - nmap
  - nuclei
""",
            },
            {
                "name": "code_scan",
                "description": "Code vulnerability scanning",
                "scan_type": "internet",
                "yaml_config": """
name: code_scan
description: Code vulnerability scanning
tasks:
  - gitleaks
  - nuclei
""",
            },
            {
                "name": "host_recon",
                "description": "Host reconnaissance",
                "scan_type": "internal",
                "yaml_config": """
name: host_recon
description: Host reconnaissance
tasks:
  - naabu
  - nmap
  - nuclei
""",
            },
            {
                "name": "subdomain_recon",
                "description": "Subdomain discovery",
                "scan_type": "internet",
                "yaml_config": """
name: subdomain_recon
description: Subdomain discovery
tasks:
  - subfinder
  - dnsx
""",
            },
            {
                "name": "url_bypass",
                "description": "Try bypass techniques for 4xx URLs",
                "scan_type": "internet",
                "yaml_config": """
name: url_bypass
description: Try bypass techniques for 4xx URLs
tasks:
  - bup
""",
            },
            {
                "name": "url_crawl",
                "description": "URL crawl (fast)",
                "scan_type": "internet",
                "yaml_config": """
name: url_crawl
description: URL crawl (fast)
tasks:
  - katana
  - gospider
  - httpx
""",
            },
            {
                "name": "url_dirsearch",
                "description": "URL directory search",
                "scan_type": "internet",
                "yaml_config": """
name: url_dirsearch
description: URL directory search
tasks:
  - dirsearch
  - ffuf
""",
            },
            {
                "name": "url_fuzz",
                "description": "URL fuzz (slow)",
                "scan_type": "internet",
                "yaml_config": """
name: url_fuzz
description: URL fuzz (slow)
tasks:
  - ffuf
  - arjun
""",
            },
            {
                "name": "url_params_fuzz",
                "description": "Extract parameters from an URL and fuzz them",
                "scan_type": "internet",
                "yaml_config": """
name: url_params_fuzz
description: Extract parameters from an URL and fuzz them
tasks:
  - arjun
  - ffuf
""",
            },
            {
                "name": "url_vuln",
                "description": "URL vulnerability scan (gf, dalfox)",
                "scan_type": "internet",
                "yaml_config": """
name: url_vuln
description: URL vulnerability scan
tasks:
  - nuclei
  - dalfox
  - bbot
""",
            },
            {
                "name": "user_hunt",
                "description": "User account search",
                "scan_type": "internet",
                "yaml_config": """
name: user_hunt
description: User account search
tasks:
  - h8mail
  - maigret
""",
            },
            {
                "name": "wordpress",
                "description": "WordPress vulnerability scan",
                "scan_type": "internet",
                "yaml_config": """
name: wordpress
description: WordPress vulnerability scan
tasks:
  - wpscan
  - wpprobe
""",
            },
        ]

        created_count = 0
        for workflow_data in builtin_workflows:
            workflow, created = SecatorWorkflow.objects.get_or_create(
                name=workflow_data["name"],
                defaults={
                    "description": workflow_data["description"],
                    "workflow_type": "builtin",
                    "yaml_configuration": workflow_data["yaml_config"],
                    "scan_type": workflow_data["scan_type"],
                    "is_active": True,
                }
            )
            
            if created:
                created_count += 1
                self.stdout.write(f"Created built-in workflow: {workflow_data['name']}")
            elif force:
                workflow.description = workflow_data["description"]
                workflow.yaml_configuration = workflow_data["yaml_config"]
                workflow.scan_type = workflow_data["scan_type"]
                workflow.save()
                self.stdout.write(f"Updated built-in workflow: {workflow_data['name']}")

        self.stdout.write(f"Loaded {created_count} built-in workflows")

    def load_custom_workflows(self, force):
        """Load custom workflows from config/workflows/ directory"""
        self.stdout.write("Loading custom workflows...")
        
        workflows_dir = os.path.join(settings.BASE_DIR, "config", "workflows")
        
        if not os.path.exists(workflows_dir):
            self.stdout.write(
                self.style.WARNING(f"Workflows directory not found: {workflows_dir}")
            )
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
                    self.stdout.write(
                        self.style.WARNING(f"Invalid workflow file: {filename}")
                    )
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
                    }
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
                self.stdout.write(
                    self.style.ERROR(f"Workflow file not found: {filename}")
                )
            except PermissionError:
                self.stdout.write(
                    self.style.ERROR(f"Permission denied reading workflow file: {filename}")
                )
            except yaml.YAMLError as e:
                self.stdout.write(
                    self.style.ERROR(f"Invalid YAML syntax in workflow file {filename}: {e}")
                )
            except UnicodeDecodeError as e:
                self.stdout.write(
                    self.style.ERROR(f"Encoding error in workflow file {filename}: {e}")
                )
            except KeyError as e:
                self.stdout.write(
                    self.style.ERROR(f"Missing required field in workflow file {filename}: {e}")
                )
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"Unexpected error loading workflow {filename}: {e}")
                )

        self.stdout.write(f"Loaded {created_count} custom workflows")

    def create_default_scan_configs(self, force):
        """Create default SecatorScan configurations"""
        self.stdout.write("Creating default SecatorScan configurations...")
        
        default_configs = [
            {
                "name": "Internet Passive",
                "description": "Passive reconnaissance for Internet targets",
                "scan_type": "internet",
                "workflow_name": "subdomain_recon",
                "execution_mode": "workflow",
                "scan_config_type": "builtin",
            },
            {
                "name": "Internet Active",
                "description": "Active reconnaissance with vulnerability scanning",
                "scan_type": "internet",
                "workflow_name": "url_vuln",
                "execution_mode": "workflow",
                "scan_config_type": "builtin",
            },
            {
                "name": "Internal Network",
                "description": "Internal network reconnaissance",
                "scan_type": "internal",
                "workflow_name": "host_recon",
                "execution_mode": "workflow",
                "scan_config_type": "builtin",
            },
            {
                "name": "WordPress Security",
                "description": "WordPress-specific vulnerability scanning",
                "scan_type": "internet",
                "workflow_name": "wordpress",
                "execution_mode": "workflow",
                "scan_config_type": "builtin",
            },
            {
                "name": "Full Reconnaissance",
                "description": "Complete reconnaissance workflow",
                "scan_type": "internet",
                "workflow_name": "full_recon",
                "execution_mode": "workflow",
                "scan_config_type": "custom",
            },
        ]

        created_count = 0
        missing_workflows = []
        
        for config_data in default_configs:
            try:
                workflow = SecatorWorkflow.objects.get(name=config_data["workflow_name"])
                
                scan_config, created = SecatorScan.objects.get_or_create(
                    name=config_data["name"],
                    defaults={
                        "description": config_data["description"],
                        "scan_type": config_data["scan_type"],
                        "workflow": workflow,
                        "execution_mode": config_data["execution_mode"],
                        "scan_config_type": config_data["scan_config_type"],
                        "is_default": True,
                    }
                )
                
                if created:
                    created_count += 1
                    self.stdout.write(f"Created scan config: {config_data['name']}")
                elif force:
                    scan_config.description = config_data["description"]
                    scan_config.scan_type = config_data["scan_type"]
                    scan_config.workflow = workflow
                    scan_config.execution_mode = config_data["execution_mode"]
                    scan_config.scan_config_type = config_data["scan_config_type"]
                    scan_config.save()
                    self.stdout.write(f"Updated scan config: {config_data['name']}")

            except SecatorWorkflow.DoesNotExist:
                missing_workflows.append({
                    "workflow_name": config_data["workflow_name"],
                    "scan_config_name": config_data["name"]
                })
                self.stdout.write(
                    self.style.ERROR(
                        f"ERROR: Workflow '{config_data['workflow_name']}' not found for scan config '{config_data['name']}'"
                    )
                )

        # Summary of missing workflows
        if missing_workflows:
            self.stdout.write(
                self.style.WARNING(
                    f"\nSummary: {len(missing_workflows)} scan configuration(s) could not be created due to missing workflows:"
                )
            )
            unique_missing_workflows = set(item["workflow_name"] for item in missing_workflows)
            for workflow_name in sorted(unique_missing_workflows):
                affected_configs = [item["scan_config_name"] for item in missing_workflows if item["workflow_name"] == workflow_name]
                self.stdout.write(
                    self.style.WARNING(
                        f"  - Missing workflow '{workflow_name}' affects: {', '.join(affected_configs)}"
                    )
                )
            self.stdout.write(
                self.style.WARNING(
                    "\nThese missing workflows may indicate:\n"
                    "  - Failed workflow loading (check workflow files)\n"
                    "  - Misconfiguration in scan config definitions\n"
                    "  - Workflow dependencies not properly loaded\n"
                    "  - Database synchronization issues"
                )
            )

        self.stdout.write(f"Created {created_count} default scan configurations")
