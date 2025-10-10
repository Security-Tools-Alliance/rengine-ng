import os

from django.db import models
import yaml


class HybridProperty:
    def __init__(self, func):
        self.func = func
        self.name = func.__name__
        self.exp = None

    def __get__(self, instance, owner):
        return self if instance is None else self.func(instance)

    def __set__(self, instance, value):
        pass

    def expression(self, exp):
        self.exp = exp
        return self


class EngineType(models.Model):
    SCAN_TYPE_CHOICES = [
        ("bug_bounty", "Bug Bounty"),
        ("internal_network", "Internal Network"),
    ]

    id = models.AutoField(primary_key=True)
    engine_name = models.CharField(max_length=200)
    yaml_configuration = models.TextField()
    default_engine = models.BooleanField(null=True, default=False)
    scan_type = models.CharField(
        max_length=20,
        choices=SCAN_TYPE_CHOICES,
        default="bug_bounty",
        help_text="Type of scan this engine is designed for",
    )

    def __str__(self):
        return self.engine_name

    def get_number_of_steps(self):
        return len(self.tasks) if self.tasks else 0

    def get_scan_type_from_yaml(self):
        """Extract scan_type from YAML configuration"""
        try:
            if not self.yaml_configuration:
                return "bug_bounty"

            config = yaml.safe_load(self.yaml_configuration)
            if isinstance(config, dict) and "scan_type" in config:
                return config["scan_type"]

            return "bug_bounty"  # Default fallback
        except Exception:
            return "bug_bounty"  # Safe fallback

    def save(self, *args, **kwargs):
        """Override save to automatically update scan_type from YAML if not explicitly set"""
        # Only update scan_type from YAML if it's not explicitly set in the form
        # This allows form submissions to override YAML scan_type
        if not hasattr(self, "_scan_type_explicitly_set") or not self._scan_type_explicitly_set:
            # Extract scan_type from YAML configuration
            self.scan_type = self.get_scan_type_from_yaml()
        super().save(*args, **kwargs)

    @classmethod
    def _get_config_parameter_names(cls):
        """Get the set of configuration parameter names"""
        return {
            "scan_type",
            "custom_header",
            "user_agent",
            "timeout",
            "threads",
            "rate_limit",
            "intensity",
            "retries",
            "proxy",
            "proxy_auth",
            "dns_servers",
            "wordlist",
            "exclude_ports",
            "include_ports",
        }

    def _parse_yaml_config(self):
        """Parse YAML configuration safely"""
        if not self.yaml_configuration:
            return {}

        try:
            config = yaml.safe_load(self.yaml_configuration)
            return config if isinstance(config, dict) else {}
        except Exception:
            return {}

    @HybridProperty
    def tasks(self):
        """Return only actual scan tasks, excluding configuration parameters"""
        config = self._parse_yaml_config()
        config_params = self._get_config_parameter_names()
        return [key for key in config.keys() if key not in config_params]

    def get_tasks_count(self):
        """Get the count of actual scan tasks (excluding configuration parameters)"""
        return len(self.tasks)

    def get_config_parameters(self):
        """Extract configuration parameters from YAML"""
        config = self._parse_yaml_config()
        config_params = self._get_config_parameter_names()
        return {key: value for key, value in config.items() if key in config_params}

    def get_config_parameters_json(self):
        """Get configuration parameters as JSON string for frontend"""
        import json

        return json.dumps(self.get_config_parameters())

    def get_config_parameters_display(self):
        """Get configuration parameters formatted for display in tooltip"""
        config_params = self.get_config_parameters()
        if not config_params:
            return ""

        display_items = []
        for key, value in config_params.items():
            formatted_key = key.replace("_", " ").title()
            formatted_value = self._format_config_value(value)
            display_items.append(f"<strong>{formatted_key}:</strong> {formatted_value}")

        return "<br/>".join(display_items)

    def _format_config_value(self, value):
        """Format a configuration value for display"""
        if isinstance(value, dict):
            # Format dictionary values nicely
            dict_items = []
            dict_items.extend(f"{k}: {v}" for k, v in value.items())
            return "{" + ", ".join(dict_items) + "}"
        elif isinstance(value, list):
            # Format array values nicely
            if len(value) == 0:
                return "[]"
            elif len(value) <= 3:
                return "[" + ", ".join(str(item) for item in value) + "]"
            else:
                return "[" + ", ".join(str(item) for item in value[:3]) + f", ... ({len(value)} items)]"
        elif isinstance(value, str) and len(value) > 50:
            return f"{value[:50]}..."
        elif isinstance(value, bool):
            return "Yes" if value else "No"
        else:
            return str(value)


class Wordlist(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=200)
    short_name = models.CharField(max_length=50, unique=True)
    count = models.IntegerField(default=0)

    def __str__(self):
        return self.name


class Configuration(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=200)
    short_name = models.CharField(max_length=50, unique=True)
    content = models.TextField()

    def __str__(self):
        return self.name


class InterestingLookupModel(models.Model):
    id = models.AutoField(primary_key=True)
    keywords = models.TextField(null=True, blank=True)
    custom_type = models.BooleanField(default=False)
    title_lookup = models.BooleanField(default=True)
    url_lookup = models.BooleanField(default=True)
    condition_200_http_lookup = models.BooleanField(default=False)


class Notification(models.Model):
    id = models.AutoField(primary_key=True)
    send_to_slack = models.BooleanField(default=False)
    send_to_lark = models.BooleanField(default=False)
    send_to_discord = models.BooleanField(default=False)
    send_to_telegram = models.BooleanField(default=False)

    slack_hook_url = models.CharField(max_length=200, null=True, blank=True)
    lark_hook_url = models.CharField(max_length=200, null=True, blank=True)
    discord_hook_url = models.CharField(max_length=200, null=True, blank=True)
    telegram_bot_token = models.CharField(max_length=100, null=True, blank=True)
    telegram_bot_chat_id = models.CharField(max_length=100, null=True, blank=True)

    send_scan_status_notif = models.BooleanField(default=True)
    send_interesting_notif = models.BooleanField(default=True)
    send_vuln_notif = models.BooleanField(default=True)
    send_subdomain_changes_notif = models.BooleanField(default=True)

    send_scan_output_file = models.BooleanField(default=True)
    send_scan_tracebacks = models.BooleanField(default=True)


class Proxy(models.Model):
    id = models.AutoField(primary_key=True)
    use_proxy = models.BooleanField(default=False)
    proxies = models.TextField(blank=True, null=True)


class Hackerone(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=100, null=True, blank=True)
    api_key = models.CharField(max_length=200, null=True, blank=True)
    send_critical = models.BooleanField(default=True)
    send_high = models.BooleanField(default=True)
    send_medium = models.BooleanField(default=False)
    report_template = models.TextField(blank=True, null=True)


class VulnerabilityReportSetting(models.Model):
    id = models.AutoField(primary_key=True)
    primary_color = models.CharField(max_length=10, null=True, blank=True, default="#FFB74D")
    secondary_color = models.CharField(max_length=10, null=True, blank=True, default="#212121")
    company_name = models.CharField(max_length=100, null=True, blank=True)
    company_address = models.CharField(max_length=255, null=True, blank=True)
    company_email = models.CharField(max_length=100, null=True, blank=True)
    company_website = models.CharField(max_length=255, null=True, blank=True)
    show_rengine_banner = models.BooleanField(default=True)
    show_executive_summary = models.BooleanField(default=True)
    executive_summary_description = models.TextField(blank=True, null=True)
    show_footer = models.BooleanField(default=False)
    footer_text = models.CharField(max_length=200, null=True, blank=True)


class InstalledExternalTool(models.Model):
    id = models.AutoField(primary_key=True)
    logo_url = models.CharField(max_length=200, null=True, blank=True)
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=2000)
    github_url = models.CharField(max_length=500)
    license_url = models.CharField(max_length=500, null=True, blank=True)
    version_lookup_command = models.CharField(max_length=200, null=True, blank=True)
    update_command = models.CharField(max_length=200, null=True, blank=True)
    install_command = models.CharField(max_length=200)
    version_match_regex = models.CharField(
        max_length=100, default=r"[vV]*(\d+\.)?(\d+\.)?(\*|\d+)", null=True, blank=True
    )
    is_default = models.BooleanField(default=False)
    is_subdomain_gathering = models.BooleanField(default=False)
    is_github_cloned = models.BooleanField(default=False)
    github_clone_path = models.CharField(max_length=1500, null=True, blank=True)
    subdomain_gathering_command = models.CharField(max_length=300, null=True, blank=True)

    def __str__(self):
        return self.name


# Define choices for workflow modes
WORKFLOW_MODE_CHOICES = [
    ("legacy", "Legacy YAML (ancien système)"),
    ("secator", "Secator Workflow (nouveau système)"),
]

# Define choices for predefined Secator workflows
SECATOR_WORKFLOW_CHOICES = [
    ("bug_bounty_basic", "Bug Bounty Basic"),
    ("internal_network_basic", "Internal Network Basic"),
    ("vulnerability_assessment", "Vulnerability Assessment"),
    ("custom", "Custom Workflow"),
]

# Define choices for Secator built-in workflows
SECATOR_BUILTIN_WORKFLOW_CHOICES = [
    ("cidr_recon", "CIDR Reconnaissance"),
    ("code_scan", "Code Vulnerability Scan"),
    ("host_recon", "Host Reconnaissance"),
    ("subdomain_recon", "Subdomain Discovery"),
    ("url_bypass", "URL Bypass"),
    ("url_crawl", "URL Crawl (Fast)"),
    ("url_dirsearch", "URL Directory Search"),
    ("url_fuzz", "URL Fuzz (Slow)"),
    ("url_params_fuzz", "URL Parameters Fuzz"),
    ("url_vuln", "URL Vulnerability Scan"),
    ("user_hunt", "User Account Search"),
    ("wordpress", "WordPress Vulnerability Scan"),
]


class ScanEngine(models.Model):
    """
    Represents a scan engine configuration, supporting both legacy YAML
    and new Secator workflow definitions for a phased migration.
    """

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=200, unique=True)
    description = models.TextField(blank=True, null=True)
    default_engine = models.BooleanField(null=True, default=False)

    # Legacy system fields
    yaml_config = models.TextField(blank=True, null=True, help_text="Legacy YAML configuration for the scan engine.")

    # New Secator system fields
    secator_workflow_name = models.CharField(
        max_length=100,
        choices=SECATOR_WORKFLOW_CHOICES,
        blank=True,
        null=True,
        help_text="Name of the predefined Secator workflow to use.",
    )
    secator_builtin_workflow = models.CharField(
        max_length=100,
        choices=SECATOR_BUILTIN_WORKFLOW_CHOICES,
        blank=True,
        null=True,
        help_text="Name of the Secator built-in workflow to use.",
    )
    custom_secator_workflow_file = models.FileField(
        upload_to="secator_workflows/", blank=True, null=True, help_text="Upload a custom Secator workflow YAML file."
    )

    # Mode of operation for the scan engine
    workflow_mode = models.CharField(
        max_length=20,
        choices=WORKFLOW_MODE_CHOICES,
        default="legacy",
        help_text="Determines whether to use legacy YAML or Secator workflow.",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Scan Engine"
        verbose_name_plural = "Scan Engines"
        ordering = ["name"]

    def __str__(self):
        return self.name

    def get_workflow_config(self):
        """
        Returns the appropriate workflow configuration based on the workflow_mode.

        Returns:
            A dictionary representing the workflow configuration.

        Raises:
            ValueError: If no valid workflow configuration is found.
        """
        if self.workflow_mode == "secator":
            # Check for built-in workflow first
            if self.secator_builtin_workflow:
                return {
                    "type": "builtin",
                    "workflow_id": self.secator_builtin_workflow,
                    "name": self.name,
                    "description": self.description,
                }
            # Check for custom workflow file
            elif self.secator_workflow_name == "custom" and self.custom_secator_workflow_file:
                return self._load_secator_workflow_from_file(self.custom_secator_workflow_file.path)
            # Check for predefined workflow
            elif self.secator_workflow_name:
                workflow_path = os.path.join(
                    os.path.dirname(os.path.abspath(__file__)),
                    "..",
                    "config",
                    "secator_workflows",
                    f"{self.secator_workflow_name}.yaml",
                )
                return self._load_secator_workflow_from_file(workflow_path)
            else:
                raise ValueError("Secator workflow mode selected but no workflow specified.")
        elif self.workflow_mode == "legacy":
            if self.yaml_config:
                return yaml.safe_load(self.yaml_config)
            else:
                raise ValueError("Legacy workflow mode selected but no YAML configuration found.")
        else:
            raise ValueError(f"Unknown workflow mode: {self.workflow_mode}")

    def _load_secator_workflow_from_file(self, file_path):
        """Helper to load Secator workflow from a given file path."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Secator workflow file not found: {file_path}")
        with open(file_path, "r") as f:
            return yaml.safe_load(f)

    def save(self, *args, **kwargs):
        """Override save to handle default engine logic and ensure consistency."""
        # Ensure that if a custom file is uploaded, the secator_workflow_name is set to 'custom'
        if self.custom_secator_workflow_file and self.secator_workflow_name != "custom":
            self.secator_workflow_name = "custom"
        elif not self.custom_secator_workflow_file and self.secator_workflow_name == "custom":
            # If custom is selected but no file, reset to None or default
            self.secator_workflow_name = None  # Or a sensible default like 'bug_bounty_basic'

        super().save(*args, **kwargs)
