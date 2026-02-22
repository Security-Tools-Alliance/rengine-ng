from urllib.parse import urlparse, urlunparse

from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import IntegrityError, models, transaction
import yaml

from reNgine.utilities.logger import get_module_logger


PREFIX_SCANENGINE = "[SCANENGINE]"
logger = get_module_logger(__name__)


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
        ("internet", "Internet"),
        ("internal_network", "Internal Network"),
    ]

    id = models.AutoField(primary_key=True)
    engine_name = models.CharField(max_length=200)
    yaml_configuration = models.TextField()
    default_engine = models.BooleanField(null=True, default=False)
    scan_type = models.CharField(
        max_length=20,
        choices=SCAN_TYPE_CHOICES,
        default="internet",
        help_text="Type of scan this engine is designed for",
    )
    is_legacy = models.BooleanField(
        default=True, help_text="Whether this is a legacy scan engine (deprecated in favor of Secator)"
    )

    class Meta:
        indexes = [models.Index(fields=["default_engine"], name="se_enginetype_default_idx")]

    def __str__(self):
        return self.engine_name

    def get_number_of_steps(self):
        return len(self.tasks) if self.tasks else 0

    def get_scan_type_from_yaml(self):
        """Extract scan_type from YAML configuration"""
        try:
            if not self.yaml_configuration:
                return "internet"

            config = yaml.safe_load(self.yaml_configuration)
            if isinstance(config, dict) and "scan_type" in config:
                return config["scan_type"]

            return "internet"  # Default fallback
        except Exception:
            return "internet"  # Safe fallback

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
        except yaml.YAMLError as e:
            logger.log_line(
                PREFIX_SCANENGINE,
                "MODEL",
                "Failed to parse YAML configuration: %s" % (e,),
                level="warning",
                exc_info=True,
            )
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


# Secator Integration Models


class SecatorWorkflow(models.Model):
    """
    Secator workflow configuration (built-in or custom).

    Optimization attributes (set by views/templatetags to avoid repeated computation):
    - _precomputed_structured_tasks: result of get_structured_tasks() when set
    - _precomputed_tasks_count: result of get_tasks_count() when set
    """

    WORKFLOW_TYPE_CHOICES = [
        ("builtin", "Built-in"),
        ("custom", "Custom"),
    ]

    WORKFLOW_NAME_CHOICES = [
        ("cidr_recon", "CIDR Recon"),
        ("code_scan", "Code Scan"),
        ("domain_recon", "Domain Recon"),
        ("host_recon", "Host Recon"),
        ("subdomain_recon", "Subdomain Recon"),
        ("url_bypass", "URL Bypass"),
        ("url_crawl", "URL Crawl"),
        ("url_dirsearch", "URL Directory Search"),
        ("url_fuzz", "URL Fuzz"),
        ("url_params_fuzz", "URL Parameters Fuzz"),
        ("url_vuln", "URL Vulnerability"),
        ("user_hunt", "User Hunt"),
        ("wordpress", "WordPress"),
    ]

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=200, unique=True)
    alias = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text="Built-in workflow alias from Secator (for CLI usage only, not used by reNgine-ng)",
    )
    description = models.TextField(blank=True, null=True)
    long_description = models.TextField(
        blank=True,
        null=True,
        help_text="Long description for the workflow",
    )
    workflow_type = models.CharField(
        max_length=20,
        choices=WORKFLOW_TYPE_CHOICES,
        default="custom",
        help_text="Type of workflow: built-in from Secator or custom",
    )
    yaml_configuration = models.TextField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    scan_type = models.CharField(
        max_length=20,
        choices=EngineType.SCAN_TYPE_CHOICES,
        default="internet",
        help_text="Type of scan this workflow is designed for",
    )
    display_name = models.CharField(
        max_length=200,
        blank=True,
        null=True,
        help_text="User-friendly display name for the workflow",
    )
    tags = ArrayField(
        models.CharField(max_length=50, blank=True),
        default=list,
        blank=True,
        help_text="Secator workflow tags for filtering and grouping (e.g. http, recon, fuzz)",
    )

    def get_display_name(self):
        """Return display_name if available, otherwise format name"""
        if self.display_name:
            return self.display_name
        return self.name.replace("_", " ").title()

    def __str__(self):
        return f"{self.get_display_name()} ({self.workflow_type})"

    def _parse_yaml_config(self):
        """Parse YAML configuration safely"""
        if not self.yaml_configuration:
            return {}

        try:
            config = yaml.safe_load(self.yaml_configuration)
            return config if isinstance(config, dict) else {}
        except yaml.YAMLError as e:
            logger.log_line(
                PREFIX_SCANENGINE,
                "MODEL",
                "Failed to parse YAML configuration: %s" % (e,),
                level="warning",
                exc_info=True,
            )
            return {}

    def get_tasks(self):
        """Return list of tasks in this workflow"""
        config = self._parse_yaml_config()
        return config.get("tasks", [])

    def get_structured_tasks(self):
        """
        Return structured list of tasks with group information.

        Returns a list of dictionaries:
        - For groups: {"type": "group", "name": "_group/discover", "display_name": "discover", "tasks": ["netdetect", "arp"]}
        - For individual tasks: {"type": "task", "name": "prompt", "group": None}
        """
        # Use pre-computed value if available (from view optimization)
        if hasattr(self, "_precomputed_structured_tasks"):
            return self._precomputed_structured_tasks

        tasks_dict = self.get_tasks()
        if not isinstance(tasks_dict, dict):
            return []

        structured = []

        for key, value in tasks_dict.items():
            # Check if this is a group (starts with _group, with or without suffix)
            if key.startswith("_group"):
                # This is a group
                group_tasks = []
                if isinstance(value, dict):
                    # Extract task names from the group
                    group_tasks = list(value.keys())

                # Extract display name: remove "_group" prefix and any following "/" or ":"
                display_name = key.replace("_group", "", 1).lstrip("/:").strip() or "tasks"

                structured.append({"type": "group", "name": key, "display_name": display_name, "tasks": group_tasks})
            else:
                # This is an individual task
                structured.append({"type": "task", "name": key, "group": None})

        return structured

    def get_tasks_count(self):
        """
        Return total count of individual tasks (including tasks within groups).

        This counts all individual tasks, not groups.
        """
        # Use pre-computed value if available (from view optimization)
        if hasattr(self, "_precomputed_tasks_count"):
            return self._precomputed_tasks_count

        structured = self.get_structured_tasks()
        return sum(len(item["tasks"]) if item["type"] == "group" else 1 for item in structured)

    def can_modify(self):
        """Check if this workflow can be modified"""
        return self.workflow_type != "builtin"

    def can_delete(self):
        """Check if this workflow can be deleted"""
        return self.workflow_type != "builtin"

    def save(self, *args, **kwargs):
        """Override save to prevent modification of built-in workflows"""
        # Allow modification if explicitly bypassing constraints (for management commands)
        if kwargs.pop("bypass_builtin_constraints", False):
            super().save(*args, **kwargs)
            return

        if self.pk is not None:
            try:
                orig = SecatorWorkflow.objects.get(pk=self.pk)
                if orig.workflow_type == "builtin":
                    raise PermissionDenied("Built-in workflows cannot be modified!")
            except SecatorWorkflow.DoesNotExist as e:
                logger.log_line(
                    PREFIX_SCANENGINE,
                    "MODEL",
                    "SecatorWorkflow pk=%s no longer exists in database; cannot check built-in constraint on save."
                    % (self.pk,),
                    level="error",
                    exc_info=True,
                )
                raise e
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Override delete to prevent deletion of built-in workflows"""
        # Allow deletion if explicitly bypassing constraints (for management commands)
        if kwargs.pop("bypass_builtin_constraints", False):
            super().delete(*args, **kwargs)
            return

        if self.workflow_type == "builtin":
            raise PermissionDenied("Built-in workflows cannot be deleted!")
        super().delete(*args, **kwargs)

    class Meta:
        ordering = ["workflow_type", "name"]
        indexes = [models.Index(fields=["is_active"], name="se_secatorworkflow_active_idx")]


class SecatorTask(models.Model):
    """Secator individual task configuration"""

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=200, unique=True)
    task_type = models.CharField(max_length=100, help_text="Secator task type (e.g., subfinder, nuclei)")
    tags = ArrayField(
        models.CharField(max_length=50, blank=True),
        default=list,
        blank=True,
        help_text="Secator task tags for filtering and grouping (e.g. url, fuzz, dns)",
    )
    description = models.TextField(blank=True, null=True)
    is_builtin = models.BooleanField(default=True, help_text="Whether this is a built-in Secator task")
    yaml_configuration = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True, help_text="Whether this task is available for use")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.task_type})"

    def can_modify(self):
        """Check if this task can be modified"""
        return not self.is_builtin

    def can_delete(self):
        """Check if this task can be deleted"""
        return not self.is_builtin

    def save(self, *args, **kwargs):
        """Override save to prevent modification of built-in tasks"""
        # Allow modification if explicitly bypassing constraints (for management commands)
        if kwargs.pop("bypass_builtin_constraints", False):
            super().save(*args, **kwargs)
            return

        if self.pk is not None:
            # This is an update operation
            try:
                orig = SecatorTask.objects.get(pk=self.pk)
                if orig.is_builtin:
                    if not kwargs.get("update_fields"):
                        # For regular operations, raise exception with clear message
                        raise PermissionDenied("Built-in tasks cannot be modified!")
                    else:
                        # For bulk operations, log the attempt but don't raise exception
                        logger.log_line(
                            PREFIX_SCANENGINE,
                            "MODEL",
                            "Attempted to modify built-in task '%s' (ID: %s) - operation blocked"
                            % (self.name, self.pk),
                            level="warning",
                        )
                        return  # Skip the save operation silently
            except SecatorTask.DoesNotExist as e:
                logger.log_line(
                    PREFIX_SCANENGINE,
                    "MODEL",
                    "SecatorTask pk=%s no longer exists in database; cannot check built-in constraint on save."
                    % (self.pk,),
                    level="error",
                    exc_info=True,
                )
                raise e
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Override delete to prevent deletion of built-in tasks"""
        # Allow deletion if explicitly bypassing constraints (for management commands)
        if kwargs.pop("bypass_builtin_constraints", False):
            super().delete(*args, **kwargs)
            return

        if self.is_builtin:
            raise PermissionDenied("Built-in tasks cannot be deleted!")
        super().delete(*args, **kwargs)

    class Meta:
        ordering = ["name"]


class SecatorScanQuerySet(models.QuerySet):
    """Custom queryset for SecatorScan with workflow filtering."""

    def filter_by_workflow(self, workflow):
        """Return scans whose YAML configuration references the given workflow (by alias or name)."""
        if identifiers := [x for x in [workflow.alias, workflow.name] if x]:
            return self.filter(workflow_identifiers__overlap=identifiers)
        else:
            return self.none()


class SecatorScanManager(models.Manager.from_queryset(SecatorScanQuerySet)):
    """Manager for SecatorScan using SecatorScanQuerySet."""

    pass


class SecatorScan(models.Model):
    """Secator scan configuration (built-in or custom)"""

    SCAN_CONFIG_TYPE_CHOICES = [
        ("builtin", "Built-in"),
        ("custom", "Custom"),
    ]

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=200, unique=True)
    description = models.TextField(blank=True, null=True)
    long_description = models.TextField(
        blank=True,
        null=True,
        help_text="Long description for the scan",
    )
    scan_config_type = models.CharField(
        max_length=20,
        choices=SCAN_CONFIG_TYPE_CHOICES,
        default="builtin",
        help_text="Type of scan configuration: built-in or custom",
    )
    yaml_configuration = models.TextField(default="")
    workflow_identifiers = ArrayField(
        models.CharField(max_length=255, blank=True),
        default=list,
        blank=True,
        help_text="Denormalized list of workflow identifiers (aliases/names) from YAML for DB-side filtering.",
    )
    is_default = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True, help_text="Whether this scan configuration is available for use")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    scan_type = models.CharField(
        max_length=20,
        choices=EngineType.SCAN_TYPE_CHOICES,
        default="internet",
        help_text="Type of scan this configuration is designed for",
    )

    objects = SecatorScanManager()

    def __str__(self):
        return f"{self.name} ({self.scan_config_type})"

    def get_display_name(self):
        """Return display name from name (underscores to spaces, preserve original case)."""
        return self.name.replace("_", " ")

    def _parse_yaml_config(self):
        """Parse YAML configuration safely"""
        if not self.yaml_configuration:
            return {}

        try:
            config = yaml.safe_load(self.yaml_configuration)
            return config if isinstance(config, dict) else {}
        except yaml.YAMLError as e:
            logger.log_line(
                PREFIX_SCANENGINE,
                "MODEL",
                "Failed to parse YAML configuration: %s" % (e,),
                level="warning",
                exc_info=True,
            )
            return {}

    def get_workflows(self):
        """Return dict of workflows in this scan (from YAML)."""
        config = self._parse_yaml_config()
        return config.get("workflows", {})

    def update_workflow_identifiers(self):
        """Refresh workflow_identifiers from YAML so DB-side filtering works."""
        self.workflow_identifiers = list(self.get_workflows().keys())

    def get_input_types(self):
        """Return list of input types for this scan"""
        config = self._parse_yaml_config()
        return config.get("input_types", [])

    def can_modify(self):
        """Check if this scan configuration can be modified"""
        return self.scan_config_type != "builtin"

    def can_delete(self):
        """Check if this scan configuration can be deleted"""
        return self.scan_config_type != "builtin"

    def save(self, *args, **kwargs):
        """Override save to prevent modification of built-in scan configurations"""
        # Allow modification if explicitly bypassing constraints (for management commands)
        if kwargs.pop("bypass_builtin_constraints", False):
            super().save(*args, **kwargs)
            return

        if self.pk is not None:
            try:
                orig = SecatorScan.objects.get(pk=self.pk)
                if orig.scan_config_type == "builtin":
                    raise PermissionDenied("Built-in scan configurations cannot be modified!")
            except SecatorScan.DoesNotExist as e:
                logger.log_line(
                    PREFIX_SCANENGINE,
                    "MODEL",
                    "SecatorScan pk=%s no longer exists in database; cannot check built-in constraint on save."
                    % (self.pk,),
                    level="error",
                    exc_info=True,
                )
                raise e
        self.update_workflow_identifiers()
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Override delete to prevent deletion of built-in scan configurations"""
        # Allow deletion if explicitly bypassing constraints (for management commands)
        if kwargs.pop("bypass_builtin_constraints", False):
            super().delete(*args, **kwargs)
            return

        if self.scan_config_type == "builtin":
            raise PermissionDenied("Built-in scan configurations cannot be deleted!")
        super().delete(*args, **kwargs)

    class Meta:
        ordering = ["scan_config_type", "name"]


class SecatorProfile(models.Model):
    """Secator profile configuration (built-in or custom)"""

    PROFILE_TYPE_CHOICES = [
        ("builtin", "Built-in"),
        ("custom", "Custom"),
    ]

    CATEGORY_CHOICES = [
        ("speed", "Speed"),
        ("evasion", "Evasion"),
        ("general", "General"),
        ("network", "Network"),
    ]

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=200, unique=True)
    category = models.CharField(
        max_length=20,
        choices=CATEGORY_CHOICES,
        help_text="Category of the profile",
    )
    description = models.TextField(help_text="Description of the profile")
    enforce = models.BooleanField(
        default=False,
        help_text="Whether this profile should enforce its options (handled by Secator)",
    )
    opts = models.TextField(
        help_text="YAML configuration options for the profile",
    )
    profile_type = models.CharField(
        max_length=20,
        choices=PROFILE_TYPE_CHOICES,
        default="custom",
        help_text="Type of profile: built-in from Secator or custom",
    )
    is_active = models.BooleanField(default=True, help_text="Whether this profile is available for use")
    is_default = models.BooleanField(
        default=False,
        help_text="Whether this profile is the default for its category (only one default per category allowed)",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.category}) - {self.profile_type}"

    def _parse_opts(self):
        """
        Parse opts YAML configuration safely.

        Returns:
            dict: Parsed options or empty dict on missing/invalid YAML.
        """
        if not getattr(self, "opts", None):
            return {}

        try:
            parsed = yaml.safe_load(self.opts)
            return parsed if isinstance(parsed, dict) else {}
        except yaml.YAMLError as exc:
            logger.log_line(
                PREFIX_SCANENGINE,
                "MODEL",
                "Failed to parse YAML opts for profile id=%s name=%s: %s"
                % (getattr(self, "id", None), getattr(self, "name", None), exc),
                level="warning",
            )
            return {}

    def can_modify(self):
        """Check if this profile can be modified"""
        return self.profile_type != "builtin"

    def can_delete(self):
        """Check if this profile can be deleted"""
        return self.profile_type != "builtin"

    def save(self, *args, **kwargs):
        """Override save to prevent modification of built-in profiles"""
        bypass_builtin = kwargs.pop("bypass_builtin_constraints", False)

        if not bypass_builtin and self.pk is not None:
            try:
                orig = SecatorProfile.objects.get(pk=self.pk)
                if orig.profile_type == "builtin":
                    raise PermissionDenied("Built-in profiles cannot be modified!")
            except SecatorProfile.DoesNotExist as e:
                logger.log_line(
                    PREFIX_SCANENGINE,
                    "MODEL",
                    "SecatorProfile pk=%s no longer exists in database; cannot check built-in constraint on save."
                    % (self.pk,),
                    level="error",
                    exc_info=True,
                )
                raise e

        try:
            with transaction.atomic():
                if self.is_default:
                    SecatorProfile.objects.filter(
                        category=self.category,
                        is_default=True,
                    ).exclude(pk=self.pk or None).update(is_default=False)
                super().save(*args, **kwargs)
        except IntegrityError as exc:
            raise ValidationError(
                "Failed to save SecatorProfile: another profile is already marked as "
                "default for this category. Please retry your request."
            ) from exc

    def delete(self, *args, **kwargs):
        """Override delete to prevent deletion of built-in profiles"""
        # Allow deletion if explicitly bypassing constraints (for management commands)
        if kwargs.pop("bypass_builtin_constraints", False):
            super().delete(*args, **kwargs)
            return

        if self.profile_type == "builtin":
            raise PermissionDenied("Built-in profiles cannot be deleted!")
        super().delete(*args, **kwargs)

    @classmethod
    def get_default_profiles(cls, categories=None):
        """
        Return a mapping of category -> default profile name.

        Performs a single query for all requested categories and applies
        hardcoded fallbacks when no active default is configured.

        Args:
            categories: List of category names to fetch defaults for.
                       Defaults to ["speed", "evasion", "general", "network"]

        Returns:
            dict: Mapping of category -> profile name (or fallback name)
        """
        if categories is None:
            categories = ["speed", "evasion", "general", "network"]

        # Hardcoded fallbacks in one place
        fallback_defaults = {
            "speed": "polite",
            "evasion": "stealth",
            "general": "full",
            "network": "all_ports",
        }

        # Fetch all relevant default profiles in a single query
        qs = cls.objects.filter(
            category__in=categories,
            is_default=True,
            is_active=True,
        ).values("category", "name")

        defaults_by_category = {row["category"]: row["name"] for row in qs}

        return {
            category: defaults_by_category.get(category, fallback_defaults.get(category, "")) for category in categories
        }

    class Meta:
        ordering = ["profile_type", "category", "name"]
        indexes = [models.Index(fields=["name", "profile_type"], name="se_secatorprofile_nametype_idx")]
        constraints = [
            models.UniqueConstraint(
                fields=["category"],
                condition=models.Q(is_default=True),
                name="unique_default_per_category",
            )
        ]


class SecatorWorkerQuerySet(models.QuerySet):
    """QuerySet for SecatorWorker with active() filter."""

    def active(self):
        """Return workers that are active (is_active=True)."""
        return self.filter(is_active=True)


class SecatorWorkerManager(models.Manager):
    """Manager that uses SecatorWorkerQuerySet and exposes active()."""

    def get_queryset(self):
        return SecatorWorkerQuerySet(self.model, using=self._db)

    def active(self):
        return self.get_queryset().active()


class SecatorWorker(models.Model):
    """
    Remote Secator worker host. Used for deployment via SSH and to associate
    runners (scan executions) with the worker that executed them.
    """

    AUTH_KEY = "key"
    AUTH_PASSWORD = "password"
    SSH_AUTH_CHOICES = [(AUTH_KEY, "SSH key"), (AUTH_PASSWORD, "Password")]

    API_ACCESS_TUNNEL = "tunnel"
    API_ACCESS_CLASSIC = "classic"
    API_ACCESS_CHOICES = [
        (API_ACCESS_TUNNEL, "SSH tunnel"),
        (API_ACCESS_CLASSIC, "HTTPS (external URL)"),
    ]

    name = models.CharField(max_length=255, unique=True)
    ssh_host = models.CharField(max_length=255)
    ssh_port = models.PositiveIntegerField(default=22)
    ssh_user = models.CharField(max_length=255)
    ssh_auth_type = models.CharField(max_length=20, choices=SSH_AUTH_CHOICES, default=AUTH_KEY)
    ssh_key_path = models.CharField(max_length=1024, null=True, blank=True)
    ssh_password_encrypted = models.TextField(null=True, blank=True)
    deploy_path = models.CharField(max_length=1024)
    container_name = models.CharField(max_length=255, null=True, blank=True)

    ssh_ok = models.BooleanField(default=False)
    container_running = models.BooleanField(default=False)
    api_reachable = models.BooleanField(default=False)
    last_status_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    api_access_type = models.CharField(
        max_length=20,
        choices=API_ACCESS_CHOICES,
        default=API_ACCESS_CLASSIC,
    )
    api_tunnel_port = models.PositiveIntegerField(
        default=8443,
        help_text="Port on worker side (127.0.0.1:port) when using SSH tunnel.",
    )
    api_url = models.CharField(
        max_length=512,
        blank=True,
        help_text="Base URL of reNgine API (e.g. https://rengine.example.com) for classic access.",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = SecatorWorkerManager()

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def get_api_base_url(self) -> str:
        """Return the API base URL this worker uses (for .env and health check)."""
        if self.api_access_type == self.API_ACCESS_TUNNEL:
            base_url = getattr(settings, "SECATOR_ADDONS_API_URL", "") or ""
            if not base_url:
                return f"https://host.docker.internal:{self.api_tunnel_port}"
            parsed = urlparse(base_url.strip().rstrip("/"))
            new_netloc = f"host.docker.internal:{self.api_tunnel_port}"
            return urlunparse(
                (parsed.scheme or "https", new_netloc, parsed.path or "/", parsed.params, parsed.query, parsed.fragment)
            ).rstrip("/")
        return (self.api_url or "").strip().rstrip("/")
