from django import forms
from django.contrib.postgres.forms import SimpleArrayField
from django.core.exceptions import ValidationError
from django_ace import AceWidget
import yaml

from reNgine.validators import validate_short_name
from scanEngine.models import (
    Configuration,
    EngineType,
    Hackerone,
    InterestingLookupModel,
    Notification,
    Proxy,
    SecatorProfile,
    SecatorScan,
    SecatorTask,
    SecatorWorker,
    SecatorWorkflow,
    VulnerabilityReportSetting,
)


class AddEngineForm(forms.ModelForm):
    class Meta:
        model = EngineType
        fields = "__all__"

    engine_name = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={"class": "form-control form-control-lg", "id": "scan_engine_name", "placeholder": "Engine Name"}
        ),
    )
    scan_type = forms.ChoiceField(
        choices=EngineType.SCAN_TYPE_CHOICES,
        required=True,
        widget=forms.Select(attrs={"class": "form-control form-control-lg", "id": "scan_type"}),
        help_text="Select the type of scan this engine is designed for",
    )
    yaml_configuration = forms.CharField(
        widget=AceWidget(
            mode="yaml",
            theme="tomorrow_night_eighties",
            width="100%",
            height="450px",
            tabsize=2,
            fontsize="17px",
            showinvisibles=True,
            attrs={"id": "editor"},
        )
    )

    def save(self, commit=True):
        """Override save to mark scan_type as explicitly set"""
        instance = super().save(commit=False)
        instance._scan_type_explicitly_set = True
        if commit:
            instance.save()
        return instance


class UpdateEngineForm(forms.ModelForm):
    class Meta:
        model = EngineType
        fields = "__all__"

    engine_name = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={"class": "form-control form-control-lg", "id": "scan_engine_name", "placeholder": "Custom Engine"}
        ),
    )
    scan_type = forms.ChoiceField(
        choices=EngineType.SCAN_TYPE_CHOICES,
        required=True,
        widget=forms.Select(attrs={"class": "form-control form-control-lg", "id": "scan_type"}),
        help_text="Select the type of scan this engine is designed for",
    )
    yaml_configuration = forms.CharField(
        widget=AceWidget(
            mode="yaml",
            theme="tomorrow_night_eighties",
            width="100%",
            height="450px",
            tabsize=2,
            fontsize="17px",
            showinvisibles=True,
            attrs={"id": "editor"},
        )
    )

    def save(self, commit=True):
        """Override save to mark scan_type as explicitly set"""
        instance = super().save(commit=False)
        instance._scan_type_explicitly_set = True
        if commit:
            instance.save()
        return instance


class AddWordlistForm(forms.Form):
    name = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control form-control-lg",
                "id": "name",
                "placeholder": "my awesome wordlist",
            }
        ),
    )
    short_name = forms.CharField(
        required=False,
        validators=[validate_short_name],
        widget=forms.TextInput(
            attrs={
                "class": "form-control form-control-lg",
                "id": "short_name",
                "placeholder": "my_awesome_wordlist",
            }
        ),
    )
    upload_file = forms.FileField(
        required=True,
        widget=forms.FileInput(
            attrs={
                "class": "form-control",
                "id": "txtFile",
                "multiple": "",
                "accept": ".txt",
            }
        ),
    )


class ConfigurationForm(forms.ModelForm):
    class Meta:
        model = Configuration
        fields = "__all__"

    name = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={
                "class": "form-control form-control-lg",
                "id": "name",
                "placeholder": "Configuration Name",
            }
        ),
    )
    short_name = forms.CharField(
        required=True,
        validators=[validate_short_name],
        widget=forms.TextInput(
            attrs={
                "class": "form-control form-control-lg",
                "id": "short_name",
                "placeholder": "my_awesome_configuration",
            }
        ),
    )
    content = forms.CharField(
        widget=AceWidget(
            mode="text",
            theme="monokai",
            width="100%",
            height="450px",
            tabsize=4,
            fontsize=13,
            toolbar=True,
        )
    )

    def set_value(self, configuration):
        self.initial["name"] = configuration.name
        self.initial["short_name"] = configuration.short_name
        self.initial["content"] = configuration.content


class InterestingLookupForm(forms.ModelForm):
    class Meta:
        model = InterestingLookupModel
        fields = "__all__"

    keywords = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control form-control-lg",
                "id": "keywords",
                "placeholder": "Interesting Keywords",
            }
        ),
    )

    custom_type = forms.BooleanField(required=False, widget=forms.HiddenInput(attrs={"value": "true"}))

    title_lookup = forms.BooleanField(
        required=False, widget=forms.CheckboxInput(attrs={"class": "form-check-input", "id": "title_lookup"})
    )

    url_lookup = forms.BooleanField(
        required=False, widget=forms.CheckboxInput(attrs={"class": "form-check-input", "id": "url_lookup"})
    )

    condition_200_http_lookup = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "form-check-input", "id": "condition_200_http_lookup"}),
    )

    def set_value(self, key):
        print(key.url_lookup)
        self.initial["keywords"] = key.keywords
        self.initial["title_lookup"] = key.title_lookup
        self.initial["url_lookup"] = key.url_lookup
        self.initial["condition_200_http_lookup"] = key.condition_200_http_lookup

    def initial_checkbox(self):
        self.initial["title_lookup"] = True
        self.initial["url_lookup"] = True
        self.initial["condition_200_http_lookup"] = False


class NotificationForm(forms.ModelForm):
    class Meta:
        model = Notification
        fields = "__all__"

    send_to_slack = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
                "id": "slack_checkbox",
            }
        ),
    )

    slack_hook_url = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "slack_hook_url",
                "placeholder": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
            }
        ),
    )

    send_to_lark = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
                "id": "lark_checkbox",
            }
        ),
    )

    lark_hook_url = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "lark_hook_url",
                "placeholder": "https://open.larksuite.com/open-apis/bot/v2/hook/XXXXXXXXXXXXXXXXXXXXXXXX",
            }
        ),
    )

    send_to_discord = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
                "id": "discord_checkbox",
            }
        ),
    )

    discord_hook_url = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "discord_hook_url",
                "placeholder": "https://discord.com/api/webhooks/000000000000000000/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            }
        ),
    )

    send_to_telegram = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
                "id": "telegram_checkbox",
            }
        ),
    )

    telegram_bot_token = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "telegram_bot_token",
                "placeholder": "Bot Token",
            }
        ),
    )

    telegram_bot_chat_id = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "telegram_bot_chat_id",
                "placeholder": "Bot Chat ID",
            }
        ),
    )

    send_scan_status_notif = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
                "id": "send_scan_status_notif",
            }
        ),
    )

    send_interesting_notif = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
                "id": "send_interesting_notif",
            }
        ),
    )

    send_vuln_notif = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
                "id": "send_vuln_notif",
            }
        ),
    )

    send_subdomain_changes_notif = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
                "id": "send_subdomain_changes_notif",
            }
        ),
    )

    send_scan_output_file = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
                "id": "send_scan_output_file",
            }
        ),
    )

    send_scan_tracebacks = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
                "id": "send_scan_tracebacks",
            }
        ),
    )

    def set_value(self, key):
        self.initial["send_to_slack"] = key.send_to_slack
        self.initial["send_to_lark"] = key.send_to_lark
        self.initial["send_to_discord"] = key.send_to_discord
        self.initial["send_to_telegram"] = key.send_to_telegram

        self.initial["slack_hook_url"] = key.slack_hook_url
        self.initial["lark_hook_url"] = key.lark_hook_url
        self.initial["discord_hook_url"] = key.discord_hook_url
        self.initial["telegram_bot_token"] = key.telegram_bot_token
        self.initial["telegram_bot_chat_id"] = key.telegram_bot_chat_id

        self.initial["send_scan_status_notif"] = key.send_scan_status_notif
        self.initial["send_interesting_notif"] = key.send_interesting_notif
        self.initial["send_vuln_notif"] = key.send_vuln_notif
        self.initial["send_subdomain_changes_notif"] = key.send_subdomain_changes_notif

        self.initial["send_scan_output_file"] = key.send_scan_output_file
        self.initial["send_scan_tracebacks"] = key.send_scan_tracebacks

        if not key.send_to_slack:
            self.fields["slack_hook_url"].widget.attrs["readonly"] = True
        if not key.send_to_lark:
            self.fields["lark_hook_url"].widget.attrs["readonly"] = True
        if not key.send_to_discord:
            self.fields["discord_hook_url"].widget.attrs["readonly"] = True
        if not key.send_to_telegram:
            self.fields["telegram_bot_token"].widget.attrs["readonly"] = True
            self.fields["telegram_bot_chat_id"].widget.attrs["readonly"] = True

    def set_initial(self):
        self.initial["send_to_slack"] = False
        self.initial["send_to_lark"] = False
        self.initial["send_to_discord"] = False
        self.initial["send_to_telegram"] = False

        self.fields["slack_hook_url"].widget.attrs["readonly"] = True
        self.fields["lark_hook_url"].widget.attrs["readonly"] = True
        self.fields["discord_hook_url"].widget.attrs["readonly"] = True
        self.fields["telegram_bot_token"].widget.attrs["readonly"] = True
        self.fields["telegram_bot_chat_id"].widget.attrs["readonly"] = True

        self.initial["send_scan_status_notif"] = True
        self.initial["send_interesting_notif"] = True
        self.initial["send_vuln_notif"] = True
        self.initial["send_subdomain_changes_notif"] = True

        self.initial["send_scan_output_file"] = True
        self.initial["send_scan_tracebacks"] = True


class ProxyForm(forms.ModelForm):
    class Meta:
        model = Proxy
        fields = "__all__"

    use_proxy = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
                "id": "use_proxy",
            }
        ),
    )

    proxies = forms.CharField(
        required=False,
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "id": "proxies",
                "rows": "10",
                "spellcheck": "false",
                "placeholder": "http://username:password@proxyip.com:port",
            }
        ),
    )

    def set_value(self, key):
        self.initial["use_proxy"] = key.use_proxy
        self.initial["proxies"] = key.proxies

        if not key.use_proxy:
            self.fields["proxies"].widget.attrs["readonly"] = True

    def set_initial(self):
        self.initial["use_proxy"] = False
        self.fields["proxies"].widget.attrs["readonly"] = True


class HackeroneForm(forms.ModelForm):
    class Meta:
        model = Hackerone
        fields = "__all__"

    username = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={
                "class": "form-control form-control-lg",
                "id": "username",
                "placeholder": "Your Hackerone Username",
            }
        ),
    )

    api_key = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={
                "class": "form-control form-control-lg",
                "id": "api_key",
                "placeholder": "Hackerone API Token",
            }
        ),
    )

    send_critical = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
                "id": "send_critical",
            }
        ),
    )

    send_high = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
                "id": "send_high",
            }
        ),
    )

    send_medium = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
                "id": "send_medium",
            }
        ),
    )

    report_template = forms.CharField(
        required=False, widget=forms.Textarea(attrs={"id": "vulnerability-report-template"})
    )

    def set_value(self, key):
        self.initial["username"] = key.username
        self.initial["api_key"] = key.api_key

        self.initial["send_critical"] = key.send_critical
        self.initial["send_high"] = key.send_high
        self.initial["send_medium"] = key.send_medium

        self.initial["report_template"] = key.report_template

    def set_initial(self):
        self.initial["send_critical"] = True
        self.initial["send_high"] = True
        self.initial["send_medium"] = False

        self.initial[
            "report_template"
        ] = """Hi Team, while testing, a {vulnerability_severity} severity vulnerability has been discovered in {vulnerable_url} and below is the findings.

# Vulnerability
{vulnerability_name}

## Issue Description
{vulnerability_description}

## Vulnerable URL
- {vulnerable_url}

## Extracted Results/Findings
{vulnerability_extracted_results}

## References
- {vulnerability_reference}

Thank you"""


class ReportForm(forms.ModelForm):
    class Meta:
        model = VulnerabilityReportSetting
        fields = "__all__"

    company_name = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control form-control-lg",
                "id": "company_name",
                "placeholder": "Company Name",
            }
        ),
    )

    company_address = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control form-control-lg",
                "id": "company_address",
                "placeholder": "Company Address",
            }
        ),
    )

    company_website = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control form-control-lg",
                "id": "company_website",
                "placeholder": "Company Website https://company.com",
            }
        ),
    )

    company_email = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control form-control-lg",
                "id": "company_email",
                "placeholder": "email@yourcompany.com",
            }
        ),
    )

    show_footer = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
                "id": "show_footer",
            }
        ),
    )

    footer_text = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control form-control-lg",
                "id": "footer_text",
                "aria-label": "switch",
                "placeholder": "Footer Text © Your Company",
            }
        ),
    )

    show_rengine_banner = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
                "id": "show_rengine_banner",
            }
        ),
    )

    show_executive_summary = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                "class": "form-check-input",
                "id": "show_executive_summary",
            }
        ),
    )

    executive_summary_description = forms.CharField(
        required=False, widget=forms.Textarea(attrs={"id": "executive_summary_description"})
    )

    primary_color = forms.CharField(
        required=False, widget=forms.TextInput(attrs={"id": "primary_color", "hidden": "true"})
    )

    secondary_color = forms.CharField(
        required=False, widget=forms.TextInput(attrs={"id": "secondary_color", "hidden": "true"})
    )

    def set_value(self, key):
        self.initial["company_name"] = key.company_name
        self.initial["company_address"] = key.company_address
        self.initial["company_website"] = key.company_website
        self.initial["company_email"] = key.company_email
        self.initial["show_rengine_banner"] = key.show_rengine_banner
        self.initial["show_executive_summary"] = key.show_executive_summary
        self.initial["executive_summary_description"] = key.executive_summary_description
        self.initial["show_footer"] = key.show_footer
        self.initial["footer_text"] = key.footer_text
        self.initial["primary_color"] = key.primary_color
        self.initial["secondary_color"] = key.secondary_color

    def set_initial(self):
        self.initial["show_rengine_banner"] = True
        self.initial["show_footer"] = False
        self.initial["show_executive_summary"] = False
        self.initial["primary_color"] = "#FFB74D"
        self.initial["secondary_color"] = "#212121"
        self.initial[
            "executive_summary_description"
        ] = """On **{scan_date}**, **{target_name}** engaged **{company_name}** to perform a security audit on their Web application.

**{company_name}** performed both Security Audit and Reconnaissance using automated tool reNgine-ng. https://github.com/Security-Tools-Alliance/rengine-ng/.

## Observations

During the course of this engagement **{company_name}** was able to discover **{subdomain_count}** Subdomains and  **{vulnerability_count}** Vulnerabilities, including informational vulnerabilities and these could pose a significant risk to the security of the application.

The breakdown of the Vulnerabilities Identified in **{target_name}** by severity are as follows:

* Critical : {critical_count}
* High : {high_count}
* Medium : {medium_count}
* Low : {low_count}
* Info : {info_count}
* Unknown : {unknown_count}

**{company_name}** recommends that these issues be addressed in timely manner.

"""


# =============================================================================
# SECATOR INTEGRATION FORMS
# =============================================================================


class SecatorWorkflowForm(forms.ModelForm):
    """Form for creating/editing Secator workflows."""

    tags = SimpleArrayField(
        forms.CharField(max_length=50, required=False),
        required=False,
        delimiter=",",
        help_text="Comma-separated tags (e.g. http, recon, fuzz)",
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "e.g. http, recon, fuzz"}),
    )

    class Meta:
        model = SecatorWorkflow
        fields = ["name", "alias", "description", "tags", "scan_type", "yaml_configuration", "is_active"]

    name = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={"class": "form-control form-control-lg", "id": "workflow_name", "placeholder": "Workflow Name"}
        ),
    )
    alias = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control form-control-lg",
                "id": "workflow_alias",
                "placeholder": "Workflow alias (e.g., subdomain_recon)",
            }
        ),
        help_text="Workflow alias from Secator (e.g., subdomain_recon, cidr_recon). See <a href='https://docs.freelabz.com/for-developers/writing-workflows' target='_blank'>Secator workflows documentation</a>",
    )
    description = forms.CharField(
        required=False,
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "id": "workflow_description",
                "rows": 3,
                "placeholder": "Enter workflow description",
            }
        ),
    )
    scan_type = forms.ChoiceField(
        choices=EngineType.SCAN_TYPE_CHOICES,
        required=True,
        widget=forms.Select(attrs={"class": "form-control form-control-lg", "id": "scan_type"}),
        help_text="Select the type of scan this workflow is designed for",
    )
    yaml_configuration = forms.CharField(
        widget=AceWidget(
            mode="yaml",
            theme="tomorrow_night_eighties",
            width="100%",
            height="450px",
            tabsize=2,
            fontsize="17px",
            showinvisibles=True,
            attrs={"id": "editor"},
        ),
        help_text="Define the workflow structure and tasks. See <a href='https://docs.freelabz.com/for-developers/writing-workflows' target='_blank'>Secator documentation</a>",
    )
    is_active = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "form-check-input", "id": "is_active"}),
    )

    def clean_yaml_configuration(self):
        """Validate YAML configuration and schema."""
        yaml_config = self.cleaned_data.get("yaml_configuration")

        if yaml_config:
            try:
                parsed_yaml = yaml.safe_load(yaml_config)
            except yaml.YAMLError as e:
                raise ValidationError(f"Invalid YAML configuration: {e}") from e

            # Schema validation: check for required fields
            if not isinstance(parsed_yaml, dict):
                raise ValidationError("YAML configuration must be a mapping (dictionary) at the top level.")

            # Required top-level fields
            required_fields = ["name", "description", "type", "tags"]
            if missing_fields := [field for field in required_fields if field not in parsed_yaml]:
                raise ValidationError(f"Missing required field(s) in YAML configuration: {', '.join(missing_fields)}")

            # Validate field types and values
            self._validate_yaml_field_types(parsed_yaml)

            # Validate tasks section if present
            if "tasks" in parsed_yaml:
                self._validate_tasks_section(parsed_yaml["tasks"])

        return yaml_config

    def _validate_yaml_field_types(self, parsed_yaml):
        """Validate types and values of YAML fields."""
        # Validate name field
        if not isinstance(parsed_yaml.get("name"), str) or not parsed_yaml.get("name").strip():
            raise ValidationError("Field 'name' must be a non-empty string.")

        # Validate description field
        if not isinstance(parsed_yaml.get("description"), str) or not parsed_yaml.get("description").strip():
            raise ValidationError("Field 'description' must be a non-empty string.")

        # Validate type field
        valid_types = ["workflow"]
        config_type = parsed_yaml.get("type")
        if not isinstance(config_type, str) or config_type not in valid_types:
            raise ValidationError(f"Field 'type' must be one of: {', '.join(valid_types)}")

        # # Validate workflow_type field
        # valid_workflow_types = ["builtin", "custom"]
        # workflow_type = parsed_yaml.get("workflow_type")
        # if not isinstance(workflow_type, str) or workflow_type not in valid_workflow_types:
        #     raise ValidationError(f"Field 'workflow_type' must be one of: {', '.join(valid_workflow_types)}")

    def _validate_tasks_section(self, tasks):
        """Validate the tasks section of the YAML configuration."""
        if not isinstance(tasks, dict):
            raise ValidationError("Field 'tasks' must be a dictionary.")

        if not tasks:
            raise ValidationError("Field 'tasks' cannot be empty.")

        for task_name, task in tasks.items():
            if not isinstance(task, (dict, str)):
                raise ValidationError(f"Task '{task_name}' must be a dictionary or string.")
            if isinstance(task, str):
                continue
            if task_name.startswith("_"):
                continue
            # Required task fields
            required_task_fields = ["description"]
            if missing_task_fields := [field for field in required_task_fields if field not in task]:
                raise ValidationError(f"Task '{task_name}' missing required field(s): {', '.join(missing_task_fields)}")

            # Validate task field types
            if not isinstance(task.get("description"), str) or not task.get("description").strip():
                raise ValidationError(f"Task '{task_name}': field 'description' must be a non-empty string.")

    def clean_name(self):
        """Validate workflow name uniqueness."""
        name = self.cleaned_data.get("name")

        if name:
            # Check for duplicates (excluding current instance)
            queryset = SecatorWorkflow.objects.filter(name=name)
            if self.instance.pk:
                queryset = queryset.exclude(pk=self.instance.pk)

            if queryset.exists():
                raise ValidationError("A workflow with this name already exists.")

        return name

    def clean(self):
        """Validate that built-in workflows cannot be modified."""
        cleaned_data = super().clean()

        # Check if this is an update operation on a built-in workflow
        if self.instance.pk and self.instance.workflow_type == "builtin":
            # Set a flag to indicate the error was raised in clean()
            self._builtin_modification_error = True
            raise ValidationError("Built-in workflows cannot be modified.")

        return cleaned_data

    def save(self, *args, **kwargs):
        # Prevent duplicate error messages if clean() already raised the error
        if getattr(self, "_builtin_modification_error", False):
            # clean() already raised the error, so just return without saving
            return self.instance
        # Additional safeguard: if somehow save() is called directly, block modification
        if self.instance.pk and self.instance.workflow_type == "builtin":
            raise ValidationError("Built-in workflows cannot be modified.")
        return super().save(*args, **kwargs)


class SecatorTaskForm(forms.ModelForm):
    """Form for creating/editing Secator tasks."""

    tags = SimpleArrayField(
        forms.CharField(max_length=50, required=False),
        required=False,
        delimiter=",",
        help_text="Comma-separated tags (e.g. url, fuzz, dns)",
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "e.g. url, fuzz, dns"}),
    )

    class Meta:
        model = SecatorTask
        fields = ["name", "task_type", "tags", "description", "yaml_configuration", "is_active"]
        widgets = {
            "name": forms.TextInput(attrs={"class": "form-control", "placeholder": "Enter task name"}),
            "task_type": forms.TextInput(
                attrs={"class": "form-control", "placeholder": "e.g., subfinder, nuclei, httpx"}
            ),
            "description": forms.Textarea(
                attrs={"class": "form-control", "rows": 3, "placeholder": "Enter task description"}
            ),
            "is_active": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "yaml_configuration": forms.Textarea(
                attrs={"class": "form-control", "rows": 10, "placeholder": "Enter YAML configuration (optional)"}
            ),
        }

    def clean_yaml_configuration(self):
        """Validate YAML configuration."""
        yaml_config = self.cleaned_data.get("yaml_configuration")

        if yaml_config:
            try:
                yaml.safe_load(yaml_config)
            except yaml.YAMLError as e:
                raise ValidationError(f"Invalid YAML configuration: {e}") from e

        return yaml_config

    def clean(self):
        """Validate task name and type uniqueness."""
        cleaned_data = super().clean()
        name = cleaned_data.get("name")
        task_type = cleaned_data.get("task_type")

        if name and task_type:
            # Check for duplicates (excluding current instance)
            queryset = SecatorTask.objects.filter(name=name, task_type=task_type)
            if self.instance.pk:
                queryset = queryset.exclude(pk=self.instance.pk)

            if queryset.exists():
                raise ValidationError("A task with this name and type already exists.")

        return cleaned_data


class SecatorScanForm(forms.ModelForm):
    """Form for creating/editing Secator scan configurations."""

    class Meta:
        model = SecatorScan
        fields = [
            "name",
            "description",
            "scan_type",
            "scan_config_type",
            "yaml_configuration",
            "is_default",
            "is_active",
        ]
        widgets = {
            "name": forms.TextInput(attrs={"class": "form-control", "placeholder": "Enter scan configuration name"}),
            "description": forms.Textarea(
                attrs={"class": "form-control", "rows": 3, "placeholder": "Enter scan description"}
            ),
            "scan_type": forms.Select(attrs={"class": "form-control"}),
            "scan_config_type": forms.Select(attrs={"class": "form-control"}),
            "yaml_configuration": AceWidget(
                mode="yaml",
                theme="tomorrow_night_eighties",
                width="100%",
                height="450px",
                tabsize=2,
                fontsize="17px",
                showinvisibles=True,
                attrs={"id": "scan-yaml-editor"},
            ),
            "is_default": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "is_active": forms.CheckboxInput(attrs={"class": "form-check-input"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields[
            "yaml_configuration"
        ].help_text = "Define the scan structure. See <a href='https://docs.freelabz.com/for-developers/writing-scans-wip' target='_blank'>Secator documentation</a>"

    def clean_yaml_configuration(self):
        """Validate YAML configuration."""
        yaml_config = self.cleaned_data.get("yaml_configuration")

        if not yaml_config:
            return yaml_config

        try:
            self._validate_scan_yaml_structure(yaml_config)
        except yaml.YAMLError as e:
            raise ValidationError(f"Invalid YAML syntax: {e}") from e

        return yaml_config

    def _validate_scan_yaml_structure(self, yaml_config):
        """Validate required top-level fields and type of a Secator scan YAML config."""
        import yaml

        parsed_yaml = yaml.safe_load(yaml_config)

        if not isinstance(parsed_yaml, dict):
            raise ValidationError("YAML configuration must be a dictionary.")

        # Required top-level fields
        required_fields = ["name", "description", "type"]
        if missing_fields := [field for field in required_fields if field not in parsed_yaml]:
            raise ValidationError(f"Missing required fields in YAML: {', '.join(missing_fields)}")

        # Validate type field
        valid_types = ["scan"]
        scan_type = parsed_yaml.get("type")
        if not isinstance(scan_type, str) or scan_type not in valid_types:
            raise ValidationError(f"Field 'type' must be one of: {', '.join(valid_types)}")

    def clean(self):
        """Validate scan configuration."""
        cleaned_data = super().clean()

        # Check if this is an update operation on a built-in scan configuration
        if self.instance.pk and self.instance.scan_config_type == "builtin":
            raise ValidationError("Built-in scan configurations cannot be modified.")

        return cleaned_data


class SecatorProfileForm(forms.ModelForm):
    """Form for creating/editing Secator profiles."""

    class Meta:
        model = SecatorProfile
        fields = ["name", "category", "description", "enforce", "opts", "is_default", "is_active"]

    name = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={"class": "form-control form-control-lg", "id": "profile_name", "placeholder": "Profile Name"}
        ),
    )
    category = forms.ChoiceField(
        choices=SecatorProfile.CATEGORY_CHOICES,
        required=True,
        widget=forms.Select(attrs={"class": "form-control form-control-lg", "id": "profile_category"}),
        help_text="Select the category of the profile",
    )
    description = forms.CharField(
        required=True,
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "id": "profile_description",
                "rows": 3,
                "placeholder": "Enter profile description",
            }
        ),
    )
    enforce = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "form-check-input", "id": "profile_enforce"}),
        help_text="Whether this profile should enforce its options (handled by Secator)",
    )
    opts = forms.CharField(
        required=True,
        widget=AceWidget(
            mode="yaml",
            theme="tomorrow_night_eighties",
            width="100%",
            height="450px",
            tabsize=2,
            fontsize="17px",
            showinvisibles=True,
            attrs={"id": "profile_opts_editor"},
        ),
        help_text="YAML configuration options for the profile",
    )
    is_default = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "form-check-input", "id": "profile_is_default"}),
        initial=False,
    )
    is_active = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "form-check-input", "id": "profile_is_active"}),
        initial=True,
    )

    def clean_opts(self):
        """Validate YAML syntax for opts field."""
        opts = self.cleaned_data.get("opts")
        if not opts:
            raise ValidationError("opts field is required")

        try:
            yaml.safe_load(opts)
        except yaml.YAMLError as e:
            raise ValidationError(f"Invalid YAML syntax: {e}") from e

        return opts

    def clean(self):
        """Validate profile configuration."""
        cleaned_data = super().clean()

        # Check if this is an update operation on a built-in profile
        if self.instance.pk and self.instance.profile_type == "builtin":
            raise ValidationError("Built-in profiles cannot be modified.")

        return cleaned_data


class SecatorWorkerForm(forms.ModelForm):
    """Form for creating/editing Secator workers (SSH deployment)."""

    class Meta:
        model = SecatorWorker
        fields = [
            "name",
            "ssh_host",
            "ssh_port",
            "ssh_user",
            "ssh_auth_type",
            "ssh_password_encrypted",
            "deploy_path",
            "container_name",
            "api_access_type",
            "api_tunnel_port",
            "api_url",
            "https_pull_agent",
            "https_pull_verify_ssl",
            "is_active",
        ]

    name = forms.CharField(
        required=True,
        max_length=255,
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "Worker name (e.g. worker-1)"}),
    )
    ssh_host = forms.CharField(
        required=False,
        max_length=255,
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "Hostname or IP"}),
    )
    ssh_port = forms.IntegerField(
        required=True,
        min_value=1,
        max_value=65535,
        initial=22,
        widget=forms.NumberInput(attrs={"class": "form-control"}),
    )
    ssh_user = forms.CharField(
        required=False,
        max_length=255,
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "SSH user"}),
    )
    ssh_auth_type = forms.ChoiceField(
        choices=SecatorWorker.SSH_AUTH_CHOICES,
        required=True,
        widget=forms.Select(attrs={"class": "form-control"}),
    )
    ssh_password_encrypted = forms.CharField(
        required=False,
        widget=forms.PasswordInput(
            attrs={"class": "form-control", "placeholder": "Password", "autocomplete": "new-password"}
        ),
    )
    deploy_path = forms.CharField(
        required=True,
        max_length=1024,
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "/opt/secator-worker"}),
    )
    container_name = forms.CharField(
        required=False,
        max_length=255,
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "secator-worker (optional)"}),
    )
    api_access_type = forms.ChoiceField(
        choices=SecatorWorker.API_ACCESS_CHOICES,
        required=True,
        widget=forms.Select(attrs={"class": "form-control"}),
    )
    api_tunnel_port = forms.IntegerField(
        required=False,
        min_value=1,
        max_value=65535,
        initial=8443,
        widget=forms.NumberInput(attrs={"class": "form-control", "placeholder": "8443"}),
    )
    api_url = forms.CharField(
        required=False,
        max_length=512,
        widget=forms.URLInput(
            attrs={
                "class": "form-control",
                "placeholder": "https://rengine.example.com",
            }
        ),
    )
    https_pull_agent = forms.BooleanField(
        required=False,
        initial=False,
        widget=forms.CheckboxInput(attrs={"class": "form-check-input", "id": "id_https_pull_agent"}),
    )
    https_pull_verify_ssl = forms.BooleanField(
        required=False,
        initial=True,
        label="Verify reNgine-ng TLS certificate (pull agent)",
        help_text="Uncheck if reNgine-ng HTTPS uses a self-signed certificate.",
        widget=forms.CheckboxInput(attrs={"class": "form-check-input", "id": "id_https_pull_verify_ssl"}),
    )
    regenerate_pull_token = forms.BooleanField(
        required=False,
        initial=False,
        label="Regenerate pull token",
        help_text="Invalidates the previous token; update the worker .env and restart the container.",
        widget=forms.CheckboxInput(attrs={"class": "form-check-input"}),
    )
    is_active = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={"class": "form-check-input"}),
    )

    def _is_pull_classic(self, api_access: str | None, https_pull_agent: object) -> bool:
        return SecatorWorker.uses_https_pull_agent_from(api_access or "", bool(https_pull_agent))

    def _apply_pull_classic_ssh_defaults(self, cleaned_data: dict[str, object], pull_classic: bool) -> None:
        """In pull-classic mode, SSH fields are irrelevant for execution (pull agent)."""
        if not pull_classic:
            return
        cleaned_data["ssh_auth_type"] = SecatorWorker.AUTH_KEY
        instance = self.instance if self.instance and self.instance.pk else None

        if submitted_host := (cleaned_data.get("ssh_host") or "").strip():
            cleaned_data["ssh_host"] = submitted_host
        elif instance and (instance.ssh_host or "").strip():
            # Preserve existing SSH metadata for operators.
            cleaned_data["ssh_host"] = instance.ssh_host
        else:
            cleaned_data["ssh_host"] = "not-used-pull-agent"

        if submitted_user := (cleaned_data.get("ssh_user") or "").strip():
            cleaned_data["ssh_user"] = submitted_user
        elif instance and (instance.ssh_user or "").strip():
            cleaned_data["ssh_user"] = instance.ssh_user
        else:
            cleaned_data["ssh_user"] = "not-used-pull-agent"

    def _require_ssh_fields_for_non_pull_api(self, cleaned_data: dict[str, object], api_access: str | None) -> None:
        if api_access not in (SecatorWorker.API_ACCESS_CLASSIC, SecatorWorker.API_ACCESS_TUNNEL):
            return

        if not (cleaned_data.get("ssh_host") or "").strip():
            self.add_error("ssh_host", "This field is required.")
        if not (cleaned_data.get("ssh_user") or "").strip():
            self.add_error("ssh_user", "This field is required.")

        ssh_port = cleaned_data.get("ssh_port")
        if ssh_port in (None, ""):
            # Ensure deterministic SSH behavior when the form does not require ssh_port
            # (or when a client submits an empty value).
            cleaned_data["ssh_port"] = 22
            return

        try:
            ssh_port_int = int(ssh_port)  # `ssh_port` is expected to be numeric.
        except (TypeError, ValueError):
            self.add_error("ssh_port", "Enter a valid port number.")
            return

        if not (1 <= ssh_port_int <= 65535):
            self.add_error("ssh_port", "Enter a valid port number.")
            return

        cleaned_data["ssh_port"] = ssh_port_int

    def _validate_password_auth(
        self,
        cleaned_data: dict[str, object],
        pull_classic: bool,
        auth_type: str | None,
    ) -> None:
        if (
            auth_type == SecatorWorker.AUTH_PASSWORD
            and not pull_classic
            and not cleaned_data.get("ssh_password_encrypted")
            and (not self.instance or not self.instance.ssh_password_encrypted)
        ):
            raise ValidationError("Password is required when using password authentication.")

    def _validate_api_access_fields(
        self,
        cleaned_data: dict[str, object],
        api_access: str | None,
        auth_type: str | None,
    ) -> None:
        if api_access == SecatorWorker.API_ACCESS_CLASSIC:
            api_url = (cleaned_data.get("api_url") or "").strip()
            if not api_url:
                raise ValidationError({"api_url": "API URL is required when using classic (HTTPS) access."})
        if api_access == SecatorWorker.API_ACCESS_TUNNEL:
            port = cleaned_data.get("api_tunnel_port")
            if port is None:
                raise ValidationError({"api_tunnel_port": "API tunnel port is required when using tunnel access."})
            if port < 1 or port > 65535:
                raise ValidationError({"api_tunnel_port": "Port must be between 1 and 65535."})
            if auth_type == SecatorWorker.AUTH_PASSWORD:
                raise ValidationError(
                    {"ssh_auth_type": "Password authentication is not supported when using API tunnel access."}
                )

    def _validate_https_pull_agent_flag(self, cleaned_data: dict[str, object], pull_classic: bool) -> None:
        if cleaned_data.get("https_pull_agent") and not pull_classic:
            raise ValidationError(
                {
                    "https_pull_agent": "Pull agent is only available with HTTPS (classic) API access.",
                }
            )

    def _apply_https_pull_verify_ssl_default(self, cleaned_data: dict[str, object], pull_classic: bool) -> None:
        # Preserve the posted preference even when pull-agent is disabled.
        # At runtime, we only use this preference when pull-agent is actually enabled.
        return

    def clean(self):
        cleaned_data = super().clean()
        api_access = cleaned_data.get("api_access_type")
        # Pull-classic mode: we normalize SSH fields for form consistency and we
        # skip SSH-required validation because execution is handled via pull-agent.
        pull_classic = self._is_pull_classic(api_access, cleaned_data.get("https_pull_agent"))
        self._apply_pull_classic_ssh_defaults(cleaned_data, pull_classic=pull_classic)
        self._require_ssh_fields_for_non_pull_api(cleaned_data, api_access=None if pull_classic else api_access)
        auth_type = cleaned_data.get("ssh_auth_type")
        self._validate_password_auth(cleaned_data, pull_classic=pull_classic, auth_type=auth_type)
        self._validate_api_access_fields(cleaned_data, api_access=api_access, auth_type=auth_type)
        self._validate_https_pull_agent_flag(cleaned_data, pull_classic=pull_classic)
        self._apply_https_pull_verify_ssl_default(cleaned_data, pull_classic=pull_classic)
        return cleaned_data

    def save(self, commit=True):
        regen = self.cleaned_data.get("regenerate_pull_token")
        instance = super().save(commit=False)
        if self.cleaned_data.get("ssh_auth_type") == SecatorWorker.AUTH_KEY:
            instance.ssh_key_path = ""
        if commit:
            instance.save()
            if regen and instance.pk:
                instance.regenerate_pull_token()
        return instance
