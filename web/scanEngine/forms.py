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
        required=True,
        widget=forms.TextInput(
            attrs={
                "class": "form-control form-control-lg",
                "id": "name",
                "placeholder": "my awesome wordlist",
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

**{company_name}** performed both Security Audit and Reconnaissance using automated tool reNgine. https://github.com/Security-Tools-Alliance/rengine-ng/.

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
                raise ValidationError(f"Invalid YAML configuration: {e}")

            # Schema validation: check for required fields
            if not isinstance(parsed_yaml, dict):
                raise ValidationError("YAML configuration must be a mapping (dictionary) at the top level.")

            # Required top-level fields
            required_fields = ["name", "description", "scan_type", "workflow_type"]
            missing_fields = [field for field in required_fields if field not in parsed_yaml]
            if missing_fields:
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

        # Validate scan_type field
        valid_scan_types = ["internet", "internal"]
        scan_type = parsed_yaml.get("scan_type")
        if not isinstance(scan_type, str) or scan_type not in valid_scan_types:
            raise ValidationError(f"Field 'scan_type' must be one of: {', '.join(valid_scan_types)}")

        # Validate workflow_type field
        valid_workflow_types = ["builtin", "custom"]
        workflow_type = parsed_yaml.get("workflow_type")
        if not isinstance(workflow_type, str) or workflow_type not in valid_workflow_types:
            raise ValidationError(f"Field 'workflow_type' must be one of: {', '.join(valid_workflow_types)}")

    def _validate_tasks_section(self, tasks):
        """Validate the tasks section of the YAML configuration."""
        if not isinstance(tasks, list):
            raise ValidationError("Field 'tasks' must be a list.")

        if not tasks:
            raise ValidationError("Field 'tasks' cannot be empty.")

        for i, task in enumerate(tasks):
            if not isinstance(task, dict):
                raise ValidationError(f"Task at index {i} must be a dictionary.")

            # Required task fields
            required_task_fields = ["name", "type"]
            missing_task_fields = [field for field in required_task_fields if field not in task]
            if missing_task_fields:
                raise ValidationError(f"Task at index {i} missing required field(s): {', '.join(missing_task_fields)}")

            # Validate task field types
            if not isinstance(task.get("name"), str) or not task.get("name").strip():
                raise ValidationError(f"Task at index {i}: field 'name' must be a non-empty string.")

            if not isinstance(task.get("type"), str) or not task.get("type").strip():
                raise ValidationError(f"Task at index {i}: field 'type' must be a non-empty string.")

            # Validate config field if present
            if "config" in task and not isinstance(task["config"], dict):
                raise ValidationError(f"Task at index {i}: field 'config' must be a dictionary.")

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
                raise ValidationError(f"Invalid YAML configuration: {e}")

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
            import yaml

            parsed_yaml = yaml.safe_load(yaml_config)

            if not isinstance(parsed_yaml, dict):
                raise ValidationError("YAML configuration must be a dictionary.")

            # Required top-level fields
            required_fields = ["name", "description", "type"]
            missing_fields = [field for field in required_fields if field not in parsed_yaml]
            if missing_fields:
                raise ValidationError(f"Missing required fields in YAML: {', '.join(missing_fields)}")

            # Validate type field
            valid_types = ["scan"]
            scan_type = parsed_yaml.get("type")
            if not isinstance(scan_type, str) or scan_type not in valid_types:
                raise ValidationError(f"Field 'type' must be one of: {', '.join(valid_types)}")

        except yaml.YAMLError as e:
            raise ValidationError(f"Invalid YAML syntax: {e}")

        return yaml_config

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
            raise ValidationError(f"Invalid YAML syntax: {e}")

        return opts

    def clean(self):
        """Validate profile configuration."""
        cleaned_data = super().clean()

        # Check if this is an update operation on a built-in profile
        if self.instance.pk and self.instance.profile_type == "builtin":
            raise ValidationError("Built-in profiles cannot be modified.")

        return cleaned_data
