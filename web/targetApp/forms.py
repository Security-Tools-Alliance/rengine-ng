from django import forms
from django.contrib.auth.models import User

from dashboard.models import Project
from reNgine.validators import validate_domain
from scanEngine.models import SecatorWorker
from startScan.models import Domain

from .models import Organization, Scope, Target


class AddTargetForm(forms.Form):
    name = forms.CharField(
        validators=[validate_domain],
        required=True,
        widget=forms.TextInput(
            attrs={"class": "form-control form-control-lg", "id": "domainName", "placeholder": "example.com"}
        ),
    )
    description = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control form-control-lg",
                "id": "domainDescription",
                "placeholder": "Target Description",
            }
        ),
    )
    h1_team_handle = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={"class": "form-control form-control-lg ", "id": "h1_team_handle", "placeholder": "team_handle"}
        ),
    )
    organization_name = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control form-control-lg",
                "id": "organizationName",
                "placeholder": "Organization Name",
            }
        ),
    )


class AddOrganizationForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        project = kwargs.pop("project")
        super(AddOrganizationForm, self).__init__(*args, **kwargs)
        self.fields["targets"] = forms.ModelMultipleChoiceField(
            queryset=Target.objects.for_project(project),
            widget=forms.SelectMultiple(
                attrs={
                    "class": "form-control select2-multiple",
                    "data-toggle": "select2",
                    "data-width": "100%",
                    "data-placeholder": "Choose Targets",
                    "id": "targets",
                }
            ),
            required=False,
        )

    class Meta:
        model = Organization
        fields = ["name", "description", "targets"]

    name = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={
                "class": "form-control form-control-lg",
                "id": "organizationName",
                "placeholder": "Organization Name",
            }
        ),
    )

    description = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control form-control-lg",
                "id": "organizationDescription",
            }
        ),
    )


class UpdateTargetForm(forms.ModelForm):
    class Meta:
        model = Domain
        fields = ["name", "description", "h1_team_handle"]

    name = forms.CharField(
        validators=[validate_domain],
        required=True,
        disabled=True,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "domainName",
            }
        ),
    )
    description = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "domainDescription",
            }
        ),
    )

    h1_team_handle = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "h1_team_handle",
            }
        ),
    )

    def set_value(self, domain_value, description_value, h1_team_handle):
        self.initial["name"] = domain_value
        self.initial["description"] = description_value
        self.initial["h1_team_handle"] = h1_team_handle


class UpdateTargetModelForm(forms.ModelForm):
    """ModelForm for Target (value read-only, description and h1_team_handle editable)."""

    class Meta:
        model = Target
        fields = ["value", "description", "h1_team_handle"]

    value = forms.CharField(
        required=True,
        disabled=True,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "targetValue",
            }
        ),
    )
    description = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "targetDescription",
            }
        ),
    )
    h1_team_handle = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "h1_team_handle",
            }
        ),
    )


class UpdateOrganizationForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(UpdateOrganizationForm, self).__init__(*args, **kwargs)
        project = getattr(self.instance, "project", None)
        target_queryset = Target.objects.filter(project=project) if project else Target.objects.none()
        self.fields["targets"] = forms.ModelMultipleChoiceField(
            queryset=target_queryset,
            widget=forms.SelectMultiple(
                attrs={
                    "class": "form-control form-control-lg tagging",
                    "multiple": "multiple",
                    "id": "targets",
                }
            ),
            required=False,
        )

    class Meta:
        model = Organization
        fields = ["name", "description"]

    name = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "organizationName",
            }
        ),
    )

    description = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "organizationDescription",
            }
        ),
    )

    def set_value(self, organization_value, description_value, target_list=None):
        self.initial["name"] = organization_value
        self.initial["description"] = description_value
        if target_list is not None and "targets" in self.fields:
            self.initial["targets"] = [int(t) for t in target_list if str(t).isdigit()]


class ScopeForm(forms.ModelForm):
    """Form for creating and updating a Scope."""

    def __init__(self, *args, **kwargs):
        project_slug = kwargs.pop("project_slug", None)
        super().__init__(*args, **kwargs)

        if project_slug:
            self.fields["organization"].queryset = Organization.objects.for_project(project_slug)
            self.fields["targets"].queryset = Target.objects.for_project(project_slug)
        elif self.instance and self.instance.pk:
            project = self.instance.organization.project
            self.fields["organization"].queryset = Organization.objects.for_project(project)
            self.fields["targets"].queryset = Target.objects.for_project(project)

        self.fields["workers"].queryset = SecatorWorker.objects.active()
        self.fields["workers"].help_text = (
            "Remote workers allowed for scans in this scope. "
            "Use \"Allow Local worker\" to include the reNgine server."
        )
        if self.instance and self.instance.pk:
            base_qs = SecatorWorker.objects.active().filter(scopes=self.instance)
            default_id = getattr(self.instance, "default_worker_id", None)
            if default_id and not base_qs.filter(pk=default_id).exists():
                self.fields["default_worker"].queryset = (
                    base_qs | SecatorWorker.objects.filter(pk=default_id)
                ).distinct().order_by("name")
            else:
                self.fields["default_worker"].queryset = base_qs.order_by("name")
        else:
            self.fields["default_worker"].queryset = SecatorWorker.objects.active()
        self.fields["default_worker"].required = False
        self.fields["default_worker"].empty_label = "Local (this server)"
        self.fields["default_worker"].help_text = (
            "When the scope has 2 or more allowed workers, choose which one is pre-selected by default."
        )

    class Meta:
        model = Scope
        fields = [
            "organization",
            "name",
            "scope_type",
            "start_date",
            "end_date",
            "description",
            "targets",
            "workers",
            "allow_local_worker",
            "default_worker",
        ]
        widgets = {
            "organization": forms.Select(
                attrs={"class": "form-control select2", "data-toggle": "select2", "data-width": "100%"}
            ),
            "name": forms.TextInput(attrs={"class": "form-control", "placeholder": "Scope name"}),
            "scope_type": forms.Select(
                attrs={"class": "form-control select2", "data-toggle": "select2", "data-width": "100%"}
            ),
            "start_date": forms.DateInput(attrs={"class": "form-control", "type": "date"}),
            "end_date": forms.DateInput(attrs={"class": "form-control", "type": "date"}),
            "description": forms.Textarea(attrs={"class": "form-control", "rows": 3}),
            "targets": forms.SelectMultiple(
                attrs={
                    "class": "form-control select2-multiple",
                    "data-toggle": "select2",
                    "data-width": "100%",
                    "data-placeholder": "Choose Targets",
                }
            ),
            "workers": forms.SelectMultiple(
                attrs={
                    "class": "form-control select2-multiple",
                    "data-toggle": "select2",
                    "data-width": "100%",
                    "data-placeholder": "Choose remote workers",
                }
            ),
            "allow_local_worker": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "default_worker": forms.Select(
                attrs={
                    "class": "form-control select2",
                    "data-toggle": "select2",
                    "data-width": "100%",
                    "data-placeholder": "Local (default)",
                }
            ),
        }

    def clean(self):
        cleaned = super().clean()
        start = cleaned.get("start_date")
        end = cleaned.get("end_date")
        if start and end and start > end:
            raise forms.ValidationError("Start date must be before end date.")
        allow_local = cleaned.get("allow_local_worker", True)
        workers = list(cleaned.get("workers") or [])
        default_worker = cleaned.get("default_worker")
        allowed_count = (1 if allow_local else 0) + len(workers)
        if allowed_count >= 2 and default_worker is not None:
            if default_worker not in workers:
                self.add_error(
                    "default_worker",
                    "Default worker must be one of the allowed workers for this scope.",
                )
        return cleaned


class ProjectForm(forms.ModelForm):
    users = forms.ModelMultipleChoiceField(
        queryset=User.objects.all(), widget=forms.CheckboxSelectMultiple, required=False
    )
    description = forms.CharField(widget=forms.Textarea(attrs={"rows": 4}), required=False)

    class Meta:
        model = Project
        fields = ["name", "description", "users"]
