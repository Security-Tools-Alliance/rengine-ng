from django import forms
from django.contrib.auth.models import User

from dashboard.models import Project
from reNgine.validators import validate_domain
from startScan.models import Domain

from .models import Organization, Target


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
            queryset=Target.objects.filter(project__slug=project),
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


class ProjectForm(forms.ModelForm):
    users = forms.ModelMultipleChoiceField(
        queryset=User.objects.all(), widget=forms.CheckboxSelectMultiple, required=False
    )
    description = forms.CharField(widget=forms.Textarea(attrs={"rows": 4}), required=False)

    class Meta:
        model = Project
        fields = ["name", "description", "users"]
