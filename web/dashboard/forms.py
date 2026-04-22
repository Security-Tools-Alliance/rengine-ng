from django import forms
from django.contrib.auth.models import User

from .models import (
    DATATABLES_DISPLAY_CLASSIC,
    DATATABLES_DISPLAY_SCROLLER,
    DATATABLES_PAGE_LENGTH_CHOICES,
    DATATABLES_PAGE_LENGTH_DEFAULT,
    Project,
)


class ProjectForm(forms.ModelForm):
    users = forms.ModelMultipleChoiceField(
        queryset=User.objects.all(), widget=forms.CheckboxSelectMultiple, required=False
    )
    description = forms.CharField(widget=forms.Textarea(attrs={"rows": 4}), required=False)

    class Meta:
        model = Project
        fields = ["name", "description", "users"]


DATATABLES_DISPLAY_CHOICES = [
    (DATATABLES_DISPLAY_CLASSIC, "Classic pagination (with page info and action buttons)"),
    (DATATABLES_DISPLAY_SCROLLER, "Scroller (virtual scroll, no page info)"),
]

DATATABLES_PAGE_LENGTH_FORM_CHOICES = [(v, str(v)) for v in DATATABLES_PAGE_LENGTH_CHOICES]


class InterfaceSettingsForm(forms.Form):
    """Form for interface preferences (DataTables display mode and default page length)."""

    datatables_display = forms.ChoiceField(
        choices=DATATABLES_DISPLAY_CHOICES,
        widget=forms.RadioSelect,
        initial=DATATABLES_DISPLAY_CLASSIC,
        label="DataTables display",
    )
    datatables_page_length = forms.TypedChoiceField(
        choices=DATATABLES_PAGE_LENGTH_FORM_CHOICES,
        coerce=int,
        initial=DATATABLES_PAGE_LENGTH_DEFAULT,
        label="Default rows per page",
        help_text="Default number of rows shown in tables (subdomains, endpoints, vulnerabilities, etc.).",
    )
