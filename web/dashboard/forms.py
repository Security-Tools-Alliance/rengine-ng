from django import forms
from django.contrib.auth.models import User

from .models import Project


class ProjectForm(forms.ModelForm):
    users = forms.ModelMultipleChoiceField(
        queryset=User.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=False
    )
    description = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 4}),
        required=False
    )

    class Meta:
        model = Project
        fields = ['name', 'description', 'users']