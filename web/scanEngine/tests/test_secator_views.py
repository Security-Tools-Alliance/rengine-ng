"""
test_secator_views.py

This file contains unit tests for the Secator views and forms.
"""

from unittest.mock import patch

from django.urls import reverse
import yaml

from scanEngine.forms import SecatorProfileForm, SecatorScanForm, SecatorWorkflowForm
from scanEngine.models import SecatorProfile, SecatorScan, SecatorTask, SecatorWorkflow
from utils.test_base import BaseTestCase


class TestSecatorViews(BaseTestCase):
    """Test class for Secator views."""

    def setUp(self):
        """Set up test data."""
        super().setUp()

        # Create test workflow
        self.workflow = SecatorWorkflow.objects.create(
            name="Test Workflow",
            alias="test_workflow",
            description="A test workflow",
            tags=["recon", "dns"],
            scan_type="internet",
            workflow_type="builtin",
            yaml_configuration="""
type: workflow
name: test_workflow
description: A test workflow
tasks:
  subfinder:
    description: Find subdomains
""",
            is_active=True,
        )

        # Create test task
        self.task = SecatorTask.objects.create(
            name="Test Task",
            task_type="subfinder",
            tags=["dns", "recon"],
            description="A test task",
            is_builtin=True,
            is_active=True,
        )

        # Create test scan
        self.scan = SecatorScan.objects.create(
            name="Test Scan",
            description="A test scan",
            scan_type="internet",
            scan_config_type="builtin",
            yaml_configuration="""
type: scan
name: domain
description: A test scan
workflows:
  test_workflow:
    description: Test workflow
input_types:
  - domain
""",
            is_default=True,
            is_active=True,
        )

    def test_secator_workflows_view(self):
        """Test the secator workflows list view."""
        response = self.client.get(reverse("workflows"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Test Workflow")

    def test_secator_workflow_detail_view(self):
        """Test the secator workflow detail view."""
        response = self.client.get(reverse("workflow_detail", args=[self.workflow.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Test Workflow")
        self.assertContains(response, "test_workflow")
        self.assertContains(response, "recon")
        self.assertContains(response, "dns")

    def test_secator_workflows_table_partial(self):
        """Test the workflows table partial view (dynamic search/filter)."""
        response = self.client.get(reverse("workflows_table_partial"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Test Workflow")
        response_filter = self.client.get(reverse("workflows_table_partial") + "?filter=builtin&search=Test")
        self.assertEqual(response_filter.status_code, 200)
        self.assertContains(response_filter, "Test Workflow")

    def test_secator_tasks_view(self):
        """Test the secator tasks list view."""
        response = self.client.get(reverse("tasks"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Test Task")

    def test_secator_task_detail_view(self):
        """Test the secator task detail view."""
        response = self.client.get(reverse("task_detail", args=[self.task.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Test Task")

    def test_secator_scans_view(self):
        """Test the secator scans list view."""
        response = self.client.get(reverse("scans"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Test Scan")

    def test_secator_scan_detail_view(self):
        """Test the secator scan detail view."""
        response = self.client.get(reverse("scan_detail", args=[self.scan.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Test Scan")
        self.assertContains(response, "domain")

    def test_secator_scans_filter_builtin(self):
        """Test filtering scans by builtin type."""
        response = self.client.get(reverse("scans") + "?filter=builtin")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Test Scan")

    def test_secator_scans_filter_custom(self):
        """Test filtering scans by custom type."""
        # Create a custom scan
        SecatorScan.objects.create(
            name="Custom Scan",
            description="A custom scan",
            scan_type="internet",
            scan_config_type="custom",
            yaml_configuration="type: scan\nname: custom",
            is_default=False,
            is_active=True,
        )

        response = self.client.get(reverse("scans") + "?filter=custom")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Custom Scan")

    def test_secator_scans_search(self):
        """Test searching scans."""
        response = self.client.get(reverse("scans") + "?search=Test")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Test Scan")

    def test_add_scan_view(self):
        """Test the add scan view."""
        response = self.client.get(reverse("add_scan"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Add Scan")

    def test_add_workflow_view(self):
        """Test the add workflow view."""
        response = self.client.get(reverse("add_workflow"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Add Workflow")

    def test_update_scan_builtin_blocked(self):
        """Test that updating built-in scans is blocked."""
        response = self.client.get(reverse("update_scan", args=[self.scan.id]))
        self.assertEqual(response.status_code, 302)  # Redirected

    def test_update_scan_custom_allowed(self):
        """Test that updating custom scans is allowed."""
        # Create a custom scan
        custom_scan = SecatorScan.objects.create(
            name="Custom Scan",
            description="A custom scan",
            scan_type="internet",
            scan_config_type="custom",
            yaml_configuration="type: scan\nname: custom",
            is_default=False,
            is_active=True,
        )

        response = self.client.get(reverse("update_scan", args=[custom_scan.id]))
        self.assertEqual(response.status_code, 200)

    def test_delete_scan_builtin_blocked(self):
        """Test that deleting built-in scans is blocked."""
        response = self.client.post(reverse("delete_scan", args=[self.scan.id]))
        self.assertEqual(response.status_code, 200)
        # Should return JSON with error
        import json

        data = json.loads(response.content)
        self.assertFalse(data["status"])
        self.assertIn("cannot be deleted", data["message"])

    def test_delete_scan_custom_allowed(self):
        """Test that deleting custom scans is allowed."""
        # Create a custom scan
        custom_scan = SecatorScan.objects.create(
            name="Custom Scan",
            description="A custom scan",
            scan_type="internet",
            scan_config_type="custom",
            yaml_configuration="type: scan\nname: custom",
            is_default=False,
            is_active=True,
        )

        response = self.client.post(reverse("delete_scan", args=[custom_scan.id]))
        self.assertEqual(response.status_code, 200)
        # Should return JSON with success
        import json

        data = json.loads(response.content)
        self.assertTrue(data["status"])

    def test_workflow_detail_related_scans(self):
        """Test that workflow detail shows related scans."""
        response = self.client.get(reverse("workflow_detail", args=[self.workflow.id]))
        self.assertEqual(response.status_code, 200)
        # Should show the scan that uses this workflow
        self.assertContains(response, "Test Scan")

    def test_duplicate_workflow_creates_custom_copy(self):
        """Duplicating a workflow creates a custom workflow copy."""
        response = self.client.get(reverse("duplicate_workflow", args=[self.workflow.id]))
        self.assertEqual(response.status_code, 302)
        duplicated = SecatorWorkflow.objects.get(name="Test Workflow copy")
        self.assertEqual(duplicated.workflow_type, "custom")
        self.assertEqual(duplicated.yaml_configuration, self.workflow.yaml_configuration)

    def test_duplicate_task_creates_custom_copy(self):
        """Duplicating a task creates a custom task copy."""
        response = self.client.get(reverse("duplicate_task", args=[self.task.id]))
        self.assertEqual(response.status_code, 302)
        duplicated = SecatorTask.objects.get(name="Test Task copy")
        self.assertFalse(duplicated.is_builtin)
        self.assertEqual(duplicated.task_type, self.task.task_type)

    def test_duplicate_scan_creates_custom_non_default_copy(self):
        """Duplicating a scan creates a custom non-default scan copy."""
        response = self.client.get(reverse("duplicate_scan", args=[self.scan.id]))
        self.assertEqual(response.status_code, 302)
        duplicated = SecatorScan.objects.get(name="Test Scan copy")
        self.assertEqual(duplicated.scan_config_type, "custom")
        self.assertFalse(duplicated.is_default)
        self.assertEqual(duplicated.yaml_configuration, self.scan.yaml_configuration)

    def test_duplicate_scan_collision_uses_incremented_suffix(self):
        """Duplicating with existing copy name appends an incremented suffix."""
        SecatorScan.objects.create(
            name="Test Scan copy",
            description="Existing duplicate name",
            scan_type="internet",
            scan_config_type="custom",
            yaml_configuration="type: scan\nname: existing-copy",
            is_default=False,
            is_active=True,
        )
        response = self.client.get(reverse("duplicate_scan", args=[self.scan.id]))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(SecatorScan.objects.filter(name="Test Scan copy 2").exists())


class TestSecatorForms(BaseTestCase):
    """Test class for Secator forms."""

    def setUp(self):
        """Set up test data."""
        super().setUp()

    def test_secator_scan_form_valid(self):
        """Test SecatorScanForm with valid data."""
        form_data = {
            "name": "Test Scan",
            "alias": "domain",
            "description": "A test scan",
            "scan_type": "internet",
            "scan_config_type": "custom",
            "yaml_configuration": """
type: scan
name: domain
description: A test scan
workflows:
  subdomain_recon:
    description: Find subdomains
input_types:
  - domain
""",
            "is_default": False,
            "is_active": True,
        }

        form = SecatorScanForm(data=form_data)
        self.assertTrue(form.is_valid())
        scan = form.save()
        parsed_yaml = yaml.safe_load(scan.yaml_configuration)
        self.assertEqual(parsed_yaml.get("name"), "Test Scan")

    def test_secator_scan_form_invalid_yaml(self):
        """Test SecatorScanForm with invalid YAML."""
        form_data = {
            "name": "Test Scan",
            "alias": "domain",
            "description": "A test scan",
            "scan_type": "internet",
            "scan_config_type": "custom",
            "yaml_configuration": "invalid: yaml: content: [",
            "is_default": False,
            "is_active": True,
        }

        form = SecatorScanForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("yaml_configuration", form.errors)

    def test_secator_scan_form_missing_required_fields(self):
        """Test SecatorScanForm with missing required fields."""
        form_data = {
            "name": "Test Scan",
            "yaml_configuration": """
type: scan
name: domain
# Missing description and workflows
""",
        }

        form = SecatorScanForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("yaml_configuration", form.errors)

    def test_secator_workflow_form_valid(self):
        """Test SecatorWorkflowForm with valid data."""
        form_data = {
            "name": "test_workflow",
            "display_name": "Test Workflow",
            "alias": "subdomain_recon",
            "description": "A test workflow",
            "scan_type": "internet",
            "yaml_configuration": """
type: workflow
name: test_workflow
description: A test workflow
tags: []
tasks:
  subfinder:
    description: Find subdomains
""",
            "is_active": True,
        }

        form = SecatorWorkflowForm(data=form_data)
        self.assertTrue(form.is_valid(), msg=form.errors)
        workflow = form.save()
        self.assertEqual(workflow.alias, "testworkflow")
        parsed_yaml = yaml.safe_load(workflow.yaml_configuration)
        self.assertEqual(parsed_yaml.get("name"), "test_workflow")

    def test_secator_workflow_form_name_without_spaces(self):
        """Workflow name cannot contain spaces."""
        form_data = {
            "name": "workflow with spaces",
            "display_name": "Workflow With Spaces",
            "alias": "subdomain_recon",
            "description": "A test workflow",
            "scan_type": "internet",
            "yaml_configuration": """
type: workflow
name: workflow_with_spaces
description: A test workflow
tags: []
tasks:
  subfinder:
    description: Find subdomains
""",
            "is_active": True,
        }
        form = SecatorWorkflowForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("name", form.errors)

    def test_secator_workflow_form_invalid_yaml(self):
        """Test SecatorWorkflowForm with invalid YAML."""
        form_data = {
            "name": "test_workflow_invalid_yaml",
            "alias": "test_workflow",
            "description": "A test workflow",
            "scan_type": "internet",
            "yaml_configuration": "invalid: yaml: content: [",
            "is_active": True,
        }

        form = SecatorWorkflowForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("yaml_configuration", form.errors)

    def test_secator_scan_form_builtin_modification_blocked(self):
        """Test that built-in scan modification is blocked in form."""
        # Create a built-in scan
        scan = SecatorScan.objects.create(
            name="Built-in Scan",
            description="A built-in scan",
            scan_type="internet",
            scan_config_type="builtin",
            yaml_configuration="type: scan\nname: domain",
            is_default=True,
            is_active=True,
        )

        form_data = {
            "name": "Modified Scan",
            "description": "Modified description",
            "scan_type": "internet",
            "scan_config_type": "builtin",
            "yaml_configuration": "type: scan\nname: domain",
            "is_default": True,
            "is_active": True,
        }

        form = SecatorScanForm(data=form_data, instance=scan)
        self.assertFalse(form.is_valid())
        self.assertIn("__all__", form.errors)


class TestSecatorProfileViews(BaseTestCase):
    """Test class for Secator profile views."""

    def setUp(self):
        """Set up test data."""
        super().setUp()

        # Create test builtin profile
        self.builtin_profile = SecatorProfile.objects.create(
            name="test_builtin",
            category="speed",
            description="A test builtin profile",
            enforce=False,
            opts=yaml.dump({"rate_limit": 100}),
            profile_type="builtin",
            is_active=True,
        )

        # Create test custom profile
        self.custom_profile = SecatorProfile.objects.create(
            name="test_custom",
            category="evasion",
            description="A test custom profile",
            enforce=True,
            opts=yaml.dump({"tcp_syn_stealth": True}),
            profile_type="custom",
            is_active=True,
        )

    def test_secator_profiles_view(self):
        """Test the secator profiles list view."""
        response = self.client.get(reverse("profiles"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "test_builtin")
        self.assertContains(response, "test_custom")

    def test_secator_profile_detail_view(self):
        """Test the secator profile detail view."""
        response = self.client.get(reverse("profile_detail", args=[self.custom_profile.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "test_custom")

    def test_add_profile_view_get(self):
        """Test the add profile view GET request."""
        response = self.client.get(reverse("add_profile"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Add Profile")

    def test_add_profile_view_post(self):
        """Test the add profile view POST request."""
        form_data = {
            "name": "new_profile",
            "category": "general",
            "description": "A new profile",
            "enforce": False,
            "opts": yaml.dump({"timeout": 300}),
            "is_active": True,
        }
        response = self.client.post(reverse("add_profile"), data=form_data)
        self.assertEqual(response.status_code, 302)  # Redirect after success
        self.assertTrue(SecatorProfile.objects.filter(name="new_profile", profile_type="custom").exists())

    def test_update_profile_view_get(self):
        """Test the update profile view GET request."""
        response = self.client.get(reverse("update_profile", args=[self.custom_profile.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Update Profile")

    def test_update_profile_view_post(self):
        """Test the update profile view POST request."""
        form_data = {
            "name": "test_custom",
            "category": "evasion",
            "description": "Updated description",
            "enforce": True,
            "opts": yaml.dump({"tcp_syn_stealth": True, "nmap_light_tcp_syn_stealth": True}),
            "is_active": True,
        }
        response = self.client.post(reverse("update_profile", args=[self.custom_profile.id]), data=form_data)
        self.assertEqual(response.status_code, 302)  # Redirect after success
        self.custom_profile.refresh_from_db()
        self.assertEqual(self.custom_profile.description, "Updated description")

    def test_cannot_update_builtin_profile(self):
        """Test that built-in profiles cannot be updated."""
        response = self.client.get(reverse("update_profile", args=[self.builtin_profile.id]))
        self.assertEqual(response.status_code, 302)  # Redirect with error message

    def test_delete_profile_view(self):
        """Test the delete profile view."""
        profile_id = self.custom_profile.id
        response = self.client.post(reverse("delete_profile", args=[profile_id]))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(SecatorProfile.objects.filter(id=profile_id).exists())

    def test_cannot_delete_builtin_profile(self):
        """Test that built-in profiles cannot be deleted."""
        response = self.client.post(reverse("delete_profile", args=[self.builtin_profile.id]))
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertFalse(response_data.get("status"))
        self.assertIn("cannot be deleted", response_data.get("message", ""))

    def test_duplicate_profile_creates_custom_non_default_copy(self):
        """Duplicating a profile creates a custom non-default profile copy."""
        response = self.client.get(reverse("duplicate_profile", args=[self.builtin_profile.id]))
        self.assertEqual(response.status_code, 302)
        duplicated = SecatorProfile.objects.get(name="test_builtin copy")
        self.assertEqual(duplicated.profile_type, "custom")
        self.assertFalse(duplicated.is_default)
        self.assertEqual(duplicated.category, self.builtin_profile.category)

    def test_duplicate_profile_with_project_slug_in_request_does_not_error(self):
        """Duplicating a profile works when a project slug is injected by request context."""
        with patch("scanEngine.views._project_slug_from_request", return_value="demo-project"):
            response = self.client.get(reverse("duplicate_profile", args=[self.builtin_profile.id]))
        self.assertEqual(response.status_code, 302)

    def test_secator_profile_form_validation(self):
        """Test SecatorProfileForm validation."""
        form_data = {
            "name": "test_form",
            "category": "speed",
            "description": "Test form profile",
            "enforce": False,
            "opts": yaml.dump({"rate_limit": 100}),
            "is_active": True,
        }
        form = SecatorProfileForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_secator_profile_form_invalid_yaml(self):
        """Test SecatorProfileForm with invalid YAML."""
        form_data = {
            "name": "test_form",
            "category": "speed",
            "description": "Test form profile",
            "enforce": False,
            "opts": "invalid: yaml: [",
            "is_active": True,
        }
        form = SecatorProfileForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("opts", form.errors)

    def test_secator_profile_form_with_is_default(self):
        """Test SecatorProfileForm with is_default field."""
        form_data = {
            "name": "test_form_default",
            "category": "speed",
            "description": "Test form profile with default",
            "enforce": False,
            "opts": yaml.dump({"rate_limit": 100}),
            "is_active": True,
            "is_default": True,
        }
        form = SecatorProfileForm(data=form_data)
        self.assertTrue(form.is_valid())
        profile = form.save()
        self.assertTrue(profile.is_default)

    def test_secator_profile_form_default_unsets_other_defaults(self):
        """Test that setting a profile as default unsets other defaults in the same category (model behavior)."""
        import uuid

        unique_suffix = str(uuid.uuid4())[:8]
        # Create first profile as default
        profile1 = SecatorProfile.objects.create(
            name=f"profile1_unsets_{unique_suffix}",
            category="speed",
            description="First profile",
            enforce=False,
            opts=yaml.dump({"rate_limit": 100}),
            profile_type="custom",
            is_active=True,
            is_default=True,
        )

        # Create second profile with is_default=True via model (form validation would fail due to
        # unique_default_per_category constraint checked before save)
        profile2 = SecatorProfile.objects.create(
            name=f"profile2_unsets_{unique_suffix}",
            category="speed",
            description="Second profile",
            enforce=False,
            opts=yaml.dump({"rate_limit": 150}),
            profile_type="custom",
            is_active=True,
            is_default=True,
        )

        # Model save() unsets other defaults in the same category
        profile1.refresh_from_db()
        self.assertFalse(profile1.is_default)
        self.assertTrue(profile2.is_default)
