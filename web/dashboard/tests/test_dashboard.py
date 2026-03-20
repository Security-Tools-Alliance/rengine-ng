"""
This file contains the test cases for the dashboard views.
"""

import json
from unittest.mock import MagicMock, patch
import uuid

from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.test import RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone
from rolepermissions.checkers import has_role
from rolepermissions.roles import assign_role

from dashboard.adapters import AccountAdapter
from dashboard.models import Project
from utils.test_base import BaseTestCase


class TestDashboardViews(BaseTestCase):
    """Test cases for dashboard views."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()

    def test_index_view(self):
        """Test the index view of the dashboard."""
        response = self.client.get(reverse("dashboardIndex", kwargs={"slug": self.data_generator.project.slug}))
        self.assertEqual(response.status_code, 200)
        self.assertIn("dashboard_data_active", response.context)
        dashboard_data = response.context["dashboard_data_active"]
        self.assertIsInstance(dashboard_data, str)
        self.assertIn("active", dashboard_data)

    def test_profile_view(self):
        """Test the profile view."""
        response = self.client.get(reverse("profile"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "dashboard/profile.html")

    def test_interface_settings_view_get(self):
        """Test the interface settings view GET."""
        response = self.client.get(reverse("interface_settings"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "dashboard/interface_settings.html")
        self.assertIn("form", response.context)

    def test_interface_settings_view_post_saves_preference(self):
        """Test the interface settings view POST saves preference and redirects."""
        from dashboard.models import DATATABLES_PAGE_LENGTH_DEFAULT
        from dashboard.services.user_preferences import get_datatables_display

        response = self.client.post(
            reverse("interface_settings"),
            {
                "datatables_display": "scroller",
                "datatables_page_length": str(DATATABLES_PAGE_LENGTH_DEFAULT),
            },
            follow=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(get_datatables_display(self.user), "scroller")

    @patch("dashboard.views.get_user_model")
    def test_admin_interface_view(self, mock_get_user_model):
        """Test the admin interface view."""
        mock_user_model = mock_get_user_model.return_value
        mock_queryset = MagicMock()
        mock_queryset.order_by.return_value = mock_queryset
        mock_user_model.objects.all.return_value = mock_queryset
        response = self.client.get(reverse("admin_interface"))
        self.assertEqual(response.status_code, 200)
        self.assertIn("users", response.context)

    def test_search_view(self):
        """Test the search view."""
        response = self.client.get(reverse("search"))
        self.assertEqual(response.status_code, 200)

    def test_projects_view(self):
        """Test the projects view."""
        response = self.client.get(reverse("list_projects"))
        self.assertEqual(response.status_code, 200)
        self.assertIn("projects", response.context)

    def test_edit_project_view(self):
        """Test the edit project view."""
        response = self.client.get(reverse("edit_project", kwargs={"slug": self.data_generator.project.slug}))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "dashboard/edit_project.html")

        # Test POST with valid data
        response = self.client.post(
            reverse("edit_project", kwargs={"slug": self.data_generator.project.slug}),
            {"name": "Updated Project", "description": "Updated description", "insert_date": timezone.now()},
        )
        self.assertRedirects(response, reverse("list_projects"))

    def test_delete_project_view(self):
        """Test the delete project view."""
        response = self.client.post(reverse("delete_project", args=[self.data_generator.project.id]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content), {"status": "true"})

    @patch("dashboard.views.Project.objects.create")
    @patch("dashboard.views.get_user_model")
    def test_onboarding_view(self, mock_get_user_model, mock_project_create):
        """Test the onboarding view."""
        mock_project_create.return_value = self.data_generator.project
        mock_user_model = mock_get_user_model.return_value
        mock_user_model.objects.create_user.return_value = MagicMock()
        response = self.client.post(
            reverse("onboarding"),
            {
                "project_name": "New Project",
                "create_username": "newuser",
                "create_password": "newpass",
                "create_user_role": "admin",
                "key_openai": "openai_key",
                "key_netlas": "netlas_key",
            },
        )
        self.assertEqual(response.status_code, 302)


class AdminInterfaceUpdateTests(BaseTestCase):
    def setUp(self):
        super().setUp()

        # Create users with different roles
        self.superuser = User.objects.create_superuser(username="superadmin", password="password123")
        self.sys_admin = User.objects.create_user(username="sysadmin", password="password123")
        assign_role(self.sys_admin, "sys_admin")
        self.normal_user = User.objects.create_user(username="normaluser", password="password123")
        assign_role(self.normal_user, "penetration_tester")

        # Additional users for testing modifications
        self.target_superuser = User.objects.create_superuser(username="target_super", password="password123")
        self.target_user = User.objects.create_user(username="target_user", password="password123")
        assign_role(self.target_user, "penetration_tester")

    def test_user_creation_permissions(self):
        User = get_user_model()  # noqa: N806

        # Test with superuser
        unique_username = f"newuser_{uuid.uuid4().hex[:8]}"
        data = {"username": unique_username, "password": "newpass", "role": "penetration_tester"}

        self.client.force_login(self.superuser)
        response = self.client.post(
            reverse("admin_interface_update") + "?mode=create", data=json.dumps(data), content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)

        # Verify user creation
        created_user = User.objects.filter(username=unique_username).first()
        self.assertIsNotNone(created_user)
        self.assertTrue(has_role(created_user, "penetration_tester"))

        # Test with sys_admin
        unique_username = f"newuser_{uuid.uuid4().hex[:8]}"
        data["username"] = unique_username

        self.client.force_login(self.sys_admin)
        response = self.client.post(
            reverse("admin_interface_update") + "?mode=create", data=json.dumps(data), content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)

        # Verify user creation by sys_admin
        created_user = User.objects.filter(username=unique_username).first()
        self.assertIsNotNone(created_user)
        self.assertTrue(has_role(created_user, "penetration_tester"))

        # Test with normal user
        unique_username = f"newuser_{uuid.uuid4().hex[:8]}"
        data["username"] = unique_username

        self.client.force_login(self.normal_user)
        response = self.client.post(
            reverse("admin_interface_update") + "?mode=create", data=json.dumps(data), content_type="application/json"
        )
        self.assertEqual(response.status_code, 302)

        # Verify user was not created
        self.assertFalse(User.objects.filter(username=unique_username).exists())

    def test_superuser_modification_permissions(self):
        url = reverse("admin_interface_update") + f"?user={self.target_superuser.id}"

        # Test superuser modifying superuser
        self.client.force_login(self.superuser)
        initial_status = self.target_superuser.is_active
        response = self.client.get(f"{url}&mode=change_status", follow=True)
        self.target_superuser.refresh_from_db()

        # Check if the status has changed and we are redirected to admin_interface
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(initial_status, self.target_superuser.is_active)
        self.assertRedirects(response, reverse("admin_interface"))

        # Test sys_admin modifying superuser
        self.client.force_login(self.sys_admin)
        initial_status = self.target_superuser.is_active
        response = self.client.get(f"{url}&mode=change_status")
        self.target_superuser.refresh_from_db()

        # Check if the status has not changed and we have a 403
        self.assertEqual(response.status_code, 403)
        self.assertEqual(initial_status, self.target_superuser.is_active)

        # Test normal user modifying superuser
        self.client.force_login(self.normal_user)
        initial_status = self.target_superuser.is_active
        response = self.client.get(f"{url}&mode=change_status")
        self.target_superuser.refresh_from_db()

        # Check if the status has not changed and we have a 302
        self.assertEqual(response.status_code, 302)
        self.assertEqual(initial_status, self.target_superuser.is_active)

    def test_user_modification_permissions(self):
        url = reverse("admin_interface_update") + f"?user={self.target_user.id}"

        # Test superuser modifying normal user
        self.client.force_login(self.superuser)
        response = self.client.post(f"{url}&mode=update", data={"role": "auditor"}, content_type="application/json")
        self.assertEqual(response.status_code, 200)
        # Verify role was actually changed
        self.target_user.refresh_from_db()
        self.assertTrue(has_role(self.target_user, "auditor"))

        # Test sys_admin modifying normal user
        self.client.force_login(self.sys_admin)
        response = self.client.post(
            f"{url}&mode=update", data={"role": "penetration_tester"}, content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        # Verify role was actually changed
        self.target_user.refresh_from_db()
        self.assertTrue(has_role(self.target_user, "penetration_tester"))

        # Test normal user modifying normal user
        self.client.force_login(self.normal_user)
        response = self.client.post(f"{url}&mode=update", data={"role": "auditor"}, content_type="application/json")
        self.assertEqual(response.status_code, 302)
        # Verify role was NOT changed (should still be penetration_tester)
        self.target_user.refresh_from_db()
        self.assertTrue(has_role(self.target_user, "penetration_tester"))

    def test_self_modification_restrictions(self):
        # Test superuser trying to delete themselves
        self.client.force_login(self.superuser)
        response = self.client.post(reverse("admin_interface_update") + f"?user={self.superuser.id}&mode=delete")
        self.assertEqual(response.status_code, 403)

        # Test sys_admin trying to delete themselves
        self.client.force_login(self.sys_admin)
        response = self.client.post(reverse("admin_interface_update") + f"?user={self.sys_admin.id}&mode=delete")
        self.assertEqual(response.status_code, 403)


class OAuthRedirectTests(TestCase):
    """Test cases for OAuth and non-OAuth login redirect behavior in AccountAdapter."""

    def setUp(self):
        self.factory = RequestFactory()
        self.adapter = AccountAdapter()
        self.user = get_user_model().objects.create_user(username="oauthuser", password="password123")
        SocialAccount.objects.create(user=self.user, provider="google", uid="oauth-123")

    def _build_request(self, user):
        request = self.factory.get("/")
        request.user = user
        return request

    def _assert_redirect_for_user_without_projects(self, user, expected_view_name):
        """
        Helper to assert the redirect target for a user without any projects.

        Used by non-OAuth redirect tests for different roles
        (e.g. superuser, sys_admin, non-admin) to keep expectations consistent.
        """
        request = self._build_request(user)
        url = self.adapter.get_login_redirect_url(request)
        self.assertEqual(url, reverse(expected_view_name))

    def test_oauth_user_first_login_redirects_to_welcome(self):
        """OAuth user on very first login (last_login is None) redirects to welcome page."""
        # New user, last_login is None by default
        request = self._build_request(self.user)

        redirect_url = self.adapter.get_login_redirect_url(request)

        self.assertEqual(redirect_url, reverse("oauth_welcome"))
        self.assertTrue(has_role(self.user, "auditor"))

    def test_oauth_user_without_projects_redirects_to_list(self):
        """OAuth user without any projects redirects to projects list (after first login)."""
        # Simulate a returning user (last_login is set after first login)
        self.user.last_login = timezone.now()
        self.user.save()

        request = self._build_request(self.user)

        redirect_url = self.adapter.get_login_redirect_url(request)

        self.assertEqual(redirect_url, reverse("list_projects"))
        # Auditor role should be applied
        self.assertTrue(has_role(self.user, "auditor"))

    def test_oauth_user_with_assigned_project_redirects_to_dashboard(self):
        """OAuth user assigned to a project redirects to that project's dashboard."""
        project = Project.objects.create(
            name="Assigned Project", description="", slug="assigned-project", insert_date=timezone.now()
        )
        project.users.add(self.user)

        request = self._build_request(self.user)
        redirect_url = self.adapter.get_login_redirect_url(request)

        self.assertEqual(redirect_url, reverse("dashboardIndex", kwargs={"slug": project.slug}))

    def test_non_oauth_user_with_projects_redirects_to_dashboard(self):
        """Non-OAuth user assigned to a project redirects to that project's dashboard."""
        user = get_user_model().objects.create_user(
            username="normaluser",
            password="password123",
        )
        project = Project.objects.create(
            name="First project", description="", slug="first-project", insert_date=timezone.now()
        )
        project.users.add(user)

        request = self._build_request(user)
        redirect_url = self.adapter.get_login_redirect_url(request)

        self.assertEqual(
            redirect_url,
            reverse("dashboardIndex", kwargs={"slug": project.slug}),
        )

    def test_non_oauth_superuser_without_projects_redirects_to_onboarding(self):
        """Superuser without projects redirects to onboarding to create one."""
        superuser = get_user_model().objects.create_superuser(
            username="superuser",
            email="super@example.com",
            password="password123",
        )

        self._assert_redirect_for_user_without_projects(superuser, "onboarding")

    def test_non_oauth_sys_admin_without_projects_redirects_to_onboarding(self):
        """sys_admin role without projects redirects to onboarding."""
        sys_admin = get_user_model().objects.create_user(
            username="sysadminuser",
            password="password123",
        )
        assign_role(sys_admin, "sys_admin")

        self._assert_redirect_for_user_without_projects(sys_admin, "onboarding")

    def test_non_oauth_non_admin_without_projects_redirects_to_list_projects(self):
        """Non-admin user without projects redirects to projects list (read-only)."""
        user = get_user_model().objects.create_user(
            username="noprojuser",
            password="password123",
        )

        self._assert_redirect_for_user_without_projects(user, "list_projects")

    def test_oauth_user_role_assignment_is_idempotent(self):
        """Calling get_login_redirect_url multiple times doesn't duplicate role."""
        request = self._build_request(self.user)

        # Call multiple times
        self.adapter.get_login_redirect_url(request)
        self.adapter.get_login_redirect_url(request)

        # Should still have auditor role assigned only once
        self.assertTrue(has_role(self.user, "auditor"))

    def test_oauth_user_with_existing_role_keeps_role(self):
        """OAuth user with existing higher role keeps that role."""
        # Assign a higher role first
        assign_role(self.user, "penetration_tester")

        request = self._build_request(self.user)
        self.adapter.get_login_redirect_url(request)

        # Should still have penetration_tester role
        self.assertTrue(has_role(self.user, "penetration_tester"))

    def test_oauth_user_unassigned_from_project_redirects_to_list(self):
        """OAuth user not assigned to any project goes to projects list (after first login)."""
        # Simulate a returning user (last_login is set after first login)
        self.user.last_login = timezone.now()
        self.user.save()

        # Create a project but don't assign the user
        Project.objects.create(
            name="Unassigned Project", description="", slug="unassigned-project", insert_date=timezone.now()
        )

        request = self._build_request(self.user)
        redirect_url = self.adapter.get_login_redirect_url(request)

        # OAuth users without project assignment go to list
        self.assertEqual(redirect_url, reverse("list_projects"))

    def test_oauth_user_deleted_and_recreated_redirects_to_welcome(self):
        """OAuth user deleted and re-created (fresh account) redirects to welcome page."""
        # Simulate a brand-new OAuth account (last_login is None)
        new_user = get_user_model().objects.create_user(username="newgoogleuser", password="!")
        new_user.set_unusable_password()
        new_user.save()
        SocialAccount.objects.create(user=new_user, provider="google", uid="new-oauth-456")

        request = self._build_request(new_user)
        redirect_url = self.adapter.get_login_redirect_url(request)

        self.assertEqual(redirect_url, reverse("oauth_welcome"))
