"""
This file contains the test cases for the dashboard views.
"""
import json
from unittest.mock import patch, MagicMock
from django.urls import reverse
from utils.test_base import BaseTestCase

__all__ = [
    'TestDashboardViews'
]

class TestDashboardViews(BaseTestCase):
    """Test cases for dashboard views."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.data_generator.create_project_full()

    def test_index_view(self):
        """Test the index view of the dashboard."""
        response = self.client.get(reverse('dashboardIndex', kwargs={'slug': self.data_generator.project.slug}))
        self.assertEqual(response.status_code, 200)
        self.assertIn('dashboard_data_active', response.context)
        dashboard_data = response.context['dashboard_data_active']
        self.assertIsInstance(dashboard_data, str)
        self.assertIn('active', dashboard_data)

    def test_profile_view(self):
        """Test the profile view."""
        response = self.client.get(reverse('profile'))
        self.assertEqual(response.status_code, 200)
        self.assertIn('form', response.context)
        self.assertEqual(response.context['current_project'].name, 'Default')

    @patch('dashboard.views.get_user_model')
    def test_admin_interface_view(self, mock_get_user_model):
        """Test the admin interface view."""
        mock_user_model = mock_get_user_model.return_value
        mock_queryset = MagicMock()
        mock_queryset.order_by.return_value = mock_queryset
        mock_user_model.objects.all.return_value = mock_queryset
        response = self.client.get(reverse('admin_interface'))
        self.assertEqual(response.status_code, 200)
        self.assertIn('users', response.context)

    @patch('dashboard.views.get_user_model')
    def test_admin_interface_update_view(self, mock_get_user_model):
        """Test the admin interface update view."""
        mock_user_model = mock_get_user_model.return_value
        mock_user_model.objects.get.return_value = self.user
        response = self.client.get(reverse('admin_interface_update'), {'mode': 'change_status', 'user': 1})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content), {'status': True})

    def test_search_view(self):
        """Test the search view."""
        response = self.client.get(reverse('search'))
        self.assertEqual(response.status_code, 200)

    def test_projects_view(self):
        """Test the projects view."""
        response = self.client.get(reverse('list_projects'))
        self.assertEqual(response.status_code, 200)
        self.assertIn('projects', response.context)

    def test_delete_project_view(self):
        """Test the delete project view."""
        response = self.client.post(reverse('delete_project', args=[self.data_generator.project.id]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content), {'status': 'true'})

    @patch('dashboard.views.Project.objects.create')
    @patch('dashboard.views.get_user_model')
    def test_onboarding_view(self, mock_get_user_model, mock_project_create):
        """Test the onboarding view."""
        mock_project_create.return_value = self.data_generator.project
        mock_user_model = mock_get_user_model.return_value
        mock_user_model.objects.create_user.return_value = MagicMock()
        response = self.client.post(reverse('onboarding'), {
            'project_name': 'New Project',
            'create_username': 'newuser',
            'create_password': 'newpass',
            'create_user_role': 'admin',
            'key_openai': 'openai_key',
            'key_netlas': 'netlas_key'
        })
        self.assertEqual(response.status_code, 302)