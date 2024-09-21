"""
This file contains the test cases for the dashboard views.
"""
import json
from unittest.mock import patch, MagicMock
from django.urls import reverse
from utils.test_base import BaseTestCase
from dashboard.views import admin_interface_update
from dashboard.models import Project
from django.contrib.auth.models import User
from rolepermissions.checkers import has_role
from reNgine.roles import SysAdmin, PenetrationTester
from django.utils import timezone

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
        response = self.client.get(reverse('profile'))  # Suppression du paramètre 'slug'
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/profile.html')  # Vérification du modèle utilisé

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

    def test_search_view(self):
        """Test the search view."""
        response = self.client.get(reverse('search'))
        self.assertEqual(response.status_code, 200)

    def test_projects_view(self):
        """Test the projects view."""
        response = self.client.get(reverse('list_projects'))
        self.assertEqual(response.status_code, 200)
        self.assertIn('projects', response.context)

    def test_edit_project_view(self):
        """Test the edit project view."""        
        response = self.client.get(reverse('edit_project', kwargs={'slug': 'test-project'}))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/edit_project.html')
        
        # Test POST with valid data
        response = self.client.post(reverse('edit_project', kwargs={'slug': 'test-project'}), {
            'name': 'Updated Project',
            'description': 'Updated description',
            'insert_date': timezone.now()
        })
        self.assertRedirects(response, reverse('list_projects'))

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

class AdminInterfaceUpdateTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.data_generator.create_project_full()
        self.user_to_test = User.objects.create_user(username='testuser', password='12345')

    def test_user_creation(self):
        data = {
            'username': 'newuser',
            'password': 'newpassword',
            'role': 'sys_admin'
        }
        response = self.client.post(
            reverse('admin_interface_update') + '?mode=create',
            data=json.dumps(data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(json.loads(response.content)['status'])
        new_user = User.objects.get(username='newuser')
        self.assertTrue(has_role(new_user, SysAdmin))

    def test_user_not_found(self):
        response = self.client.get(reverse('admin_interface_update') + '?user=999')
        self.assertEqual(response.status_code, 404)
        self.assertFalse(json.loads(response.content)['status'])

    def test_get_request(self):
        response = self.client.get(reverse('admin_interface_update') + f'?user={self.user_to_test.id}&mode=change_status')
        self.assertEqual(response.status_code, 302)

    def test_get_request_with_invalid_mode(self):
        response = self.client.get(reverse('admin_interface_update') + f'?user={self.user_to_test.id}&mode=wrong_mode')
        self.assertEqual(response.status_code, 400)

    def test_post_request_update(self):
        data = {
            'role': 'penetration_tester',
            'projects': []
        }
        response = self.client.post(
            reverse('admin_interface_update') + f'?user={self.user_to_test.id}&mode=update',
            data=json.dumps(data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(json.loads(response.content)['status'])
        self.user_to_test.refresh_from_db()
        self.assertTrue(has_role(self.user_to_test, PenetrationTester))

    def test_post_request_delete(self):
        response = self.client.post(
            reverse('admin_interface_update') + f'?user={self.user_to_test.id}&mode=delete',
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(json.loads(response.content)['status'])
        self.assertFalse(User.objects.filter(id=self.user_to_test.id).exists())

    def test_invalid_method(self):
        response = self.client.put(reverse('admin_interface_update') + f'?user={self.user_to_test.id}')
        self.assertEqual(response.status_code, 302)

