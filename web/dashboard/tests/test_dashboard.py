"""
This file contains the test cases for the dashboard views.
"""
import json
from unittest.mock import patch, MagicMock
from django.urls import reverse
from utils.test_base import BaseTestCase
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.utils import timezone
from rolepermissions.checkers import has_role
from rolepermissions.roles import assign_role
import uuid

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
        self.assertTemplateUsed(response, 'dashboard/profile.html')

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
        
        # Create users with different roles
        self.superuser = User.objects.create_superuser(username='superadmin', password='password123')
        self.sys_admin = User.objects.create_user(username='sysadmin', password='password123')
        assign_role(self.sys_admin, 'sys_admin')
        self.normal_user = User.objects.create_user(username='normaluser', password='password123')
        assign_role(self.normal_user, 'penetration_tester')
        
        # Additional users for testing modifications
        self.target_superuser = User.objects.create_superuser(username='target_super', password='password123')
        self.target_user = User.objects.create_user(username='target_user', password='password123')
        assign_role(self.target_user, 'penetration_tester')

    def test_user_creation_permissions(self):
        User = get_user_model()
        
        # Test with superuser
        unique_username = f'newuser_{uuid.uuid4().hex[:8]}'
        data = {'username': unique_username, 'password': 'newpass', 'role': 'penetration_tester'}
        
        self.client.force_login(self.superuser)
        response = self.client.post(reverse('admin_interface_update') + '?mode=create',
                                  data=json.dumps(data), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        
        # Verify user creation
        created_user = User.objects.filter(username=unique_username).first()
        self.assertIsNotNone(created_user)
        self.assertTrue(has_role(created_user, 'penetration_tester'))
        
        # Test with sys_admin
        unique_username = f'newuser_{uuid.uuid4().hex[:8]}'
        data['username'] = unique_username
        
        self.client.force_login(self.sys_admin)
        response = self.client.post(reverse('admin_interface_update') + '?mode=create',
                                  data=json.dumps(data), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        
        # Verify user creation by sys_admin
        created_user = User.objects.filter(username=unique_username).first()
        self.assertIsNotNone(created_user)
        self.assertTrue(has_role(created_user, 'penetration_tester'))
        
        # Test with normal user
        unique_username = f'newuser_{uuid.uuid4().hex[:8]}'
        data['username'] = unique_username
        
        self.client.force_login(self.normal_user)
        response = self.client.post(reverse('admin_interface_update') + '?mode=create',
                                  data=json.dumps(data), content_type='application/json')
        self.assertEqual(response.status_code, 302)
        
        # Verify user was not created
        self.assertFalse(User.objects.filter(username=unique_username).exists())

    def test_superuser_modification_permissions(self):
        url = reverse('admin_interface_update') + f'?user={self.target_superuser.id}'
        
        # Test superuser modifying superuser
        self.client.force_login(self.superuser)
        initial_status = self.target_superuser.is_active
        response = self.client.get(f'{url}&mode=change_status', follow=True)
        self.target_superuser.refresh_from_db()
        
        # Check if the status has changed and we are redirected to admin_interface
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(initial_status, self.target_superuser.is_active)
        self.assertRedirects(response, reverse('admin_interface'))
        
        # Test sys_admin modifying superuser
        self.client.force_login(self.sys_admin)
        initial_status = self.target_superuser.is_active
        response = self.client.get(f'{url}&mode=change_status')
        self.target_superuser.refresh_from_db()
        
        # Check if the status has not changed and we have a 403
        self.assertEqual(response.status_code, 403)
        self.assertEqual(initial_status, self.target_superuser.is_active)
        
        # Test normal user modifying superuser
        self.client.force_login(self.normal_user)
        initial_status = self.target_superuser.is_active
        response = self.client.get(f'{url}&mode=change_status')
        self.target_superuser.refresh_from_db()
        
        # Check if the status has not changed and we have a 302
        self.assertEqual(response.status_code, 302)
        self.assertEqual(initial_status, self.target_superuser.is_active)

    def test_user_modification_permissions(self):
        url = reverse('admin_interface_update') + f'?user={self.target_user.id}'
        
        # Test superuser modifying normal user
        self.client.force_login(self.superuser)
        response = self.client.post(f'{url}&mode=update',
                                  data={'role': 'auditor'}, content_type='application/json')
        self.assertEqual(response.status_code, 200)
        
        # Test sys_admin modifying normal user
        self.client.force_login(self.sys_admin)
        response = self.client.post(f'{url}&mode=update',
                                  data={'role': 'penetration_tester'}, content_type='application/json')
        self.assertEqual(response.status_code, 200)
        
        # Test normal user modifying normal user
        self.client.force_login(self.normal_user)
        response = self.client.post(f'{url}&mode=update',
                                  data={'role': 'auditor'}, content_type='application/json')
        self.assertEqual(response.status_code, 302)

    def test_self_modification_restrictions(self):
        # Test superuser trying to delete themselves
        self.client.force_login(self.superuser)
        response = self.client.post(
            reverse('admin_interface_update') + f'?user={self.superuser.id}&mode=delete')
        self.assertEqual(response.status_code, 403)
        
        # Test sys_admin trying to delete themselves
        self.client.force_login(self.sys_admin)
        response = self.client.post(
            reverse('admin_interface_update') + f'?user={self.sys_admin.id}&mode=delete')
        self.assertEqual(response.status_code, 403)

