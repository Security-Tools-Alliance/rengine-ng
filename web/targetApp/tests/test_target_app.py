"""
TestTargetAppViews contains unit tests for the views of the targetApp application. 
It verifies the functionality related to targets and organizations, ensuring that views 
return the correct status codes, templates, and handle various scenarios appropriately.

Methods:
    setUp: Initializes test objects for projects, domains, and organizations before each test.
    test_index_view: Tests the index view for correct status code and template usage.
    test_add_target_view: Tests the addition of a new target to ensure it is created successfully.
    test_add_ip_view: Tests the addition of a new IP target to ensure it is created successfully.
    test_add_target_with_invalid_ip: Tests the addition of a target with an invalid IP address.
    test_add_target_with_file: Tests the addition of targets from a file to ensure they are created successfully.
    test_add_target_with_empty_file: Tests the handling of an empty file upload.
    test_list_target_view: Tests the list target view for correct status code and template usage.
    test_delete_target_view: Tests the deletion of a target to ensure it is removed successfully.
    test_update_target_view: Tests the update of a target to ensure it is updated successfully.
    test_update_organization_view_with_invalid_data: Tests updating an organization with invalid data.
    test_delete_non_existent_target: Tests the deletion of a non-existent target.
    test_add_organization_view: Tests the addition of a new organization to ensure it is created successfully.
    test_list_organization_view: Tests the list organization view for correct status code and template usage.
    test_delete_organization_view: Tests the deletion of an organization to ensure it is removed successfully.
    test_update_organization_view: Tests the update of an organization to ensure it is updated successfully.
    test_update_organization_with_invalid_data: Tests updating an organization with invalid data.
    test_add_organization_with_duplicate_name: Tests adding an organization with a duplicate name.
    test_delete_non_existent_organization: Tests the deletion of a non-existent organization.
"""

import os
from django.urls import reverse
from django.contrib.messages import get_messages
from utils.test_base import BaseTestCase
from targetApp.models import Domain, Organization

__all__ = [
    'TestTargetAppViews',
]

class TestTargetAppViews(BaseTestCase):
    """
    Test class for the views of the targetApp.
    """

    def setUp(self):
        """
        Initial setup for the tests.
        Creates test objects for projects, domains, and organizations.
        """
        super().setUp()

    def test_index_view(self):
        """
        Tests the index view to ensure it returns the correct status code and template.
        """
        response = self.client.get(reverse('targetIndex'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'target/index.html')

    def test_add_target_view(self):
        """
        Tests the add target view to ensure a new target is created successfully.
        """
        Domain.objects.all().delete()
        response = self.client.post(
            reverse('add_target', kwargs={
                'slug': self.data_generator.project.slug
            }), {
                'addTargets': 'example.com',
                'targetDescription': 'Test Description',
                'targetH1TeamHandle': 'Test Handle',
                'targetOrganization': 'Test Organization',
                'add-multiple-targets': 'submit',
            }
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Domain.objects.filter(name='example.com').exists())

    def test_add_ip_view(self):
        """
        Tests the add target view to ensure a new target is created successfully.
        """
        Domain.objects.all().delete()
        response = self.client.post(
            reverse('add_target', kwargs={
                'slug': self.data_generator.project.slug
            }), {
                'ip_address': '192.168.1.0%2F24',
                'resolved_ip_domains': ['example.local','other-example.local'],
                'targetDescription': 'Test Description',
                'targetH1TeamHandle': 'Test Handle',
                'targetOrganization': 'Test Organization',
                'add-ip-target': 'submit',
            }
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Domain.objects.filter(name='example.local').exists())
        self.assertTrue(Domain.objects.filter(name='other-example.local').exists())

    def test_add_target_with_invalid_ip(self):
        """
        Test adding a target with an invalid IP address.
        """
        response = self.client.post(
            reverse('add_target', kwargs={'slug': self.data_generator.project.slug}),
            {
                'ip_address': '999.999.999.999',  # Invalid IP address
                'resolved_ip_domains': ['999.999.999.999'],
                'targetDescription': 'Test Description',
                'targetH1TeamHandle': 'Test Handle',
                'targetOrganization': 'Test Organization',
                'add-ip-target': 'submit',
            }
        )

        self.assertEqual(response.status_code, 302)
        messages_list = list(get_messages(response.wsgi_request))
        self.assertIn(
            "IP 999.999.999.999 is not a valid IP address / domain. Skipping.",
            [str(message) for message in messages_list]
        )


    def test_add_target_with_file(self):
        """
        Test the add target with file view to ensure a new target is created successfully.
        """
        Domain.objects.all().delete()
        # Create a temporary file for the test
        with open('domains.txt', 'w', encoding='utf-8') as f:
            f.write("example.local\nother-example.local\n")

        with open('domains.txt', 'rb') as file:
            response = self.client.post(
                reverse('add_target', kwargs={'slug': self.data_generator.project.slug}),
                {
                    'txtFile': file,
                    'import-txt-target': 'Upload',
                },
                format='multipart'
            )

        # Check that the response is correct
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Domain.objects.filter(name='example.local').exists())
        self.assertTrue(Domain.objects.filter(name='other-example.local').exists())

        # Clean up the temporary file
        os.remove('domains.txt')

    def test_add_target_with_empty_file(self):
        """
        Test uploading an empty file to ensure the system handles it correctly.
        """
        # Create an empty file for the test
        with open('empty_file.txt', 'w', encoding='utf-8') as f:
            pass  # Create an empty file

        with open('empty_file.txt', 'rb') as file:
            response = self.client.post(
                reverse('add_target', kwargs={'slug': self.data_generator.project.slug}),
                {
                    'txtFile': file,
                    'import-txt-target': 'Upload',
                },
                format='multipart'
            )

        # Check that the response is correct
        self.assertEqual(response.status_code, 302)

        # Check the returned message
        messages_list = list(get_messages(response.wsgi_request))
        self.assertIn(
            "The uploaded file is empty. Please upload a valid file.",
            [str(message) for message in messages_list]
        )

        # Check that no new target was created
        self.assertFalse(Domain.objects.filter(name='example.local').exists())

        # Clean up the empty file
        os.remove('empty_file.txt')

    def test_list_target_view(self):
        """
        Tests the list target view to ensure it returns the correct status code and template.
        """
        response = self.client.get(
            reverse('list_target', kwargs={
                'slug': self.data_generator.project.slug
            })
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'target/list.html')

    def test_delete_target_view(self):
        """
        Tests the delete target view to ensure a target is deleted successfully.
        """
        response = self.client.post(
            reverse('delete_target', kwargs={
                'id': self.data_generator.domain.id,
                'slug': self.data_generator.project.slug
            })
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Domain.objects.filter(id=self.data_generator.domain.id).exists())

    def test_update_target_view(self):
        """
        Tests the update target view to ensure a target is updated successfully.
        """
        response = self.client.post(
            reverse('update_target', kwargs={
                'slug': self.data_generator.project.slug,
                'id': self.data_generator.domain.id
            }),
            {
                'description': 'Updated description',
                'h1_team_handle': 'Updated Handle'
            }
        )
        self.assertEqual(response.status_code, 302)
        self.data_generator.domain.refresh_from_db()
        updated_domain = Domain.objects.get(id=self.data_generator.domain.id)
        self.assertEqual(updated_domain.description, 'Updated description')
        self.assertEqual(updated_domain.h1_team_handle, 'Updated Handle')

    def test_update_organization_view_with_invalid_data(self):
        """
        Test updating an organization with invalid data to ensure validation works.
        """
        # Prepare invalid data (e.g., empty name)
        invalid_data = {
            'name': '',  # Invalid: name cannot be empty
            'description': 'Updated Org Description',
        }

        response = self.client.post(
            reverse('update_organization', kwargs={
                'slug': self.data_generator.project.slug,
                'id': self.data_generator.organization.id
            }),
            invalid_data
        )

        # Check that the response is still 200 (indicating the form was not valid)
        self.assertEqual(response.status_code, 200)

        # Check for the presence of an error message in the response context
        self.assertContains(response, "This field is required.")

        # Verify that the organization data has not changed
        self.data_generator.organization.refresh_from_db()
        self.assertEqual(self.data_generator.organization.name, 'Test Organization')
        self.assertEqual(self.data_generator.organization.description, 'Test Description')

    def test_delete_non_existent_target(self):
        """
        Test attempting to delete a target that does not exist.
        """
        # Attempt to delete a target with a non-existent ID
        non_existent_id = self.data_generator.domain.id + 999  # Ensure this ID does not exist

        response = self.client.post(
            reverse('delete_target', kwargs={
                'id': non_existent_id,
                'slug': self.data_generator.project.slug
            }),
            follow=True  # Follow the redirect after deletion
        )

        # Check that the response is still 200 (indicating the request was processed)
        self.assertEqual(response.status_code, 200)

        messages_list = list(get_messages(response.wsgi_request))
        self.assertIn(
            "Domain not found.",
            [str(message) for message in messages_list]
        )

        # Verify that the existing target is still present
        self.assertTrue(Domain.objects.filter(id=self.data_generator.domain.id).exists())

    def test_add_organization_view(self):
        """
        Tests the add organization view to ensure a new organization is created successfully.
        """
        Organization.objects.all().delete()
        response = self.client.post(
            reverse('add_organization', kwargs={
                'slug': self.data_generator.project.slug
            }), {
                'name': 'New Organization',
                'description': 'New Org Description',
                'domains': [self.data_generator.domain.id],
            }
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Organization.objects.filter(name='New Organization').exists())

    def test_list_organization_view(self):
        """
        Tests the list organization view to ensure it returns the correct status code and template.
        """
        response = self.client.get(
            reverse('list_organization', kwargs={
                'slug': self.data_generator.project.slug
            })
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'organization/list.html')

    def test_delete_organization_view(self):
        """
        Tests the delete organization view to ensure an organization is deleted successfully.
        """
        response = self.client.post(
            reverse('delete_organization', kwargs={
                'id': self.data_generator.organization.id,
                'slug': self.data_generator.project.slug
            })
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Organization.objects.filter(id=self.data_generator.organization.id).exists())

    def test_update_organization_view(self):
        """
        Tests the update organization view to ensure an organization is updated successfully.
        """
        response = self.client.post(
            reverse('update_organization', kwargs={
                'slug': self.data_generator.project.slug,
                'id': self.data_generator.organization.id
            }),
            {
                'name': 'Updated Organization',
                'description': 'Updated Org Description',
                'domains': [self.data_generator.domain.id],
            }
        )
        self.assertEqual(response.status_code, 302)
        self.data_generator.organization.refresh_from_db()
        self.assertEqual(self.data_generator.organization.name, 'Updated Organization')
        self.assertEqual(self.data_generator.organization.description, 'Updated Org Description')

    def test_update_organization_with_invalid_data(self):
        """
        Test updating an organization with invalid data to ensure validation works.
        """
        response = self.client.post(
            reverse('update_organization', kwargs={
                'slug': self.data_generator.project.slug,
                'id': self.data_generator.organization.id
            }),
            {
                'name': '',  # Invalid: name cannot be empty
                'description': 'Updated Org Description',
                'domains': []  # Assuming domains are required
            }
        )

        # Check that the response is still 200 (indicating the form was not valid)
        self.assertEqual(response.status_code, 200)

        # Check for the presence of an error message in the response context
        self.assertContains(response, "This field is required.")

        # Verify that the organization data has not changed
        self.data_generator.organization.refresh_from_db()
        self.assertEqual(self.data_generator.organization.name, 'Test Organization')
        self.assertEqual(self.data_generator.organization.description, 'Test Description')

    def test_add_organization_with_duplicate_name(self):
        """
        Test adding an organization with a name that already exists.
        """
        response = self.client.post(
            reverse('add_organization', kwargs={'slug': self.data_generator.project.slug}),
            {
                'name': 'Test Organization',  # Duplicate name
                'description': 'New Org Description',
                'domains': []
            }
        )

        # Check that the response is still 200 (indicating the form was not valid)
        self.assertEqual(response.status_code, 200)

        # Check for the presence of an error message in the response context
        self.assertContains(response, "Organization with this Name already exists.")

        # Verify that no new organization was created
        self.assertEqual(Organization.objects.count(), 1)

    def test_delete_non_existent_organization(self):
        """
        Test attempting to delete an organization that does not exist.
        """
        # Attempt to delete an organization with a non-existent ID
        non_existent_id = self.data_generator.organization.id + 999

        response = self.client.post(
            reverse('delete_organization', kwargs={
                'id': non_existent_id,
                'slug': self.data_generator.project.slug
            }),
            follow=True  # Follow the redirect after deletion
        )

        # Check that the response is 200
        self.assertEqual(response.status_code, 200)

        messages_list = list(get_messages(response.wsgi_request))
        self.assertIn(
            "Organization not found.",
            [str(message) for message in messages_list]
        )

        # Verify that the existing organization is still present
        self.assertTrue(Organization.objects.filter(id=self.data_generator.organization.id).exists())
