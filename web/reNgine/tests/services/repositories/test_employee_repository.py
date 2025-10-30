"""
Tests for Employee repository functionality.
"""

from reNgine.services.repositories.employee_repository import EmployeeRepository
from utils.test_base import BaseTestCase


class TestEmployeeRepository(BaseTestCase):
    """Test cases for EmployeeRepository."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.employee_repo = EmployeeRepository()
        # Create test domain and scan history
        self.domain = self.data_generator.create_domain()
        self.scan_history = self.data_generator.create_scan_history()

    def test_save_from_secator_valid_employee_with_username(self):
        """Test saving valid employee with username from Secator."""
        item = {
            "_type": "user_account",
            "username": "john.doe",
            "site_name": "example.com",
            "url": "https://example.com/profile/john.doe",
        }

        result = self.employee_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.username, "john.doe")
        self.assertEqual(result.site_name, "example.com")
        self.assertEqual(result.url, "https://example.com/profile/john.doe")
        self.assertEqual(result.name, "john.doe")  # name should be set to username

    def test_save_from_secator_valid_employee_with_email(self):
        """Test saving valid employee with email from Secator."""
        item = {
            "_type": "user_account",
            "email": "john.doe@example.com",
            "site_name": "example.com",
            "url": "https://example.com/profile/john.doe",
        }

        result = self.employee_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.site_name, "example.com")
        self.assertEqual(result.url, "https://example.com/profile/john.doe")
        self.assertEqual(result.name, "john.doe@example.com")  # name should be set to email

        # Verify email association
        emails = list(result.emails.all())
        self.assertTrue(len(emails) > 0, "Employee should have at least one email")
        email_addresses = [email.address for email in emails]
        self.assertIn("john.doe@example.com", email_addresses)

    def test_save_from_secator_valid_employee_with_both_username_email(self):
        """Test saving valid employee with both username and email."""
        item = {
            "_type": "user_account",
            "username": "john.doe",
            "email": "john.doe@example.com",
            "site_name": "example.com",
            "url": "https://example.com/profile/john.doe",
        }

        result = self.employee_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.username, "john.doe")
        self.assertEqual(result.name, "john.doe")  # name should be set to username

        # Verify email association
        emails = list(result.emails.all())
        self.assertTrue(len(emails) > 0, "Employee should have at least one email")
        email_addresses = [email.address for email in emails]
        self.assertIn("john.doe@example.com", email_addresses)

    def test_save_from_secator_missing_username_and_email(self):
        """Test handling missing username and email."""
        item = {
            "_type": "user_account",
            "site_name": "example.com",
            "url": "https://example.com/profile/john.doe",
        }

        result = self.employee_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNone(result)

    def test_save_from_secator_with_subdomain_association(self):
        """Test saving employee with subdomain association."""
        # Create subdomain first
        subdomain = self.data_generator.create_subdomain(
            name="test.example.com",
            scan_history=self.scan_history,
            target_domain=self.domain,
        )

        item = {
            "_type": "user_account",
            "username": "john.doe",
            "email": "john.doe@example.com",
            "site_name": "example.com",
            "url": "https://test.example.com/profile/john.doe",
        }

        result = self.employee_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.username, "john.doe")
        self.assertEqual(result.subdomain, subdomain)

    def test_save_from_secator_with_endpoint_association(self):
        """Test saving employee with endpoint association."""
        # Create subdomain and endpoint first
        subdomain = self.data_generator.create_subdomain(
            name="test.example.com",
            scan_history=self.scan_history,
            target_domain=self.domain,
        )

        endpoint = self.data_generator.create_endpoint(
            http_url="https://test.example.com/profile/john.doe",
            scan_history=self.scan_history,
            target_domain=self.domain,
            subdomain=subdomain,
        )

        item = {
            "_type": "user_account",
            "username": "john.doe",
            "email": "john.doe@example.com",
            "site_name": "example.com",
            "url": "https://test.example.com/profile/john.doe",
        }

        result = self.employee_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.username, "john.doe")
        self.assertEqual(result.endpoint, endpoint)

    def test_get_or_create_existing_employee_by_username_site(self):
        """Test get_or_create with existing employee by username and site."""
        # Create employee first
        employee1, created1 = self.employee_repo.get_or_create(
            "john.doe", "john.doe@example.com", self.scan_history.id, site_name="example.com"
        )
        self.assertTrue(created1)

        # Try to create same employee again
        employee2, created2 = self.employee_repo.get_or_create(
            "john.doe", "john.doe@example.com", self.scan_history.id, site_name="example.com"
        )
        self.assertFalse(created2)
        self.assertEqual(employee1.id, employee2.id)

    def test_get_or_create_existing_employee_by_email(self):
        """Test get_or_create with existing employee by email."""
        # Create employee first
        employee1, created1 = self.employee_repo.get_or_create("", "john.doe@example.com", self.scan_history.id)
        self.assertTrue(created1)

        # Try to create same employee again
        employee2, created2 = self.employee_repo.get_or_create("", "john.doe@example.com", self.scan_history.id)
        self.assertFalse(created2)
        self.assertEqual(employee1.id, employee2.id)

    def test_get_or_create_new_employee(self):
        """Test get_or_create with new employee."""
        employee, created = self.employee_repo.get_or_create("john.doe", "john.doe@example.com", self.scan_history.id)

        self.assertIsNotNone(employee)
        self.assertTrue(created)
        self.assertEqual(employee.username, "john.doe")

        # Verify email association
        emails = list(employee.emails.all())
        self.assertTrue(len(emails) > 0, "Employee should have at least one email")
        email_addresses = [email.address for email in emails]
        self.assertIn("john.doe@example.com", email_addresses)

    def test_bulk_create_employees(self):
        """Test bulk creation of employees."""
        employees_data = [
            {
                "username": "john.doe",
                "email": "john.doe@example.com",
                "site_name": "example.com",
            },
            {
                "username": "jane.smith",
                "email": "jane.smith@example.com",
                "site_name": "example.com",
            },
        ]

        result = self.employee_repo.bulk_create(employees_data, self.scan_history.id, self.domain.id)

        self.assertEqual(len(result), 2)
        created_usernames = [emp.username for emp in result]
        self.assertIn("john.doe", created_usernames)
        self.assertIn("jane.smith", created_usernames)

    def test_bulk_create_duplicate_employees(self):
        """Test bulk creation with duplicate employees."""
        employees_data = [
            {
                "username": "john.doe",
                "email": "john.doe@example.com",
                "site_name": "example.com",
            },
            {
                "username": "john.doe",  # Duplicate username
                "email": "john.doe@example.com",
                "site_name": "example.com",
            },
        ]

        result = self.employee_repo.bulk_create(employees_data, self.scan_history.id, self.domain.id)

        # Should only create unique employees
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].username, "john.doe")

    # Tests for private methods removed - these methods no longer exist in the repository

    def test_search_by_email(self):
        """Test searching employees by email."""
        # Create employee with email
        employee = self.data_generator.create_employee(
            username="john.doe",
            scan_history=self.scan_history,
        )

        # Create email and associate it
        from startScan.models import Email

        email_obj = Email.objects.create(address="john.doe@example.com")
        employee.emails.add(email_obj)

        result = self.employee_repo.search_by_email("john.doe@example.com")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].id, employee.id)

    def test_search_by_username(self):
        """Test searching employees by username."""
        # Create employee
        employee = self.data_generator.create_employee(
            username="john.doe",
            scan_history=self.scan_history,
        )

        result = self.employee_repo.search_by_username("john.doe")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].id, employee.id)

    def test_search_by_username_partial(self):
        """Test searching employees by partial username."""
        # Create employees
        self.data_generator.create_employee(
            username="john.doe",
            scan_history=self.scan_history,
        )
        self.data_generator.create_employee(
            username="john.smith",
            scan_history=self.scan_history,
        )

        result = self.employee_repo.search_by_username("john")

        self.assertEqual(len(result), 2)
        usernames = [emp.username for emp in result]
        self.assertIn("john.doe", usernames)
        self.assertIn("john.smith", usernames)

    def test_get_employees_for_subdomain(self):
        """Test getting employees for a specific subdomain."""
        # Create subdomain and employees
        subdomain = self.data_generator.create_subdomain(
            name="test.example.com",
            scan_history=self.scan_history,
            target_domain=self.domain,
        )

        self.data_generator.create_employee(
            username="john.doe",
            scan_history=self.scan_history,
            subdomain=subdomain,
        )
        self.data_generator.create_employee(
            username="jane.smith",
            scan_history=self.scan_history,
            subdomain=subdomain,
        )

        result = self.employee_repo.get_employees_for_subdomain("test.example.com", self.scan_history.id)

        self.assertEqual(len(result), 2)
        usernames = [emp.username for emp in result]
        self.assertIn("john.doe", usernames)
        self.assertIn("jane.smith", usernames)

    # Tests for private validation methods removed - these methods no longer exist in the repository

    def test_save_from_secator_with_extra_data(self):
        """Test saving employee with extra data."""
        item = {
            "_type": "user_account",
            "username": "john.doe",
            "email": "john.doe@example.com",
            "site_name": "example.com",
            "url": "https://example.com/profile/john.doe",
            "extra_data": {
                "role": "admin",
                "last_login": "2023-01-01T00:00:00Z",
            },
        }

        result = self.employee_repo.save_from_secator(item, self.scan_history.id, self.domain.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.username, "john.doe")
        self.assertEqual(result.extra_data["role"], "admin")
        self.assertEqual(result.extra_data["last_login"], "2023-01-01T00:00:00Z")
