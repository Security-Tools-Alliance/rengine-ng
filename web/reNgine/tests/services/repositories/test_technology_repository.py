"""
Tests for Technology repository functionality.
"""

from reNgine.services.repositories.technology_repository import TechnologyRepository
from utils.test_base import BaseTestCase


class TestTechnologyRepository(BaseTestCase):
    """Test cases for TechnologyRepository."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.tech_repo = TechnologyRepository()
        # Create test domain and scan history
        self.domain = self.data_generator.create_domain()
        self.scan_history = self.data_generator.create_scan_history()

    def test_save_from_secator_with_subdomain_match(self):
        """Test saving technology with subdomain match."""
        # Create subdomain first
        subdomain = self.data_generator.create_subdomain(name="test.example.com")

        item = {
            "_type": "tag",
            "name": "nginx",
            "match": "test.example.com",
        }

        result = self.tech_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.name, "nginx")

        # Verify association with subdomain
        subdomain.refresh_from_db()
        self.assertIn(result, subdomain.technologies.all())

    def test_save_from_secator_with_url_match(self):
        """Test saving technology with URL match."""
        # Create subdomain and endpoint first
        subdomain = self.data_generator.create_subdomain(name="test.example.com")

        endpoint = self.data_generator.create_endpoint(
            http_url="https://test.example.com/admin",
            scan_history=self.scan_history,
            domain=self.domain,
            subdomain=subdomain,
        )

        item = {
            "_type": "tag",
            "name": "apache",
            "match": "https://test.example.com/admin",
        }

        result = self.tech_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.name, "apache")

        # Verify association with endpoint
        endpoint.refresh_from_db()
        self.assertIn(result, endpoint.techs.all())

    def test_save_from_secator_missing_name(self):
        """Test handling missing technology name."""
        item = {
            "_type": "tag",
            "match": "test.example.com",
        }

        result = self.tech_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNone(result)

    def test_save_from_secator_missing_match(self):
        """Test handling missing match field."""
        item = {
            "_type": "tag",
            "name": "nginx",
        }

        result = self.tech_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNone(result)

    def test_save_from_secator_nonexistent_target(self):
        """Test saving technology with non-existent target."""
        item = {
            "_type": "tag",
            "name": "nginx",
            "match": "nonexistent.example.com",
        }

        result = self.tech_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        # Should still create technology but without association
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "nginx")

    def test_get_or_create_existing_technology(self):
        """Test get_or_create with existing technology."""
        # Create technology first
        tech1, created1 = self.tech_repo.get_or_create("nginx")
        self.assertTrue(created1)

        # Try to create same technology again
        tech2, created2 = self.tech_repo.get_or_create("nginx")
        self.assertFalse(created2)
        self.assertEqual(tech1.id, tech2.id)

    def test_get_or_create_new_technology(self):
        """Test get_or_create with new technology."""
        tech, created = self.tech_repo.get_or_create("apache")

        self.assertIsNotNone(tech)
        self.assertTrue(created)
        self.assertEqual(tech.name, "apache")

    def test_bulk_create_technologies(self):
        """Test bulk creation of technologies."""
        tech_names = ["nginx", "apache", "mysql", "php"]

        result = self.tech_repo.bulk_create(tech_names)

        self.assertEqual(len(result), 4)
        created_names = [tech.name for tech in result]
        for name in tech_names:
            self.assertIn(name, created_names)

    def test_bulk_create_duplicate_technologies(self):
        """Test bulk creation with duplicate technology names."""
        tech_names = ["nginx", "apache", "nginx", "mysql"]  # nginx appears twice

        result = self.tech_repo.bulk_create(tech_names)

        # Should only create unique technologies
        self.assertEqual(len(result), 3)
        created_names = [tech.name for tech in result]
        self.assertIn("nginx", created_names)
        self.assertIn("apache", created_names)
        self.assertIn("mysql", created_names)

    # Tests for private methods removed - these methods no longer exist in the repository

    def test_save_from_secator_with_extra_data(self):
        """Test saving technology with extra data."""
        subdomain = self.data_generator.create_subdomain(name="test.example.com")

        item = {
            "_type": "tag",
            "name": "nginx",
            "match": "test.example.com",
            "extra_data": {
                "version": "1.18.0",
                "confidence": 0.9,
            },
        }

        result = self.tech_repo.save_from_secator(item, self.scan_history.id, self.data_generator.target.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.name, "nginx")

        # Verify association
        subdomain.refresh_from_db()
        self.assertIn(result, subdomain.technologies.all())

    def test_process_secator_technology_item_valid(self):
        """Test _process_secator_technology_item with valid data."""
        subdomain = self.data_generator.create_subdomain(name="test.example.com")

        item = {
            "name": "nginx",
            "match": "test.example.com",
            "value": "1.18.0",
            "category": "webserver",
        }

        result = self.tech_repo._process_secator_technology_item(
            item, self.scan_history.id, self.data_generator.target.id
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.name, "nginx")
        self.assertEqual(result.value, "1.18.0")
        self.assertEqual(result.category, "webserver")

        # Verify technology is associated with subdomain
        subdomain.refresh_from_db()
        self.assertIn(result, subdomain.technologies.all())

    def test_process_secator_technology_item_missing_name(self):
        """Test _process_secator_technology_item with missing name."""
        item = {
            "match": "test.example.com",
        }

        result = self.tech_repo._process_secator_technology_item(
            item, self.scan_history.id, self.data_generator.target.id
        )

        self.assertIsNone(result)

    def test_process_secator_technology_item_missing_match(self):
        """Test _process_secator_technology_item with missing match."""
        item = {
            "name": "nginx",
        }

        result = self.tech_repo._process_secator_technology_item(
            item, self.scan_history.id, self.data_generator.target.id
        )

        self.assertIsNone(result)
