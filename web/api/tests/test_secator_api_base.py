"""
Tests for SecatorAPIBase base class.
"""

from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError
from rest_framework.response import Response

from api.secator_api_base import SecatorAPIBase
from utils.test_base import BaseTestCase


class TestSecatorAPIBase(BaseTestCase):
    """Test cases for SecatorAPIBase."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.base = SecatorAPIBase()

    def test_validate_request_data_valid(self):
        """Test validation of valid request data."""
        data = {"key": "value"}
        is_valid, error_response = self.base.validate_request_data(data)
        self.assertTrue(is_valid)
        self.assertIsNone(error_response)

    def test_validate_request_data_invalid(self):
        """Test validation of invalid request data."""
        data = "not a dict"
        is_valid, error_response = self.base.validate_request_data(data)
        self.assertFalse(is_valid)
        self.assertIsInstance(error_response, Response)
        self.assertEqual(error_response.status_code, 400)

    def test_extract_runner_context(self):
        """Test extraction of runner context."""
        runner_data = {
            "config": {"type": "workflow", "name": "test_workflow"},
            "context": {"scan_history_id": 123, "domain_id": 1, "celery_id": "celery-123"},
            "status": "RUNNING",
            "progress": 50,
            "done": False,
        }
        context = self.base.extract_runner_context(runner_data)
        self.assertEqual(context["runner_type"], "workflow")
        self.assertEqual(context["runner_name"], "test_workflow")
        self.assertEqual(context["scan_history_id"], 123)
        self.assertEqual(context["domain_id"], 1)
        self.assertEqual(context["celery_id"], "celery-123")
        self.assertEqual(context["status"], "RUNNING")
        self.assertEqual(context["progress"], 50)
        self.assertEqual(context["done"], False)

    def test_extract_runner_context_partial_data(self):
        """Test extraction of runner context with partial data."""
        runner_data = {}
        context = self.base.extract_runner_context(runner_data)
        # All keys should be present even if None
        self.assertIn("runner_type", context)
        self.assertIn("runner_name", context)
        self.assertIn("scan_history_id", context)
        self.assertIn("domain_id", context)
        self.assertIn("celery_id", context)
        self.assertIn("status", context)
        self.assertIn("progress", context)
        self.assertIn("done", context)
        # Values should be None when missing
        self.assertIsNone(context["runner_type"])
        self.assertIsNone(context["runner_name"])
        self.assertIsNone(context["scan_history_id"])
        self.assertIsNone(context["domain_id"])

    def test_validate_request_data_with_prefix(self):
        """Test validation of request data with custom prefix."""
        data = "not a dict"
        is_valid, error_response = self.base.validate_request_data(data, prefix=self.base.logger.PREFIX_FINDING)
        self.assertFalse(is_valid)
        self.assertIsInstance(error_response, Response)
        self.assertEqual(error_response.status_code, 400)

    def test_validate_scan_context_with_prefix(self):
        """Test validation of scan context with custom prefix."""
        is_valid, error_response, scan_history, domain = self.base.validate_scan_context(
            self.data_generator.scan_history.id,
            self.data_generator.domain.id,
            "subdomain",
            prefix=self.base.logger.PREFIX_RUNNER,
        )
        self.assertTrue(is_valid)
        self.assertIsNone(error_response)
        self.assertIsNotNone(scan_history)
        self.assertIsNotNone(domain)

    def test_extract_finding_context(self):
        """Test extraction of finding context."""
        finding_data = {
            "_type": "subdomain",
            "_context": {"scan_history_id": 123, "domain_id": 1, "task": "subfinder"},
        }
        context = self.base.extract_finding_context(finding_data)
        self.assertEqual(context["finding_type"], "subdomain")
        self.assertEqual(context["scan_history_id"], 123)
        self.assertEqual(context["domain_id"], 1)
        self.assertEqual(context["task"], "subfinder")

    def test_validate_scan_context_success(self):
        """Test successful validation of scan context."""
        is_valid, error_response, scan_history, domain = self.base.validate_scan_context(
            self.data_generator.scan_history.id, self.data_generator.domain.id, "subdomain"
        )
        self.assertTrue(is_valid)
        self.assertIsNone(error_response)
        self.assertIsNotNone(scan_history)
        self.assertIsNotNone(domain)

    def test_validate_scan_context_missing_scan_history_id(self):
        """Test validation with missing scan_history_id."""
        is_valid, error_response, scan_history, domain = self.base.validate_scan_context(None, 1, "subdomain")
        self.assertFalse(is_valid)
        self.assertIsInstance(error_response, Response)
        self.assertEqual(error_response.status_code, 400)

    def test_validate_scan_context_missing_domain_id(self):
        """Test validation with missing domain_id."""
        is_valid, error_response, scan_history, domain = self.base.validate_scan_context(123, None, "subdomain")
        self.assertFalse(is_valid)
        self.assertIsInstance(error_response, Response)
        self.assertEqual(error_response.status_code, 400)

    def test_validate_scan_context_scan_history_not_found(self):
        """Test validation when scan history doesn't exist."""
        is_valid, error_response, scan_history, domain = self.base.validate_scan_context(99999, 1, "subdomain")
        self.assertFalse(is_valid)
        self.assertIsInstance(error_response, Response)
        self.assertEqual(error_response.status_code, 404)

    def test_validate_scan_context_domain_not_found(self):
        """Test validation when domain doesn't exist."""
        is_valid, error_response, scan_history, domain = self.base.validate_scan_context(
            self.data_generator.scan_history.id, 99999, "subdomain"
        )
        self.assertFalse(is_valid)
        self.assertIsInstance(error_response, Response)
        self.assertEqual(error_response.status_code, 404)

    def test_get_repository_for_finding_type(self):
        """Test getting repository for finding type."""
        from reNgine.services.repositories.subdomain_repository import SubdomainRepository

        repo_class = self.base.get_repository_for_finding_type("subdomain")
        self.assertEqual(repo_class, SubdomainRepository)

    def test_get_repository_for_finding_type_unknown(self):
        """Test getting repository for unknown finding type."""
        repo_class = self.base.get_repository_for_finding_type("unknown_type")
        self.assertIsNone(repo_class)

    def test_is_metadata_type(self):
        """Test checking if type is metadata type."""
        self.assertTrue(self.base.is_metadata_type("warning"))
        self.assertTrue(self.base.is_metadata_type("stat"))
        self.assertFalse(self.base.is_metadata_type("subdomain"))

    def test_handle_repository_error_object_does_not_exist(self):
        """Test handling ObjectDoesNotExist error."""
        error = ObjectDoesNotExist("Object not found")
        response = self.base.handle_repository_error(error, "subdomain", 123, 1)
        self.assertIsInstance(response, Response)
        self.assertEqual(response.status_code, 404)

    def test_handle_repository_error_integrity_error(self):
        """Test handling IntegrityError."""
        error = IntegrityError("Integrity error")
        response = self.base.handle_repository_error(error, "subdomain", 123, 1)
        self.assertIsInstance(response, Response)
        self.assertEqual(response.status_code, 409)

    def test_handle_repository_error_validation_error(self):
        """Test handling validation error."""
        error = ValueError("Validation error: invalid data")
        response = self.base.handle_repository_error(error, "subdomain", 123, 1)
        self.assertIsInstance(response, Response)
        self.assertEqual(response.status_code, 400)

    def test_handle_repository_error_generic_error(self):
        """Test handling generic error."""
        error = Exception("Generic error")
        response = self.base.handle_repository_error(error, "subdomain", 123, 1)
        self.assertIsInstance(response, Response)
        self.assertEqual(response.status_code, 500)
