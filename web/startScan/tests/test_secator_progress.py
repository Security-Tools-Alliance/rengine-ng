"""
Test cases for Secator scan progress and data mapping.
"""

from datetime import timedelta

from django.utils import timezone

from reNgine.services.repositories.certificate_repository import CertificateRepository
from reNgine.services.secator.progress_sync import SecatorProgressSync
from startScan.models import Certificate, SecatorRunner
from utils.test_base import BaseTestCase


class TestSecatorProgress(BaseTestCase):
    """Test cases for Secator scan progress calculation."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.scan_history = self.data_generator.scan_history

    def test_calculate_workflow_progress_with_single_runner(self):
        """Test progress calculation with a single workflow runner."""
        SecatorRunner.objects.create(
            runner_type="workflow",
            runner_name="test_workflow",
            scan_history=self.scan_history,
            domain=self.data_generator.domain,
            runner_data={
                "status": "RUNNING",
                "progress": 50,
                "done": False,
            },
        )

        progress = SecatorProgressSync.calculate_workflow_progress(self.scan_history.id)
        self.assertEqual(progress, 50)

    def test_calculate_workflow_progress_with_multiple_runners(self):
        """Test progress calculation with multiple task runners."""
        # Create workflow runner
        SecatorRunner.objects.create(
            runner_type="workflow",
            runner_name="test_workflow",
            scan_history=self.scan_history,
            domain=self.data_generator.domain,
            runner_data={
                "status": "RUNNING",
                "progress": 0,
                "done": False,
            },
        )

        # Create task runners
        SecatorRunner.objects.create(
            runner_type="task",
            runner_name="task1",
            scan_history=self.scan_history,
            domain=self.data_generator.domain,
            runner_data={
                "status": "SUCCESS",
                "progress": 100,
                "done": True,
            },
        )

        SecatorRunner.objects.create(
            runner_type="task",
            runner_name="task2",
            scan_history=self.scan_history,
            domain=self.data_generator.domain,
            runner_data={
                "status": "RUNNING",
                "progress": 50,
                "done": False,
            },
        )

        progress = SecatorProgressSync.calculate_workflow_progress(self.scan_history.id)
        # Average of 100 and 50 = 75
        self.assertEqual(progress, 75)

    def test_get_current_running_runner(self):
        """Test getting the current running runner."""
        SecatorRunner.objects.create(
            runner_type="workflow",
            runner_name="test_workflow",
            scan_history=self.scan_history,
            domain=self.data_generator.domain,
            runner_data={
                "status": "RUNNING",
                "progress": 50,
                "done": False,
            },
        )

        runner = SecatorProgressSync.get_current_running_runner(self.scan_history.id)
        self.assertIsNotNone(runner)
        self.assertEqual(runner.runner_name, "test_workflow")
        self.assertEqual(runner.runner_type, "workflow")

    def test_get_current_running_runner_no_running(self):
        """Test getting current runner when none is running."""
        SecatorRunner.objects.create(
            runner_type="workflow",
            runner_name="test_workflow",
            scan_history=self.scan_history,
            domain=self.data_generator.domain,
            runner_data={
                "status": "SUCCESS",
                "progress": 100,
                "done": True,
            },
        )

        runner = SecatorProgressSync.get_current_running_runner(self.scan_history.id)
        self.assertIsNone(runner)

    def test_scan_history_get_progress_with_secator(self):
        """Test ScanHistory.get_progress() with Secator runners."""
        SecatorRunner.objects.create(
            runner_type="workflow",
            runner_name="test_workflow",
            scan_history=self.scan_history,
            domain=self.data_generator.domain,
            runner_data={
                "status": "RUNNING",
                "progress": 75,
                "done": False,
            },
        )

        progress = self.scan_history.get_progress()
        self.assertEqual(progress, 75)

    def test_scan_history_get_current_task_with_secator(self):
        """Test ScanHistory.get_current_task() with Secator runners."""
        SecatorRunner.objects.create(
            runner_type="workflow",
            runner_name="subdomain_discovery",
            scan_history=self.scan_history,
            domain=self.data_generator.domain,
            runner_data={
                "status": "RUNNING",
                "progress": 50,
                "done": False,
            },
        )

        current_task = self.scan_history.get_current_task()
        self.assertIsNotNone(current_task)
        self.assertIn("subdomain_discovery", current_task.lower())


class TestSecatorDataMapping(BaseTestCase):
    """Test cases for Secator data mapping in repositories."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.scan_history_id = self.data_generator.scan_history.id
        self.domain_id = self.data_generator.domain.id

    def test_certificate_repository_save_from_secator(self):
        """Test CertificateRepository.save_from_secator()."""
        repository = CertificateRepository()

        certificate_data = {
            "host": "example.com",
            "fingerprint_sha256": "abc123def456",
            "ip": "192.168.1.1",
            "subject_cn": "Example Certificate",
            "subject_an": ["www.example.com", "mail.example.com"],
            "not_before": timezone.now() - timedelta(days=365),
            "not_after": timezone.now() + timedelta(days=365),
            "issuer": "Let's Encrypt",
            "self_signed": False,
            "trusted": True,
            "status": "valid",
            "keysize": 2048,
            "serial_number": "123456",
            "ciphers": ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"],
        }

        certificate = repository.save_from_secator(certificate_data, self.scan_history_id, self.domain_id)

        self.assertIsNotNone(certificate)
        self.assertEqual(certificate.host, "example.com")
        self.assertEqual(certificate.fingerprint_sha256, "abc123def456")
        self.assertEqual(certificate.subject_cn, "Example Certificate")
        self.assertEqual(len(certificate.subject_an), 2)
        self.assertFalse(certificate.self_signed)
        self.assertTrue(certificate.trusted)
        self.assertEqual(certificate.keysize, 2048)

    def test_certificate_repository_parse_datetime(self):
        """Test CertificateRepository._parse_datetime()."""
        repository = CertificateRepository()

        # Test with datetime object
        dt = timezone.now()
        result = repository._parse_datetime(dt)
        self.assertEqual(result, dt)

        # Test with ISO string
        iso_string = "2024-01-01T12:00:00Z"
        result = repository._parse_datetime(iso_string)
        self.assertIsNotNone(result)

        # Test with None
        result = repository._parse_datetime(None)
        self.assertIsNone(result)

    def test_certificate_is_expired(self):
        """Test Certificate.is_expired() method."""
        certificate = Certificate.objects.create(
            host="example.com",
            fingerprint_sha256="abc123",
            scan_history=self.data_generator.scan_history,
            domain=self.data_generator.domain,
            not_after=timezone.now() - timedelta(days=1),
        )

        self.assertTrue(certificate.is_expired())

    def test_certificate_is_expired_soon(self):
        """Test Certificate.is_expired_soon() method."""
        certificate = Certificate.objects.create(
            host="example.com",
            fingerprint_sha256="abc123",
            scan_history=self.data_generator.scan_history,
            domain=self.data_generator.domain,
            not_after=timezone.now() + timedelta(days=15),
        )

        self.assertTrue(certificate.is_expired_soon(months=1))

    def test_certificate_get_or_create(self):
        """Test Certificate get_or_create with unique_together constraint."""
        cert1, created1 = Certificate.objects.get_or_create(
            host="example.com",
            fingerprint_sha256="abc123",
            scan_history=self.data_generator.scan_history,
            defaults={
                "domain": self.data_generator.domain,
            },
        )
        self.assertTrue(created1)
        self.assertIsNotNone(cert1)

        # Try to get or create duplicate - should get existing
        cert2, created2 = Certificate.objects.get_or_create(
            host="example.com",
            fingerprint_sha256="abc123",
            scan_history=self.data_generator.scan_history,
            defaults={
                "domain": self.data_generator.domain,
            },
        )
        self.assertFalse(created2)
        self.assertEqual(cert1.id, cert2.id)
