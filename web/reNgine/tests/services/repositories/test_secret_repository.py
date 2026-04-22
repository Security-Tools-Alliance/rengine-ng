"""
Tests for SecretRepository.save_from_secator_tag.
"""

from reNgine.services.repositories.secret_repository import SecretRepository
from startScan.models import Secret
from utils.test_base import BaseTestCase


class TestSecretRepository(BaseTestCase):
    """Test cases for SecretRepository."""

    def setUp(self):
        super().setUp()
        self.repo = SecretRepository()
        self.scan_history = self.data_generator.scan_history
        self.target = self.data_generator.target

    def test_save_from_secator_tag_creates_secret(self):
        """Valid tag payload creates Secret with value in plain text."""
        data = {
            "name": "generic_api_key",
            "match": "src/config.go:42:1",
            "value": "sk-abc123secret",
            "extra_data": {"line": "42"},
        }
        obj = self.repo.save_from_secator_tag(
            data,
            self.scan_history.id,
            self.target.id,
        )
        self.assertIsNotNone(obj)
        self.assertIsInstance(obj, Secret)
        self.assertEqual(obj.rule_name, "generic_api_key")
        self.assertEqual(obj.matched_at, "src/config.go:42:1")
        self.assertEqual(obj.value, "sk-abc123secret")
        self.assertEqual(obj.scan_history_id, self.scan_history.id)
        self.assertEqual(obj.extra_data, {"line": "42"})

    def test_save_from_secator_tag_empty_rule_name_returns_none(self):
        """Empty rule_name returns None and does not create Secret."""
        data = {
            "name": "",
            "match": "file.txt:1:0",
            "value": "secret",
        }
        obj = self.repo.save_from_secator_tag(
            data,
            self.scan_history.id,
            self.target.id,
        )
        self.assertIsNone(obj)
        self.assertEqual(Secret.objects.filter(scan_history=self.scan_history).count(), 0)

    def test_save_from_secator_tag_invalid_scan_history_returns_none(self):
        """Invalid scan_history_id returns None."""
        data = {
            "name": "aws_key",
            "match": "x",
            "value": "val",
        }
        obj = self.repo.save_from_secator_tag(data, 999999, self.target.id)
        self.assertIsNone(obj)
