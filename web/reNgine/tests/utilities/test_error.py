"""
Tests for safe user-facing error message utility.
"""

from unittest.mock import MagicMock

from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import IntegrityError
from django.test import TestCase

from reNgine.definitions import GENERIC_USER_ERROR_MESSAGE
from reNgine.utilities.error import UserSafeError, get_safe_user_message


class TestGetSafeUserMessage(TestCase):
    """Test get_safe_user_message returns safe messages and logs when logger provided."""

    def test_object_does_not_exist_returns_fixed_message(self):
        """ObjectDoesNotExist returns generic message, no object detail."""
        logger = MagicMock()
        exc = ObjectDoesNotExist("ScanHistory matching query does not exist.")
        msg = get_safe_user_message(exc, logger)
        self.assertEqual(msg, "Required object not found.")
        logger.exception.assert_called_once()

    def test_integrity_error_returns_fixed_message(self):
        """IntegrityError returns generic message, no DB detail."""
        logger = MagicMock()
        exc = IntegrityError("UNIQUE constraint failed: scanEngine_secatorworkflow.name")
        msg = get_safe_user_message(exc, logger)
        self.assertEqual(msg, "Database integrity error.")
        logger.exception.assert_called_once()

    def test_validation_error_returns_message(self):
        """ValidationError returns str(exception) for UX (may be list repr in Django)."""
        logger = MagicMock()
        exc = ValidationError("Invalid name")
        msg = get_safe_user_message(exc, logger)
        self.assertIn("Invalid name", msg)
        logger.exception.assert_called_once()

    def test_exception_with_validation_keyword_returns_message(self):
        """Exception message containing 'validation' returns sanitized message."""
        logger = MagicMock()
        exc = ValueError("Field validation failed")
        msg = get_safe_user_message(exc, logger)
        self.assertEqual(msg, "Field validation failed")
        logger.exception.assert_called_once()

    def test_exception_with_invalid_keyword_returns_message(self):
        """Exception message containing 'invalid' returns sanitized message."""
        logger = MagicMock()
        exc = ValueError("Invalid input")
        msg = get_safe_user_message(exc, logger)
        self.assertEqual(msg, "Invalid input")
        logger.exception.assert_called_once()

    def test_exception_with_required_keyword_returns_message(self):
        """Exception message containing 'required' returns sanitized message."""
        logger = MagicMock()
        exc = ValueError("activity_id is required")
        msg = get_safe_user_message(exc, logger)
        self.assertEqual(msg, "activity_id is required")
        logger.exception.assert_called_once()

    def test_runtime_error_always_returns_generic(self):
        """RuntimeError is not passed through; returns GENERIC to avoid leaking internal messages."""
        logger = MagicMock()
        exc = RuntimeError("Worker compose file not found. Check server configuration.")
        msg = get_safe_user_message(exc, logger)
        self.assertEqual(msg, GENERIC_USER_ERROR_MESSAGE)
        logger.exception.assert_called_once()

    def test_runtime_error_unsafe_message_returns_generic(self):
        """RuntimeError with path/newline returns GENERIC_USER_ERROR_MESSAGE."""
        logger = MagicMock()
        exc = RuntimeError("Internal path /etc/secret leaked")
        msg = get_safe_user_message(exc, logger)
        self.assertEqual(msg, GENERIC_USER_ERROR_MESSAGE)
        logger.exception.assert_called_once()

    def test_user_safe_error_safe_message_returns_message(self):
        """UserSafeError with safe message (e.g. deploy config) is returned to user."""
        logger = MagicMock()
        exc = UserSafeError("Worker compose file not found. Check server configuration.")
        msg = get_safe_user_message(exc, logger)
        self.assertEqual(msg, "Worker compose file not found. Check server configuration.")
        logger.exception.assert_called_once()

    def test_user_safe_error_unsafe_message_returns_generic(self):
        """UserSafeError with path/newline returns GENERIC_USER_ERROR_MESSAGE."""
        logger = MagicMock()
        exc = UserSafeError("Error in /etc/secret")
        msg = get_safe_user_message(exc, logger)
        self.assertEqual(msg, GENERIC_USER_ERROR_MESSAGE)
        logger.exception.assert_called_once()

    def test_logger_none_user_safe_error_returns_message(self):
        """When logger is None, UserSafeError message is still returned if safe."""
        exc = UserSafeError("SSH error during deployment.")
        msg = get_safe_user_message(exc, None)
        self.assertEqual(msg, "SSH error during deployment.")

    def test_logger_none_runtime_error_returns_generic(self):
        """When logger is None, RuntimeError returns generic (not passed through)."""
        exc = RuntimeError("Some internal error")
        msg = get_safe_user_message(exc, None)
        self.assertEqual(msg, GENERIC_USER_ERROR_MESSAGE)

    def test_logger_none_validation_like_still_returns_sanitized(self):
        """When logger is None, validation-like exceptions still return str(exc)."""
        exc = ValueError("Invalid value")
        msg = get_safe_user_message(exc, None)
        self.assertEqual(msg, "Invalid value")

    def test_validation_like_message_with_system_path_returns_generic(self):
        """Validation-like message containing absolute system path (e.g. /etc/secret) returns generic."""
        logger = MagicMock()
        exc = ValueError("Invalid path: /etc/secret")
        msg = get_safe_user_message(exc, logger)
        self.assertEqual(msg, GENERIC_USER_ERROR_MESSAGE)

    def test_validation_like_message_with_url_path_returns_message(self):
        """Validation-like message mentioning a URL path (e.g. invalid URL /foo) is allowed."""
        logger = MagicMock()
        exc = ValueError("invalid URL /foo")
        msg = get_safe_user_message(exc, logger)
        self.assertEqual(msg, "invalid URL /foo")

    def test_validation_like_message_with_newline_returns_generic(self):
        """Validation-like exception message containing newline returns generic."""
        logger = MagicMock()
        exc = ValueError("Invalid value\n  at line 1")
        msg = get_safe_user_message(exc, logger)
        self.assertEqual(msg, GENERIC_USER_ERROR_MESSAGE)
