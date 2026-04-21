"""
Tests for API key generator utility.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase

from dashboard.models import UserAPIKey
from reNgine.utilities.api_key_generator import generate_secator_api_key, get_secator_user, has_secator_api_key


User = get_user_model()


class TestAPIKeyGenerator(TestCase):
    """Test API key generation functions."""

    def setUp(self):
        """Set up test case."""
        # Clean up any existing secator user
        User.objects.filter(username="secator-worker").delete()

    def tearDown(self):
        """Clean up after test."""
        # Clean up secator user
        User.objects.filter(username="secator-worker").delete()

    def test_generate_secator_api_key_creates_user(self):
        """Test that API key generation creates system user."""
        key, created = generate_secator_api_key()

        self.assertTrue(created)
        self.assertIsNotNone(key)

        # Verify user was created
        user = User.objects.get(username="secator-worker")
        self.assertEqual(user.email, "secator@rengine.local")
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertFalse(user.has_usable_password())

    def test_generate_secator_api_key_creates_system_key(self):
        """Test that generated API key is marked as system key."""
        key, created = generate_secator_api_key()

        self.assertTrue(created)

        # Verify API key was created with is_system=True
        user = User.objects.get(username="secator-worker")
        api_key = UserAPIKey.objects.get(user=user, name="Secator Worker System Key")
        self.assertTrue(api_key.is_system)
        self.assertTrue(api_key.is_active)

    def test_generate_secator_api_key_idempotent(self):
        """Test that calling function twice doesn't create duplicate keys."""
        # First call
        key1, created1 = generate_secator_api_key()
        self.assertTrue(created1)

        # Second call without recreate should return None and False
        key2, created2 = generate_secator_api_key()
        self.assertFalse(created2)
        self.assertIsNone(key2)

        # Verify only one API key exists
        user = User.objects.get(username="secator-worker")
        count = UserAPIKey.objects.filter(user=user, is_system=True).count()
        self.assertEqual(count, 1)

    def test_generate_secator_api_key_recreate(self):
        """Test that recreate flag deletes old key and creates new one."""
        # First call
        key1, created1 = generate_secator_api_key()
        self.assertTrue(created1)

        # Get the first API key ID
        user = User.objects.get(username="secator-worker")
        first_key = UserAPIKey.objects.get(user=user, is_system=True)
        first_key_id = first_key.id

        # Second call with recreate
        key2, created2 = generate_secator_api_key(recreate=True)
        self.assertTrue(created2)
        self.assertIsNotNone(key2)

        # Verify old key was deleted and new one created
        count = UserAPIKey.objects.filter(user=user, is_system=True).count()
        self.assertEqual(count, 1)

        # Verify new key has different ID
        new_key = UserAPIKey.objects.get(user=user, is_system=True)
        self.assertNotEqual(new_key.id, first_key_id)

    def test_get_secator_user(self):
        """Test getting the Secator system user."""
        # User doesn't exist yet
        with self.assertRaises(User.DoesNotExist):
            get_secator_user()

        # Create user
        generate_secator_api_key()

        # Now should succeed
        user = get_secator_user()
        self.assertEqual(user.username, "secator-worker")

    def test_has_secator_api_key(self):
        """Test checking if Secator API key exists."""
        # No key exists
        self.assertFalse(has_secator_api_key())

        # Create key
        generate_secator_api_key()

        # Now should return True
        self.assertTrue(has_secator_api_key())

    def test_generated_key_not_empty(self):
        """Test that generated key is not empty."""
        key, created = generate_secator_api_key()

        self.assertTrue(created)
        self.assertIsNotNone(key)
        self.assertGreater(len(key), 20)  # API keys should be reasonably long

    def test_system_key_cannot_be_deleted_programmatically(self):
        """Test that is_system field is set correctly to prevent UI deletion."""
        # Generate key
        generate_secator_api_key()

        # Get the key
        user = User.objects.get(username="secator-worker")
        api_key = UserAPIKey.objects.get(user=user, is_system=True)

        # Verify is_system is True (UI should check this before allowing deletion)
        self.assertTrue(api_key.is_system)

        # Note: Actual deletion prevention should be tested in view tests
        # This just verifies the flag is set correctly
