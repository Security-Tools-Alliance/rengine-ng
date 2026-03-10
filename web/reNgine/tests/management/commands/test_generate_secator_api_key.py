"""
Tests for generate_secator_api_key Django management command.
"""

from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from dashboard.models import UserAPIKey
from reNgine.utilities.api_key_generator import has_secator_api_key


class TestGenerateSecatorApiKeyManagementCommand(TestCase):
    """Test the generate_secator_api_key management command."""

    def setUp(self):
        """Clean up any existing secator user before tests."""
        from dashboard.models import User
        User.objects.filter(username="secator-worker").delete()

    def tearDown(self):
        """Clean up after tests."""
        from dashboard.models import User
        User.objects.filter(username="secator-worker").delete()

    def test_generate_secator_api_key_command_creates_user(self):
        """Test that the command creates the secator-worker user."""
        out = StringIO()
        call_command("generate_secator_api_key", stdout=out)

        output = out.getvalue()
        self.assertIn("System API key generated successfully", output)

        from dashboard.models import User
        user = User.objects.get(username="secator-worker")
        self.assertEqual(user.email, "secator@rengine.local")
        self.assertTrue(user.is_active)
        self.assertFalse(user.has_usable_password())

    def test_generate_secator_api_key_command_api_key_created(self):
        """Test that the command creates an API key."""
        out = StringIO()
        call_command("generate_secator_api_key", stdout=out)

        from dashboard.models import User
        user = User.objects.get(username="secator-worker")
        api_key = UserAPIKey.objects.get(user=user, is_system=True)
        self.assertTrue(api_key.is_system)
        self.assertTrue(api_key.is_active)

    def test_generate_secator_api_key_command_idempotent(self):
        """Test that running the command twice does not create duplicate keys."""
        out1 = StringIO()
        call_command("generate_secator_api_key", stdout=out1)

        out2 = StringIO()
        call_command("generate_secator_api_key", stdout=out2)

        output2 = out2.getvalue()
        self.assertIn("already exists", output2)

        from dashboard.models import User
        user = User.objects.get(username="secator-worker")
        count = UserAPIKey.objects.filter(user=user, is_system=True).count()
        self.assertEqual(count, 1)

    def test_generate_secator_api_key_command_recreate_flag(self):
        """Test that --recreate flag regenerates the API key."""
        out1 = StringIO()
        call_command("generate_secator_api_key", stdout=out1)

        from dashboard.models import User
        user = User.objects.get(username="secator-worker")
        first_key = UserAPIKey.objects.get(user=user, is_system=True)
        first_key_id = first_key.id

        out2 = StringIO()
        call_command("generate_secator_api_key", "--recreate", stdout=out2)

        output2 = out2.getvalue()
        self.assertIn("Recreating system API key", output2)

        count = UserAPIKey.objects.filter(user=user, is_system=True).count()
        self.assertEqual(count, 1)

        new_key = UserAPIKey.objects.get(user=user, is_system=True)
        self.assertNotEqual(new_key.id, first_key_id)

    def test_generate_secator_api_key_command_show_key_flag(self):
        """Test that --show-key flag displays the API key."""
        out = StringIO()
        call_command("generate_secator_api_key", "--show-key", stdout=out)

        output = out.getvalue()
        self.assertIn("API Key", output)
        self.assertIn("save this securely", output)

    def test_generate_secator_api_key_command_show_key_with_recreate(self):
        """Test that --show-key works with --recreate flag."""
        out1 = StringIO()
        call_command("generate_secator_api_key", stdout=out1)

        out2 = StringIO()
        call_command("generate_secator_api_key", "--recreate", "--show-key", stdout=out2)

        output = out2.getvalue()
        self.assertIn("API Key (save this securely)", output)
        self.assertIn("This is the only time you will see this key", output)

    def test_generate_secator_api_key_command_no_key_display_without_flag(self):
        """Test that API key is not displayed without --show-key flag."""
        out = StringIO()
        call_command("generate_secator_api_key", stdout=out)

        output = out.getvalue()
        self.assertIn("API key was generated but not displayed", output)

    def test_generate_secator_api_key_command_already_exists_message(self):
        """Test the message shown when API key already exists."""
        out1 = StringIO()
        call_command("generate_secator_api_key", stdout=out1)

        out2 = StringIO()
        call_command("generate_secator_api_key", stdout=out2)

        output = out2.getvalue()
        self.assertIn("already exists", output)
        self.assertIn("--recreate", output)
        self.assertIn("--show-key", output)

    def test_generate_secator_api_key_command_help(self):
        """Test that the command shows help information."""
        from django.core.management import CommandError

        try:
            call_command("generate_secator_api_key", "--help")
        except SystemExit:
            pass
        except CommandError:
            self.fail("Unexpected CommandError when calling --help")

