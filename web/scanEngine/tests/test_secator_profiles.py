"""
test_secator_profiles.py

This file contains unit tests for the SecatorProfile model.
"""

from django.core.exceptions import PermissionDenied
import yaml

from scanEngine.models import SecatorProfile
from utils.test_base import BaseTestCase


class TestSecatorProfile(BaseTestCase):
    """Test class for SecatorProfile model."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.profile_data = {
            "name": "test_profile",
            "category": "speed",
            "description": "A test profile",
            "enforce": False,
            "opts": yaml.dump({"rate_limit": 100, "delay": 0}),
            "is_active": True,
        }

    def test_create_builtin_profile(self):
        """Test creating a built-in profile."""
        profile = SecatorProfile.objects.create(profile_type="builtin", **self.profile_data)
        self.assertEqual(profile.profile_type, "builtin")
        self.assertFalse(profile.can_modify())
        self.assertFalse(profile.can_delete())

    def test_create_custom_profile(self):
        """Test creating a custom profile."""
        profile = SecatorProfile.objects.create(profile_type="custom", **self.profile_data)
        self.assertEqual(profile.profile_type, "custom")
        self.assertTrue(profile.can_modify())
        self.assertTrue(profile.can_delete())

    def test_parse_opts(self):
        """Test opts YAML parsing."""
        profile = SecatorProfile.objects.create(profile_type="custom", **self.profile_data)
        opts = profile._parse_opts()
        self.assertIsInstance(opts, dict)
        self.assertEqual(opts.get("rate_limit"), 100)
        self.assertEqual(opts.get("delay"), 0)

    def test_parse_opts_empty(self):
        """Test parsing empty opts."""
        profile_data = self.profile_data.copy()
        profile_data["opts"] = ""
        profile = SecatorProfile.objects.create(profile_type="custom", **profile_data)
        opts = profile._parse_opts()
        self.assertIsInstance(opts, dict)
        self.assertEqual(len(opts), 0)

    def test_parse_opts_invalid_yaml(self):
        """Test parsing invalid YAML opts."""
        profile_data = self.profile_data.copy()
        profile_data["opts"] = "invalid: yaml: ["
        profile = SecatorProfile.objects.create(profile_type="custom", **profile_data)
        opts = profile._parse_opts()
        # Should return empty dict on error
        self.assertIsInstance(opts, dict)
        self.assertEqual(len(opts), 0)

    def test_cannot_modify_builtin_profile(self):
        """Test that built-in profiles cannot be modified."""
        profile = SecatorProfile.objects.create(profile_type="builtin", **self.profile_data)
        profile.description = "Modified description"
        with self.assertRaises(PermissionDenied):
            profile.save()

    def test_cannot_delete_builtin_profile(self):
        """Test that built-in profiles cannot be deleted."""
        profile = SecatorProfile.objects.create(profile_type="builtin", **self.profile_data)
        with self.assertRaises(PermissionDenied):
            profile.delete()

    def test_can_modify_custom_profile(self):
        """Test that custom profiles can be modified."""
        profile = SecatorProfile.objects.create(profile_type="custom", **self.profile_data)
        profile.description = "Modified description"
        profile.save()
        profile.refresh_from_db()
        self.assertEqual(profile.description, "Modified description")

    def test_can_delete_custom_profile(self):
        """Test that custom profiles can be deleted."""
        profile = SecatorProfile.objects.create(profile_type="custom", **self.profile_data)
        profile_id = profile.id
        profile.delete()
        self.assertFalse(SecatorProfile.objects.filter(id=profile_id).exists())

    def test_bypass_builtin_constraints(self):
        """Test bypassing built-in constraints for management commands."""
        profile = SecatorProfile.objects.create(profile_type="builtin", **self.profile_data)
        profile.description = "Modified description"
        profile.save(bypass_builtin_constraints=True)
        profile.refresh_from_db()
        self.assertEqual(profile.description, "Modified description")

    def test_profile_categories(self):
        """Test all profile categories."""
        categories = ["speed", "evasion", "general", "network"]
        for category in categories:
            profile_data = self.profile_data.copy()
            profile_data["name"] = f"test_profile_{category}"
            profile_data["category"] = category
            profile = SecatorProfile.objects.create(profile_type="custom", **profile_data)
            self.assertEqual(profile.category, category)

    def test_profile_str_representation(self):
        """Test profile string representation."""
        profile = SecatorProfile.objects.create(profile_type="custom", **self.profile_data)
        str_repr = str(profile)
        self.assertIn("test_profile", str_repr)
        self.assertIn("speed", str_repr)
        self.assertIn("custom", str_repr)

    def test_set_default_profile(self):
        """Test setting a profile as default."""
        profile = SecatorProfile.objects.create(profile_type="custom", **self.profile_data)
        self.assertFalse(profile.is_default)

        profile.is_default = True
        profile.save()
        profile.refresh_from_db()
        self.assertTrue(profile.is_default)

    def test_only_one_default_per_category(self):
        """Test that only one profile per category can be default."""
        profile_data1 = {k: v for k, v in self.profile_data.items() if k not in ["name", "category"]}
        profile_data1["name"] = "profile1"
        profile_data1["category"] = "speed"
        profile1 = SecatorProfile.objects.create(profile_type="custom", **profile_data1)

        profile_data2 = {k: v for k, v in self.profile_data.items() if k not in ["name", "category"]}
        profile_data2["name"] = "profile2"
        profile_data2["category"] = "speed"
        profile2 = SecatorProfile.objects.create(profile_type="custom", **profile_data2)

        # Set first profile as default
        profile1.is_default = True
        profile1.save()
        profile1.refresh_from_db()
        self.assertTrue(profile1.is_default)

        # Set second profile as default - should unset first
        profile2.is_default = True
        profile2.save()
        profile1.refresh_from_db()
        profile2.refresh_from_db()

        self.assertFalse(profile1.is_default)
        self.assertTrue(profile2.is_default)

    def test_default_uniqueness_across_categories(self):
        """Test that different categories can each have a default."""
        speed_data = {k: v for k, v in self.profile_data.items() if k not in ["name", "category"]}
        speed_data["name"] = "speed_profile"
        speed_data["category"] = "speed"
        speed_profile = SecatorProfile.objects.create(profile_type="custom", **speed_data)

        evasion_data = {k: v for k, v in self.profile_data.items() if k not in ["name", "category"]}
        evasion_data["name"] = "evasion_profile"
        evasion_data["category"] = "evasion"
        evasion_profile = SecatorProfile.objects.create(profile_type="custom", **evasion_data)

        speed_profile.is_default = True
        speed_profile.save()
        evasion_profile.is_default = True
        evasion_profile.save()

        speed_profile.refresh_from_db()
        evasion_profile.refresh_from_db()

        self.assertTrue(speed_profile.is_default)
        self.assertTrue(evasion_profile.is_default)

    def test_builtin_profile_can_be_default(self):
        """Test that built-in profiles can be set as default."""
        profile = SecatorProfile.objects.create(profile_type="builtin", **self.profile_data)
        profile.is_default = True
        profile.save(bypass_builtin_constraints=True)
        profile.refresh_from_db()
        self.assertTrue(profile.is_default)
