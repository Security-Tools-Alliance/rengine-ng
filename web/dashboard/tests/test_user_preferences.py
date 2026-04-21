"""
Tests for UserPreference model and user_preferences service.
"""

from dashboard.models import (
    DATATABLES_DISPLAY_CLASSIC,
    DATATABLES_DISPLAY_SCROLLER,
    DATATABLES_PAGE_LENGTH_DEFAULT,
    UserPreference,
)
from dashboard.services.user_preferences import (
    PREF_DATATABLES_DISPLAY,
    PREF_DATATABLES_PAGE_LENGTH,
    get_datatables_display,
    get_datatables_page_length,
    get_user_preference,
    set_user_preference,
)
from utils.test_base import BaseTestCase


class UserPreferenceModelTest(BaseTestCase):
    """Tests for UserPreference model."""

    def test_create_user_preference(self):
        """UserPreference is created with empty preferences by default."""
        pref, created = UserPreference.objects.get_or_create(user=self.user, defaults={"preferences": {}})
        self.assertTrue(created)
        self.assertEqual(pref.preferences, {})
        self.assertEqual(str(pref), f"Preferences for {self.user.username}")

    def test_preferences_json_storage(self):
        """Preferences store and retrieve JSON values."""
        pref, _ = UserPreference.objects.get_or_create(user=self.user, defaults={"preferences": {}})
        pref.preferences[PREF_DATATABLES_DISPLAY] = DATATABLES_DISPLAY_SCROLLER
        pref.save()
        pref.refresh_from_db()
        self.assertEqual(pref.preferences.get(PREF_DATATABLES_DISPLAY), DATATABLES_DISPLAY_SCROLLER)


class UserPreferencesServiceTest(BaseTestCase):
    """Tests for get_user_preference, set_user_preference, get_datatables_display."""

    def test_get_user_preference_missing_returns_default(self):
        """When user has no UserPreference row, get_user_preference returns default."""
        self.assertEqual(
            get_user_preference(self.user, "nonexistent_key", default="fallback"),
            "fallback",
        )

    def test_set_and_get_user_preference(self):
        """set_user_preference creates/updates and get_user_preference reads."""
        set_user_preference(self.user, "test_key", "test_value")
        self.assertEqual(get_user_preference(self.user, "test_key"), "test_value")
        set_user_preference(self.user, "test_key", "updated")
        self.assertEqual(get_user_preference(self.user, "test_key"), "updated")

    def test_get_datatables_display_default_classic(self):
        """get_datatables_display returns classic when not set."""
        self.assertEqual(get_datatables_display(self.user), DATATABLES_DISPLAY_CLASSIC)

    def test_get_datatables_display_returns_scroller_when_set(self):
        """get_datatables_display returns scroller when user chose scroller."""
        set_user_preference(self.user, PREF_DATATABLES_DISPLAY, DATATABLES_DISPLAY_SCROLLER)
        self.assertEqual(get_datatables_display(self.user), DATATABLES_DISPLAY_SCROLLER)

    def test_get_datatables_display_returns_classic_when_set(self):
        """get_datatables_display returns classic when explicitly set."""
        set_user_preference(self.user, PREF_DATATABLES_DISPLAY, DATATABLES_DISPLAY_CLASSIC)
        self.assertEqual(get_datatables_display(self.user), DATATABLES_DISPLAY_CLASSIC)

    def test_get_datatables_display_invalid_value_falls_back_to_classic(self):
        """Invalid stored value falls back to classic."""
        set_user_preference(self.user, PREF_DATATABLES_DISPLAY, "invalid")
        self.assertEqual(get_datatables_display(self.user), DATATABLES_DISPLAY_CLASSIC)

    def test_get_user_preference_anonymous_returns_default(self):
        """Anonymous user gets default for any preference."""
        from django.contrib.auth.models import AnonymousUser

        anon = AnonymousUser()
        self.assertEqual(
            get_user_preference(anon, PREF_DATATABLES_DISPLAY, default="classic"),
            "classic",
        )

    def test_set_user_preference_anonymous_no_op(self):
        """set_user_preference on anonymous user does nothing."""
        from django.contrib.auth.models import AnonymousUser

        anon = AnonymousUser()
        set_user_preference(anon, PREF_DATATABLES_DISPLAY, DATATABLES_DISPLAY_SCROLLER)
        self.assertEqual(UserPreference.objects.count(), 0)

    def test_get_datatables_page_length_default(self):
        """get_datatables_page_length returns default when not set."""
        self.assertEqual(get_datatables_page_length(self.user), DATATABLES_PAGE_LENGTH_DEFAULT)

    def test_get_datatables_page_length_returns_set_value(self):
        """get_datatables_page_length returns user choice when set."""
        set_user_preference(self.user, PREF_DATATABLES_PAGE_LENGTH, 100)
        self.assertEqual(get_datatables_page_length(self.user), 100)

    def test_get_datatables_page_length_invalid_falls_back_to_default(self):
        """Invalid stored value falls back to default."""
        set_user_preference(self.user, PREF_DATATABLES_PAGE_LENGTH, 999)
        self.assertEqual(get_datatables_page_length(self.user), DATATABLES_PAGE_LENGTH_DEFAULT)

    def test_get_datatables_page_length_anonymous_returns_default(self):
        """Anonymous user gets default page length."""
        from django.contrib.auth.models import AnonymousUser

        anon = AnonymousUser()
        self.assertEqual(get_datatables_page_length(anon), DATATABLES_PAGE_LENGTH_DEFAULT)
