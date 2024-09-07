import logging

from utils.test_utils import TestDataGenerator
from django.test import TestCase, Client
from django.contrib.auth import get_user_model

from dashboard.views import on_user_logged_in

class BaseTestCase(TestCase):
    """
    Base test case for all API tests.
    Sets up common fixtures and mocks the user login process.
    """

    fixtures = [
        "dashboard.json",
        "targetApp.json",
        "scanEngine.json",
        "startScan.json",
        "recon_note.json",
        "fixtures/auth.json",
        "fixtures/django_celery_beat.json",
    ]

    def setUp(self):
        self.client = Client()
        user = get_user_model()
        self.user = user.objects.get(username="rengine")

        # Save original on_user_logged_in function
        self.original_on_user_logged_in = on_user_logged_in

        # Replace on_user_logged_in with a mock function
        def mock_on_user_logged_in(sender, request, **kwargs):
            pass

        on_user_logged_in.__code__ = mock_on_user_logged_in.__code__

        # Login
        self.client.force_login(self.user)

        # Ensure the session is saved after login
        self.client.session.save()

        # Create test data
        self.data_generator = TestDataGenerator()

        # Disable logging for tests
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        # Restore original on_user_logged_in function
        on_user_logged_in.__code__ = self.original_on_user_logged_in.__code__

