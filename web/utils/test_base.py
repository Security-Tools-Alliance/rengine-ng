from utils.test_utils import TestDataGenerator, TestValidation
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from dashboard.views import on_user_logged_in
from reNgine.utils.logger import Logger

__all__ = [
    'BaseTestCase',
]

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
        self.test_validation = TestValidation()

        # Disable logging for tests
        Logger.disable_logging()

    def tearDown(self):
        # Restore original on_user_logged_in function
        on_user_logged_in.__code__ = self.original_on_user_logged_in.__code__
        
        # Re-enable logging
        Logger.enable_logging()
