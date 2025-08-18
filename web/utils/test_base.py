import logging

from utils.test_utils import TestDataGenerator, TestValidation
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from dashboard.views import on_user_logged_in

__all__ = [
    'BaseTestCase',
]

class BaseTestCase(TestCase):
    """
    Base test case for all API tests.
    Uses programmatic test data creation only - no more fixtures!
    """
    
    def setUp(self):
        self.client = Client()
        
        # Create test data generator first
        self.data_generator = TestDataGenerator()
        self.test_validation = TestValidation()
        
        # Create minimal auth setup (user and permissions)
        self.user = self.data_generator.create_minimal_auth_setup()
        
        # Save original on_user_logged_in function
        self.original_on_user_logged_in = on_user_logged_in
        
        # Replace on_user_logged_in with a mock function
        def mock_on_user_logged_in(sender, request, **kwargs):
            pass
        
        on_user_logged_in.__code__ = mock_on_user_logged_in.__code__
        
        # Login the user
        self.client.force_login(self.user)
        
        # Ensure the session is saved after login
        self.client.session.save()
        
        # Create essential scan engine setup
        self.data_generator.create_essential_scan_engine_setup()
        
        # Create minimal celery setup
        self.data_generator.create_minimal_celery_setup()
        
        # Create full project setup by default to avoid foreign key issues
        # Tests can override this behavior by setting self.use_full_setup = False in setUp()
        if not getattr(self, 'use_minimal_setup', False):
            self.data_generator.create_project_full()
        
        # Disable logging for tests
        logging.disable(logging.CRITICAL)
    
    def tearDown(self):
        """Clean up after tests."""
        # Restore original on_user_logged_in function
        on_user_logged_in.__code__ = self.original_on_user_logged_in.__code__
