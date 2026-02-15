"""
API Key Generator utility for Secator workers.
Generates system API keys that cannot be deleted through the UI.
"""

from typing import Tuple

from django.contrib.auth import get_user_model
from django.db import transaction

from dashboard.models import UserAPIKey
from reNgine.utilities.logger import get_module_logger

PREFIX_API_KEY = "[API_KEY]"
logger = get_module_logger(__name__)
User = get_user_model()


def generate_secator_api_key(recreate: bool = False) -> Tuple[str, bool]:
    """
    Generate or retrieve the system API key for Secator workers.

    This function creates a system user account and associated API key
    that will be used by all Secator workers to authenticate with the reNgine API.

    Args:
        recreate: If True, delete existing key and create a new one

    Returns:
        Tuple[str, bool]: (api_key, was_created)
            - api_key: The API key string
            - was_created: True if a new key was created, False if existing key was returned

    Raises:
        Exception: If key generation fails
    """
    username = "secator-worker"
    key_name = "Secator Worker System Key"

    try:
        with transaction.atomic():
            # Get or create system user
            user, user_created = User.objects.get_or_create(
                username=username,
                defaults={
                    "email": "secator@rengine.local",
                    "is_active": True,
                    "is_staff": False,
                    "is_superuser": False,
                },
            )

            if user_created:
                # Set unusable password for system user (no login allowed)
                user.set_unusable_password()
                user.save()
                logger.log_line(
                    PREFIX_API_KEY,
                    "USER",
                    "Created system user: %s" % (username,),
                    level="info",
                )
            else:
                logger.log_line(
                    PREFIX_API_KEY,
                    "USER",
                    "System user already exists: %s" % (username,),
                    level="info",
                )

            # Check for existing system API key
            existing_key = UserAPIKey.objects.filter(user=user, name=key_name, is_system=True).first()

            if existing_key and not recreate:
                logger.log_line(
                    PREFIX_API_KEY,
                    "KEY",
                    "System API key already exists, returning existing key",
                    level="info",
                )
                # Return the existing key (note: we can't retrieve the actual key value from the hash)
                # So we need to inform the user to use the management command with --show-key option
                return (None, False)

            if existing_key and recreate:
                logger.log_line(
                    PREFIX_API_KEY,
                    "KEY",
                    "Deleting existing system API key for recreation",
                    level="warning",
                )
                existing_key.delete()

            # Generate new API key
            api_key, key = UserAPIKey.objects.create_key(
                user=user,
                name=key_name,
            )

            # Mark as system key
            api_key.is_system = True
            api_key.save(update_fields=["is_system"])

            logger.log_line(
                PREFIX_API_KEY,
                "KEY",
                "Generated new system API key: %s" % (key_name,),
                level="info",
            )
            return (key, True)

    except Exception as e:
        logger.log_line(
            PREFIX_API_KEY,
            "KEY",
            "Failed to generate system API key: %s" % (e,),
            level="error",
        )
        raise


def get_secator_user() -> User:
    """
    Get the Secator system user.

    Returns:
        User: The Secator system user

    Raises:
        User.DoesNotExist: If the system user doesn't exist
    """
    return User.objects.get(username="secator-worker")


def has_secator_api_key() -> bool:
    """
    Check if a Secator system API key exists.

    Returns:
        bool: True if system API key exists, False otherwise
    """
    try:
        user = get_secator_user()
        return UserAPIKey.objects.filter(user=user, is_system=True).exists()
    except User.DoesNotExist:
        return False
