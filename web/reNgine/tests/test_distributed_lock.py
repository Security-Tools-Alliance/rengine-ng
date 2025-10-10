"""
Simplified tests for distributed lock utilities.

This module provides basic unit tests for the distributed lock utilities
focusing on creation and basic functionality.
"""

import unittest
from unittest.mock import Mock, patch

from reNgine.utilities.distributed.lock import (
    DistributedLock,
    DistributedLockManager,
    acquire_lock,
    get_distributed_lock_manager,
    get_redis_connection,
    release_lock,
    with_distributed_lock,
)
from utils.test_base import BaseTestCase


class TestDistributedLock(BaseTestCase):
    """Test DistributedLock class."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.lock_key = "test_lock"
        self.lock = DistributedLock(self.lock_key)

    def test_lock_creation(self):
        """Test lock creation."""
        # The lock key is hashed, so we just check it starts with the prefix
        self.assertTrue(self.lock.lock_key.startswith("distributed_lock:"))
        self.assertEqual(self.lock.timeout, 30)
        self.assertEqual(self.lock.blocking_timeout, 5)
        self.assertFalse(self.lock.acquired)
        self.assertIsNone(self.lock._redis_client)

    def test_lock_creation_with_custom_timeouts(self):
        """Test lock creation with custom timeouts."""
        lock = DistributedLock("custom_lock", timeout=60, blocking_timeout=10)

        self.assertEqual(lock.timeout, 60)
        self.assertEqual(lock.blocking_timeout, 10)

    def test_context_manager(self):
        """Test lock as context manager."""
        with patch("reNgine.utilities.distributed.lock.get_redis_connection") as mock_redis:
            mock_redis.return_value = Mock()
            mock_redis.return_value.set.return_value = True
            mock_redis.return_value.delete.return_value = True

            with self.lock as lock:
                self.assertTrue(lock.acquired)

    def test_acquire_lock_success(self):
        """Test successful lock acquisition."""
        with patch("reNgine.utilities.distributed.lock.get_redis_connection") as mock_redis:
            mock_redis.return_value = Mock()
            mock_redis.return_value.set.return_value = True

            result = self.lock.acquire()

            self.assertTrue(result)
            self.assertTrue(self.lock.acquired)

    def test_acquire_lock_failure(self):
        """Test failed lock acquisition."""
        with patch("reNgine.utilities.distributed.lock.get_redis_connection") as mock_redis:
            mock_redis.return_value = Mock()
            mock_redis.return_value.set.return_value = False

            result = self.lock.acquire()

            self.assertFalse(result)
            self.assertFalse(self.lock.acquired)

    def test_release_lock(self):
        """Test lock release."""
        with patch("reNgine.utilities.distributed.lock.get_redis_connection") as mock_redis:
            mock_redis.return_value = Mock()
            mock_redis.return_value.set.return_value = True
            mock_redis.return_value.delete.return_value = True

            # Acquire lock first
            self.lock.acquire()
            self.assertTrue(self.lock.acquired)

            # Release lock
            self.lock.release()
            self.assertFalse(self.lock.acquired)

    def test_execute_with_lock_success(self):
        """Test execute_with_lock with successful acquisition."""
        with patch("reNgine.utilities.distributed.lock.get_redis_connection") as mock_redis:
            mock_redis.return_value = Mock()
            mock_redis.return_value.set.return_value = True
            mock_redis.return_value.delete.return_value = True

            def protected_operation():
                return "success"

            result = self.lock.execute_with_lock(protected_operation)

            self.assertEqual(result, "success")

    def test_execute_with_lock_fallback(self):
        """Test execute_with_lock with fallback operation."""
        with patch("reNgine.utilities.distributed.lock.get_redis_connection") as mock_redis:
            mock_redis.return_value = Mock()
            mock_redis.return_value.set.return_value = False  # Lock acquisition fails

            def protected_operation():
                return "protected"

            def fallback_operation():
                return "fallback"

            result = self.lock.execute_with_lock(protected_operation, fallback_operation)

            self.assertEqual(result, "fallback")


class TestDistributedLockManager(BaseTestCase):
    """Test DistributedLockManager class."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.manager = DistributedLockManager()

    def test_manager_creation(self):
        """Test lock manager creation."""
        self.assertIsInstance(self.manager.active_locks, dict)
        self.assertEqual(len(self.manager.active_locks), 0)

    def test_acquire_lock(self):
        """Test acquiring lock through manager."""
        lock = self.manager.acquire("test_lock")

        self.assertIsInstance(lock, DistributedLock)
        self.assertIn("test_lock", self.manager.active_locks)

    def test_release_lock(self):
        """Test releasing lock through manager."""
        lock = self.manager.acquire("test_lock")

        with patch.object(lock, "release") as mock_release:
            mock_release.return_value = True

            result = self.manager.release("test_lock")

            self.assertTrue(result)
            self.assertNotIn("test_lock", self.manager.active_locks)

    def test_release_nonexistent_lock(self):
        """Test releasing nonexistent lock."""
        result = self.manager.release("nonexistent_lock")

        self.assertFalse(result)

    def test_release_all_locks(self):
        """Test releasing all locks."""
        lock1 = self.manager.acquire("lock1")
        lock2 = self.manager.acquire("lock2")

        with patch.object(lock1, "release") as mock_release1, patch.object(lock2, "release") as mock_release2:
            mock_release1.return_value = True
            mock_release2.return_value = True

            released_count = self.manager.release_all()

            self.assertEqual(released_count, 2)
            self.assertEqual(len(self.manager.active_locks), 0)


class TestDistributedLockUtilityFunctions(BaseTestCase):
    """Test distributed lock utility functions."""

    def test_get_redis_connection(self):
        """Test get_redis_connection function."""
        with patch("redis.ConnectionPool"), patch("redis.Redis") as mock_redis:
            mock_redis.return_value = Mock()

            result = get_redis_connection()

            self.assertIsNotNone(result)

    def test_get_redis_connection_failure(self):
        """Test get_redis_connection function with failure."""
        # Reset the global pool to None first
        import reNgine.utilities.distributed.lock as lock_module

        lock_module._redis_pool = None

        with patch("redis.ConnectionPool", side_effect=Exception("Connection failed")):
            result = get_redis_connection()

            self.assertIsNone(result)

    def test_acquire_lock_function(self):
        """Test acquire_lock function."""
        lock = acquire_lock("test_lock", timeout=60, blocking_timeout=10)

        self.assertIsInstance(lock, DistributedLock)
        self.assertEqual(lock.timeout, 60)
        self.assertEqual(lock.blocking_timeout, 10)

    def test_release_lock_function(self):
        """Test release_lock function."""
        with patch("reNgine.utilities.distributed.lock.DistributedLock") as mock_lock_class:
            mock_lock = Mock()
            mock_lock.release.return_value = True
            mock_lock_class.return_value = mock_lock

            result = release_lock("test_lock")

            self.assertTrue(result)
            mock_lock.release.assert_called_once()

    def test_get_distributed_lock_manager(self):
        """Test get_distributed_lock_manager function."""
        manager = get_distributed_lock_manager()

        self.assertIsInstance(manager, DistributedLockManager)

    def test_with_distributed_lock_decorator(self):
        """Test with_distributed_lock decorator."""

        @with_distributed_lock(lambda x: f"lock_{x}")
        def test_function(value):
            return f"processed_{value}"

        with patch("reNgine.utilities.distributed.lock.get_redis_connection") as mock_redis:
            mock_redis.return_value = Mock()
            mock_redis.return_value.set.return_value = True
            mock_redis.return_value.delete.return_value = True

            result = test_function("test")

            self.assertEqual(result, "processed_test")


class TestDistributedLockStaticMethods(BaseTestCase):
    """Test DistributedLock static methods."""

    def test_safe_get_or_create_with_lock(self):
        """Test safe_get_or_create_with_lock static method."""
        from django.db import models

        # Create a simple test model
        class TestModel(models.Model):
            name = models.CharField(max_length=100, unique=True)
            value = models.IntegerField(default=0)

            class Meta:
                app_label = "test"

        with patch("reNgine.utilities.distributed.lock.get_redis_connection") as mock_redis:
            mock_redis.return_value = Mock()
            mock_redis.return_value.set.return_value = True
            mock_redis.return_value.delete.return_value = True

            with (
                patch.object(TestModel.objects, "filter") as mock_filter,
                patch.object(TestModel.objects, "create") as mock_create,
            ):
                mock_filter.return_value.first.return_value = None
                mock_create.return_value = Mock(id=1, name="test", _was_created=True)

                result = DistributedLock.safe_get_or_create_with_lock(
                    TestModel, "test_lock", {"name": "test"}, {"name": "test", "value": 42}
                )

                self.assertIsNotNone(result)
                self.assertTrue(hasattr(result, "_was_created"))


if __name__ == "__main__":
    unittest.main()
