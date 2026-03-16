"""
Tests for WebSocket utilities, including Redis transient-error retry in channel group_send.
"""

from unittest.mock import MagicMock, patch

from django.test import TestCase

from reNgine.utilities.websocket import _channel_group_send_with_retry


def _redis_exceptions():
    """Import redis exceptions if available; skip tests if not."""
    try:
        from redis.exceptions import (
            BusyLoadingError,
        )
        from redis.exceptions import (
            ConnectionError as RedisConnectionError,
        )
        from redis.exceptions import (
            TimeoutError as RedisTimeoutError,
        )

        return BusyLoadingError, RedisConnectionError, RedisTimeoutError
    except ImportError:
        return None, None, None


class TestChannelGroupSendWithRetry(TestCase):
    """_channel_group_send_with_retry retries on Redis transient errors and does not raise after exhaustion."""

    def setUp(self):
        super().setUp()
        self.channel_layer = MagicMock()
        # Make async_to_sync a no-op so we can use sync mocks
        self._async_to_sync_patcher = patch(
            "reNgine.utilities.websocket.async_to_sync",
            side_effect=lambda f: lambda *a, **kw: f(*a, **kw),
        )
        self._async_to_sync_patcher.start()
        self._sleep_patcher = patch("reNgine.utilities.websocket.time.sleep")
        self._sleep_patcher.start()

    def tearDown(self):
        self._sleep_patcher.stop()
        self._async_to_sync_patcher.stop()
        super().tearDown()

    def test_success_on_first_call(self):
        """First group_send succeeds; no retry and no exception."""
        self.channel_layer.group_send = MagicMock(return_value=None)
        _channel_group_send_with_retry(
            self.channel_layer,
            "test-group",
            {"type": "test", "payload": {}},
        )
        self.channel_layer.group_send.assert_called_once_with(
            "test-group",
            {"type": "test", "payload": {}},
        )

    def test_busy_loading_error_then_success(self):
        """BusyLoadingError on first call, success on second; one retry then succeeds."""
        busy_loading_error, _, _ = _redis_exceptions()
        if busy_loading_error is None:
            self.skipTest("redis not installed")
        self.channel_layer.group_send = MagicMock(
            side_effect=[busy_loading_error("Redis is loading the dataset in memory"), None],
        )
        _channel_group_send_with_retry(
            self.channel_layer,
            "scan-status-1",
            {"type": "scan_status_update", "message": {}},
        )
        self.assertEqual(self.channel_layer.group_send.call_count, 2)

    def test_connection_error_exhausted_does_not_raise(self):
        """ConnectionError on every attempt; after retries exhausted, return without raising."""
        _, redis_connection_error, _ = _redis_exceptions()
        if redis_connection_error is None:
            self.skipTest("redis not installed")
        self.channel_layer.group_send = MagicMock(
            side_effect=redis_connection_error("Connection reset by peer"),
        )
        _channel_group_send_with_retry(
            self.channel_layer,
            "worker-status",
            {"type": "worker_status_update", "payload": {"worker_id": 1}},
        )
        # 1 initial + 3 retries (delays 2, 5, 10)
        self.assertEqual(self.channel_layer.group_send.call_count, 4)

    def test_busy_loading_error_exhausted_does_not_raise(self):
        """BusyLoadingError on every attempt; after retries exhausted, return without raising."""
        busy_loading_error, _, _ = _redis_exceptions()
        if busy_loading_error is None:
            self.skipTest("redis not installed")
        self.channel_layer.group_send = MagicMock(
            side_effect=busy_loading_error("Redis is loading the dataset in memory"),
        )
        _channel_group_send_with_retry(
            self.channel_layer,
            "scan-status-99",
            {"type": "scan_status_update", "message": {}},
        )
        self.assertEqual(self.channel_layer.group_send.call_count, 4)

    def test_non_transient_exception_propagates(self):
        """Non-Redis exception (e.g. ValueError) propagates; no retry."""
        self.channel_layer.group_send = MagicMock(side_effect=ValueError("bad payload"))
        with self.assertRaises(ValueError):
            _channel_group_send_with_retry(
                self.channel_layer,
                "test-group",
                {"type": "test"},
            )
        self.channel_layer.group_send.assert_called_once()
