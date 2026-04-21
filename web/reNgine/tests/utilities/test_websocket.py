"""
Tests for WebSocket utilities, including Redis transient-error retry in channel group_send,
throttle/force behavior, and light vs full payload shape for UI consumption.
"""

import time
from unittest.mock import MagicMock, patch

from django.test import TestCase

from reNgine.utilities.websocket import (
    _channel_group_send_with_retry,
    build_light_scan_status_message,
    build_scan_status_message,
    send_scan_status_update,
)
from startScan.models import ScanHistory
from utils.test_base import BaseTestCase


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


class TestSendScanStatusThrottleAndForce(BaseTestCase):
    """Throttle skips second send; force=True bypasses throttle and sends full payload."""

    def setUp(self):
        super().setUp()
        self.scan_history = self.data_generator.create_scan_history()
        self.scan_id = self.scan_history.id

    def test_throttle_skips_second_send(self):
        """Two send_scan_status_update calls within throttle window: only first sends."""
        channel_mock = MagicMock()
        call_count = [0]

        def get_last_sent_ts_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return None
            return time.time() - 1.0

        with patch("reNgine.utilities.websocket.get_channel_layer", return_value=channel_mock):
            with patch("reNgine.utilities.websocket._get_last_sent_ts", side_effect=get_last_sent_ts_side_effect):
                with patch("reNgine.utilities.websocket._set_last_sent_ts"):
                    with patch("reNgine.utilities.websocket._get_last_full_ts", return_value=None):
                        with patch("reNgine.utilities.websocket._set_last_full_ts"):
                            with patch("reNgine.utilities.websocket._THROTTLE_SECONDS", 2):
                                with patch(
                                    "reNgine.utilities.websocket.async_to_sync",
                                    side_effect=lambda f: lambda *a, **kw: f(*a, **kw),
                                ):
                                    send_scan_status_update(self.scan_id)
                                    send_scan_status_update(self.scan_id)
        self.assertEqual(channel_mock.group_send.call_count, 2)

    def test_force_true_sends_immediately(self):
        """Second call with force=True sends even within throttle window."""
        channel_mock = MagicMock()
        with patch("reNgine.utilities.websocket.get_channel_layer", return_value=channel_mock):
            with patch("reNgine.utilities.websocket._get_last_sent_ts", side_effect=[None, time.time() - 0.5]):
                with patch("reNgine.utilities.websocket._set_last_sent_ts"):
                    with patch("reNgine.utilities.websocket._get_last_full_ts", return_value=None):
                        with patch("reNgine.utilities.websocket._set_last_full_ts"):
                            with patch("reNgine.utilities.websocket._THROTTLE_SECONDS", 2):
                                with patch(
                                    "reNgine.utilities.websocket.async_to_sync",
                                    side_effect=lambda f: lambda *a, **kw: f(*a, **kw),
                                ):
                                    send_scan_status_update(self.scan_id)
                                    send_scan_status_update(self.scan_id, force=True)
        self.assertEqual(channel_mock.group_send.call_count, 4)


class TestScanStatusPayloadShape(BaseTestCase):
    """Light and full payloads have keys expected by the UI (table, detail, sidebar, commands, timeline, subscans)."""

    def setUp(self):
        super().setUp()
        self.scan_history = self.data_generator.create_scan_history()
        self.scan_id = self.scan_history.id

    def test_light_payload_has_required_ui_fields_and_no_heavy_fields(self):
        """Light payload has scan_id, status, progress, current_task, counts; no commands, timeline, runners, subscans."""
        result = build_light_scan_status_message(self.scan_id)
        self.assertIsInstance(result, dict)
        self.assertIn("scan_id", result)
        self.assertIn("status", result)
        self.assertIn("progress", result)
        self.assertIn("current_task", result)
        self.assertIn("scan_type", result)
        self.assertIn("scan_name", result)
        scan = ScanHistory.objects.get(id=self.scan_id)
        self.assertEqual(result["scan_name"], scan.scan_engine_used)
        self.assertIn("domain_count", result)
        self.assertIn("subdomain_count", result)
        self.assertIn("endpoint_count", result)
        self.assertIn("vulnerability_count", result)
        self.assertIn("ip_address_count", result)
        self.assertIn("ip_alive_count", result)
        self.assertNotIn("commands", result)
        self.assertNotIn("timeline", result)
        self.assertNotIn("runners", result)
        self.assertNotIn("subscans", result)

    def test_full_payload_has_heavy_fields_for_ui(self):
        """Full payload includes commands, timeline or runners, and subscans for logs/detail/sidebar."""
        result = build_scan_status_message(self.scan_id)
        self.assertIsInstance(result, dict)
        self.assertIn("scan_id", result)
        self.assertIn("status", result)
        self.assertIn("progress", result)
        self.assertIn("current_task", result)
        self.assertIn("commands", result)
        self.assertIsInstance(result["commands"], list)
        self.assertIn("subscans", result)
        self.assertIsInstance(result["subscans"], list)
        self.assertTrue("timeline" in result or "runners" in result)
