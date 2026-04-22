"""
Tests for worker WebSocket channel group name helpers.
"""

from django.test import TestCase

from reNgine.utilities.worker_ws_groups import worker_deploy_group, worker_refresh_group


class TestWorkerWsGroups(TestCase):
    """worker_deploy_group and worker_refresh_group return consistent names."""

    def test_worker_deploy_group_format(self):
        """worker_deploy_group(worker_id) returns worker-deploy-{id}."""
        self.assertEqual(worker_deploy_group(1), "worker-deploy-1")
        self.assertEqual(worker_deploy_group(42), "worker-deploy-42")

    def test_worker_refresh_group_format(self):
        """worker_refresh_group(worker_id) returns worker-refresh-{id}."""
        self.assertEqual(worker_refresh_group(1), "worker-refresh-1")
        self.assertEqual(worker_refresh_group(99), "worker-refresh-99")
