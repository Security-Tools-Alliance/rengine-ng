"""
Tests for Secator service functionality.
"""

from unittest.mock import MagicMock, Mock, patch

from reNgine.definitions import ABORTED_TASK, FAILED_TASK, INITIATED_TASK, RUNNING_TASK, SUCCESS_TASK
from reNgine.secator.service import (
    _persist_scan_config_on_history,
    handle_scan_error,
    run_per_task_secator_scans,
    start_secator_scan,
)
from startScan.models import ScanHistory
from utils.test_base import BaseTestCase


class TestSecatorService(BaseTestCase):
    """Test cases for Secator service."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.scan_history = self.data_generator.create_scan_history()
        self.domain = self.data_generator.create_domain(scan_history=self.scan_history)

    def test_handle_scan_error_sets_failed_status(self):
        """Test that handle_scan_error sets scan status to FAILED_TASK."""
        self.scan_history.scan_status = RUNNING_TASK
        self.scan_history.save()

        error = Exception("Test error")
        handle_scan_error(self.scan_history, error)

        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_status, FAILED_TASK)

    def test_handle_scan_error_skips_when_already_success(self):
        """Test that handle_scan_error skips update when scan is already SUCCESS."""
        self.scan_history.scan_status = SUCCESS_TASK
        self.scan_history.save()

        error = Exception("Test error")
        handle_scan_error(self.scan_history, error)

        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_status, SUCCESS_TASK)

    def test_handle_scan_error_skips_when_already_failed(self):
        """Test that handle_scan_error skips update when scan is already FAILED."""
        self.scan_history.scan_status = FAILED_TASK
        self.scan_history.save()

        error = Exception("Test error")
        handle_scan_error(self.scan_history, error)

        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_status, FAILED_TASK)

    def test_handle_scan_error_skips_when_already_aborted(self):
        """Test that handle_scan_error skips update when scan is already ABORTED."""
        self.scan_history.scan_status = ABORTED_TASK
        self.scan_history.save()

        error = Exception("Test error")
        handle_scan_error(self.scan_history, error)

        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_status, ABORTED_TASK)

    def test_handle_scan_error_updates_from_initiated(self):
        """Test that handle_scan_error updates scan from INITIATED status."""
        self.scan_history.scan_status = INITIATED_TASK
        self.scan_history.save()

        error = Exception("Test error")
        handle_scan_error(self.scan_history, error)

        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_status, FAILED_TASK)

    def test_handle_scan_error_updates_from_running(self):
        """Test that handle_scan_error updates scan from RUNNING status."""
        self.scan_history.scan_status = RUNNING_TASK
        self.scan_history.save()

        error = Exception("Test error")
        handle_scan_error(self.scan_history, error)

        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_status, FAILED_TASK)

    @patch("reNgine.secator.service.logger")
    def test_handle_scan_error_logs_error(self, mock_logger):
        """Test that handle_scan_error logs the error via log_line."""
        self.scan_history.scan_status = RUNNING_TASK
        self.scan_history.save()

        error = Exception("Test error message")
        handle_scan_error(self.scan_history, error)

        mock_logger.log_line.assert_called()
        error_calls = [
            c
            for c in mock_logger.log_line.call_args_list
            if c[1].get("level") == "error" and c[1].get("exc_info") is True
        ]
        self.assertEqual(len(error_calls), 1)
        self.assertIn("Test error message", str(error_calls[0]))

    @patch("reNgine.secator.service.logger")
    def test_handle_scan_error_logs_debug_when_terminal(self, mock_logger):
        """Test that handle_scan_error logs debug when scan is already in terminal state."""
        self.scan_history.scan_status = SUCCESS_TASK
        self.scan_history.save()

        error = Exception("Test error")
        handle_scan_error(self.scan_history, error)

        mock_logger.log_line.assert_called()
        debug_calls = [c for c in mock_logger.log_line.call_args_list if c[1].get("level") == "debug"]
        self.assertEqual(len(debug_calls), 1)
        self.assertIn("terminal state", str(debug_calls[0]).lower())

    def test_handle_scan_error_refreshes_from_db(self):
        """Test that handle_scan_error refreshes scan from database before checking status."""
        self.scan_history.scan_status = RUNNING_TASK
        self.scan_history.save()

        # Manually change status in DB to simulate race condition
        from startScan.models import ScanHistory

        ScanHistory.objects.filter(id=self.scan_history.id).update(scan_status=SUCCESS_TASK)

        error = Exception("Test error")
        handle_scan_error(self.scan_history, error)

        # Should skip update because refresh_from_db detected SUCCESS status
        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_status, SUCCESS_TASK)

    @patch("reNgine.secator.service.threading.Thread")
    def test_start_secator_scan_passes_targets_override_to_initiate(self, mock_thread):
        """Test that start_secator_scan passes targets_override to initiate_secator_scan."""
        mock_scan_repo = Mock()
        mock_scan_repo.create_scan.return_value = self.scan_history.id

        def run_target_and_return_mock(*args, **kwargs):
            kwargs.get("target", lambda: None)()
            return Mock()

        mock_thread.side_effect = run_target_and_return_mock

        with patch("reNgine.secator.service.ScanRepository", return_value=mock_scan_repo):
            with patch("reNgine.secator.service.ScanHistory.objects.get", return_value=self.scan_history):
                with patch("reNgine.secator.service.initiate_secator_scan") as mock_initiate:
                    result = start_secator_scan(
                        target_id=self.scan_history.target_id,
                        user_id=self.user.id,
                        execution_mode="tasks",
                        task_ids=[1],
                        targets_override=["host1.example.com", "host2.example.com"],
                    )
                    self.assertTrue(result.get("status"))
                    self.assertEqual(result.get("target_name"), self.data_generator.target.value)
                    self.assertNotIn("domain_id", result)
                    self.assertNotIn("domain_name", result)
                    mock_initiate.assert_called_once()
                    call_kwargs = mock_initiate.call_args[1]
                    self.assertEqual(
                        call_kwargs.get("targets_override"),
                        ["host1.example.com", "host2.example.com"],
                    )

    @patch("reNgine.secator.service.threading.Thread")
    def test_start_secator_scan_with_scan_history_id_reuses_existing_scan(self, mock_thread):
        """When scan_history_id is provided, no new scan is created and thread uses that id."""
        self.scan_history.target_id = self.data_generator.target.id
        self.scan_history.save()

        def run_target_and_return_mock(*args, **kwargs):
            kwargs.get("target", lambda: None)()
            return Mock()

        mock_thread.side_effect = run_target_and_return_mock

        with patch("reNgine.secator.service.ScanHistory.objects.get", return_value=self.scan_history):
            with patch("reNgine.secator.service.initiate_secator_scan") as mock_initiate:
                result = start_secator_scan(
                    target_id=self.scan_history.target_id,
                    user_id=self.user.id,
                    execution_mode="tasks",
                    task_ids=[1],
                    targets_override=["host1.example.com"],
                    scan_history_id=self.scan_history.id,
                )
                self.assertTrue(result.get("status"))
                self.assertEqual(result.get("scan_id"), self.scan_history.id)
                self.assertEqual(result.get("target_name"), self.data_generator.target.value)
                self.assertNotIn("domain_id", result)
                self.assertNotIn("domain_name", result)
                mock_initiate.assert_called_once()
                self.assertEqual(mock_initiate.call_args[1]["scan_history_id"], self.scan_history.id)
                self.assertEqual(mock_initiate.call_args[1]["task_ids"], [1])


class TestRunPerTaskSecatorScans(BaseTestCase):
    """Test cases for run_per_task_secator_scans."""

    def setUp(self):
        super().setUp()
        self.scan_history = self.data_generator.create_scan_history()
        self.domain = self.data_generator.create_domain(scan_history=self.scan_history)
        self.task = self.data_generator.create_secator_task()
        self.task_type_to_id = {self.task.task_type: self.task.id}

    @patch("reNgine.secator.service.ScanHistory.objects.get")
    @patch("reNgine.secator.service.start_secator_scan")
    @patch("reNgine.secator.service.ScanRepository")
    def test_valid_tasks_all_succeed(self, mock_scan_repo_cls, mock_start, mock_scan_get):
        """When selected_targets_per_task is valid, one ScanHistory is created and shared."""
        shared_scan_id = 123
        mock_scan_repo_cls.return_value.create_scan.return_value = shared_scan_id
        mock_scan_get.return_value = MagicMock(id=shared_scan_id)
        mock_start.return_value = {"status": True, "scan_id": shared_scan_id}
        selected = {self.task.task_type: ["host1.example.com"]}
        result = run_per_task_secator_scans(
            target_id=self.scan_history.target_id,
            user_id=self.user.id,
            selected_targets_per_task=selected,
            task_type_to_id=self.task_type_to_id,
        )
        self.assertEqual(result["validation_errors"], [])
        self.assertEqual(result["success_count"], 1)
        self.assertEqual(result["failed_count"], 0)
        self.assertEqual(result["scan_id"], shared_scan_id)
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["task_type"], self.task.task_type)
        self.assertEqual(result["results"][0]["status"], "success")
        self.assertEqual(result["results"][0]["scan_id"], shared_scan_id)
        mock_start.assert_called_once()
        self.assertEqual(mock_start.call_args[1]["scan_history_id"], shared_scan_id)

    def test_unknown_task_type_fills_validation_errors_no_scan(self):
        """Unknown task_type yields validation_errors and no start_secator_scan call."""
        selected = {"unknown_task": ["host1.example.com"]}
        with patch("reNgine.secator.service.start_secator_scan") as mock_start:
            result = run_per_task_secator_scans(
                target_id=self.scan_history.target_id,
                user_id=self.user.id,
                selected_targets_per_task=selected,
                task_type_to_id=self.task_type_to_id,
            )
        self.assertEqual(len(result["validation_errors"]), 1)
        self.assertEqual(result["validation_errors"][0]["task_type"], "unknown_task")
        self.assertEqual(result["validation_errors"][0]["reason"], "unknown_task_type")
        self.assertEqual(result["success_count"], 0)
        self.assertEqual(result["failed_count"], 0)
        self.assertIsNone(result["scan_id"])
        self.assertEqual(result["results"], [])
        mock_start.assert_not_called()

    def test_empty_targets_fills_validation_errors_no_scan(self):
        """Task with empty targets yields validation_errors and no start_secator_scan call."""
        selected = {self.task.task_type: []}
        with patch("reNgine.secator.service.start_secator_scan") as mock_start:
            result = run_per_task_secator_scans(
                target_id=self.scan_history.target_id,
                user_id=self.user.id,
                selected_targets_per_task=selected,
                task_type_to_id=self.task_type_to_id,
            )
        self.assertEqual(len(result["validation_errors"]), 1)
        self.assertEqual(result["validation_errors"][0]["task_type"], self.task.task_type)
        self.assertEqual(result["validation_errors"][0]["reason"], "no_targets")
        self.assertEqual(result["success_count"], 0)
        self.assertEqual(result["failed_count"], 0)
        self.assertIsNone(result["scan_id"])
        self.assertEqual(result["results"], [])
        mock_start.assert_not_called()

    @patch("reNgine.secator.service.ScanHistory.objects.get")
    @patch("reNgine.secator.service.start_secator_scan")
    @patch("reNgine.secator.service.ScanRepository")
    def test_mix_valid_and_invalid_one_success_one_validation_error(
        self, mock_scan_repo_cls, mock_start, mock_scan_get
    ):
        """One valid task runs and succeeds; one unknown task only adds validation error."""
        shared_scan_id = 99
        mock_scan_repo_cls.return_value.create_scan.return_value = shared_scan_id
        mock_scan_get.return_value = MagicMock(id=shared_scan_id)
        mock_start.return_value = {"status": True, "scan_id": shared_scan_id}
        task2_type = "other_unknown"
        selected = {
            self.task.task_type: ["host1.example.com"],
            task2_type: ["host2.example.com"],
        }
        result = run_per_task_secator_scans(
            target_id=self.scan_history.target_id,
            user_id=self.user.id,
            selected_targets_per_task=selected,
            task_type_to_id=self.task_type_to_id,
        )
        self.assertEqual(len(result["validation_errors"]), 1)
        self.assertEqual(result["validation_errors"][0]["task_type"], task2_type)
        self.assertEqual(result["success_count"], 1)
        self.assertEqual(result["failed_count"], 0)
        self.assertEqual(result["scan_id"], shared_scan_id)
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["task_type"], self.task.task_type)
        self.assertEqual(result["results"][0]["status"], "success")
        self.assertEqual(result["results"][0]["scan_id"], shared_scan_id)
        mock_start.assert_called_once()
        self.assertEqual(mock_start.call_args[1]["scan_history_id"], shared_scan_id)

    @patch("reNgine.secator.service.ScanHistory.objects.get")
    @patch("reNgine.secator.service.start_secator_scan")
    @patch("reNgine.secator.service.ScanRepository")
    def test_start_returns_error_appends_error_result(self, mock_scan_repo_cls, mock_start, mock_scan_get):
        """When start_secator_scan returns status False, result has status error and failed_count increments."""
        shared_scan_id = 55
        mock_scan_repo_cls.return_value.create_scan.return_value = shared_scan_id
        mock_scan_get.return_value = MagicMock(id=shared_scan_id)
        mock_start.return_value = {"status": False, "error": "Domain not found"}
        selected = {self.task.task_type: ["host1.example.com"]}
        result = run_per_task_secator_scans(
            target_id=self.scan_history.target_id,
            user_id=self.user.id,
            selected_targets_per_task=selected,
            task_type_to_id=self.task_type_to_id,
        )
        self.assertEqual(result["validation_errors"], [])
        self.assertEqual(result["success_count"], 0)
        self.assertEqual(result["failed_count"], 1)
        self.assertEqual(result["scan_id"], shared_scan_id)
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["task_type"], self.task.task_type)
        self.assertEqual(result["results"][0]["status"], "error")
        self.assertEqual(result["results"][0]["error"], "Domain not found")

    @patch("reNgine.secator.service.ScanHistory.objects.get")
    @patch("reNgine.secator.service.start_secator_scan")
    @patch("reNgine.secator.service.ScanRepository")
    def test_start_raises_exception_appends_error_result(self, mock_scan_repo_cls, mock_start, mock_scan_get):
        """When start_secator_scan raises, result has status error and failed_count increments."""
        shared_scan_id = 66
        mock_scan_repo_cls.return_value.create_scan.return_value = shared_scan_id
        mock_scan_get.return_value = MagicMock(id=shared_scan_id)
        mock_start.side_effect = ValueError("Invalid config")
        selected = {self.task.task_type: ["host1.example.com"]}
        result = run_per_task_secator_scans(
            target_id=self.scan_history.target_id,
            user_id=self.user.id,
            selected_targets_per_task=selected,
            task_type_to_id=self.task_type_to_id,
        )
        self.assertEqual(result["validation_errors"], [])
        self.assertEqual(result["success_count"], 0)
        self.assertEqual(result["failed_count"], 1)
        self.assertEqual(result["scan_id"], shared_scan_id)
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["task_type"], self.task.task_type)
        self.assertEqual(result["results"][0]["status"], "error")
        self.assertIn("Invalid config", result["results"][0]["error"])

    @patch("reNgine.secator.service.ScanHistory.objects.get")
    @patch("reNgine.secator.service.start_secator_scan")
    @patch("reNgine.secator.service.ScanRepository")
    def test_loads_task_type_to_id_when_none(self, mock_scan_repo_cls, mock_start, mock_scan_get):
        """When task_type_to_id is None, it is loaded from SecatorTask."""
        shared_scan_id = 1
        mock_scan_repo_cls.return_value.create_scan.return_value = shared_scan_id
        mock_scan_get.return_value = MagicMock(id=shared_scan_id)
        mock_start.return_value = {"status": True, "scan_id": shared_scan_id}
        selected = {self.task.task_type: ["host.example.com"]}
        result = run_per_task_secator_scans(
            target_id=self.scan_history.target_id,
            user_id=self.user.id,
            selected_targets_per_task=selected,
            task_type_to_id=None,
        )
        self.assertEqual(result["success_count"], 1)
        self.assertEqual(result["scan_id"], shared_scan_id)
        self.assertEqual(len(result["results"]), 1)
        mock_start.assert_called_once()
        call_kwargs = mock_start.call_args[1]
        self.assertEqual(call_kwargs["task_ids"], [self.task.id])
        self.assertEqual(call_kwargs["scan_history_id"], shared_scan_id)

    @patch("reNgine.secator.service.start_secator_scan")
    @patch("reNgine.secator.service.ScanRepository")
    def test_reuses_scan_history_id_when_provided_and_valid(self, mock_scan_repo_cls, mock_start):
        """When scan_history_id is provided and exists for domain, that scan is reused; create_scan is not called."""
        existing_scan = self.data_generator.create_scan_history()
        mock_start.return_value = {"status": True, "scan_id": existing_scan.id}
        selected = {self.task.task_type: ["host.example.com"]}
        result = run_per_task_secator_scans(
            target_id=self.scan_history.target_id,
            user_id=self.user.id,
            selected_targets_per_task=selected,
            task_type_to_id=self.task_type_to_id,
            scan_history_id=existing_scan.id,
        )
        mock_scan_repo_cls.return_value.create_scan.assert_not_called()
        self.assertEqual(result["scan_id"], existing_scan.id)
        self.assertEqual(result["success_count"], 1)
        self.assertEqual(mock_start.call_args[1]["scan_history_id"], existing_scan.id)

    @patch("reNgine.secator.service.ScanHistory.objects.get")
    @patch("reNgine.secator.service.start_secator_scan")
    @patch("reNgine.secator.service.ScanRepository")
    def test_creates_scan_when_scan_history_id_invalid(self, mock_scan_repo_cls, mock_start, mock_scan_get):
        """When scan_history_id is provided but does not exist for domain, a new scan is created."""
        new_scan_id = 999
        mock_scan_repo_cls.return_value.create_scan.return_value = new_scan_id
        mock_scan_get.return_value = MagicMock(id=new_scan_id)
        mock_start.return_value = {"status": True, "scan_id": new_scan_id}
        selected = {self.task.task_type: ["host.example.com"]}
        result = run_per_task_secator_scans(
            target_id=self.scan_history.target_id,
            user_id=self.user.id,
            selected_targets_per_task=selected,
            task_type_to_id=self.task_type_to_id,
            scan_history_id=0,
        )
        mock_scan_repo_cls.return_value.create_scan.assert_called_once()
        self.assertEqual(result["scan_id"], new_scan_id)
        self.assertEqual(result["success_count"], 1)


class TestPersistScanConfigOnHistory(BaseTestCase):
    """Test cases for _persist_scan_config_on_history helper."""

    def setUp(self):
        super().setUp()
        self.scan_history = self.data_generator.create_scan_history()

    def test_sets_scan_config_on_history(self):
        """scan_config dict is saved on the ScanHistory row."""
        config = {"threads": 10, "profiles": ["polite"]}
        _persist_scan_config_on_history(self.scan_history, config)
        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_config, config)

    def test_noop_when_config_is_empty(self):
        """Empty dict is falsy so no write should occur."""
        _persist_scan_config_on_history(self.scan_history, {})
        self.scan_history.refresh_from_db()
        self.assertIsNone(self.scan_history.scan_config)

    def test_noop_when_config_is_none(self):
        """None config should not write."""
        _persist_scan_config_on_history(self.scan_history, None)
        self.scan_history.refresh_from_db()
        self.assertIsNone(self.scan_history.scan_config)


class TestStartSecatorScanPersistsScanConfig(BaseTestCase):
    """Verify start_secator_scan persists secator_config on the ScanHistory."""

    def setUp(self):
        super().setUp()
        self.scan_history = self.data_generator.create_scan_history()

    @patch("reNgine.secator.service.threading.Thread")
    def test_new_scan_persists_scan_config(self, mock_thread):
        """When execution_mode creates a new scan, scan_config is persisted."""
        config = {"threads": 20, "delay": 1}

        def run_target_and_return_mock(*args, **kwargs):
            kwargs.get("target", lambda: None)()
            return Mock()

        mock_thread.side_effect = run_target_and_return_mock

        with patch("reNgine.secator.service.initiate_secator_scan"):
            result = start_secator_scan(
                target_id=self.scan_history.target_id,
                user_id=self.user.id,
                execution_mode="tasks",
                task_ids=[1],
                secator_config=config,
            )
        self.assertTrue(result.get("status"))
        scan = ScanHistory.objects.get(pk=result["scan_id"])
        self.assertEqual(scan.scan_config, config)

    @patch("reNgine.secator.service.threading.Thread")
    def test_reused_scan_does_not_overwrite_scan_config(self, mock_thread):
        """When scan_history_id is provided, scan_config is NOT overwritten."""
        self.scan_history.scan_config = {"threads": 5}
        self.scan_history.save(update_fields=["scan_config"])

        def run_target_and_return_mock(*args, **kwargs):
            kwargs.get("target", lambda: None)()
            return Mock()

        mock_thread.side_effect = run_target_and_return_mock

        with patch("reNgine.secator.service.initiate_secator_scan"):
            result = start_secator_scan(
                target_id=self.scan_history.target_id,
                user_id=self.user.id,
                execution_mode="tasks",
                task_ids=[1],
                secator_config={"threads": 99},
                scan_history_id=self.scan_history.id,
            )
        self.assertTrue(result.get("status"))
        self.scan_history.refresh_from_db()
        self.assertEqual(self.scan_history.scan_config, {"threads": 5})
