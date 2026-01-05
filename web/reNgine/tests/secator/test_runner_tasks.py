"""
Tests for SecatorRunner task execution.
"""

from unittest.mock import MagicMock, patch

from reNgine.secator.runner import SecatorRunner
from targetApp.models import Domain
from utils.test_base import BaseTestCase


class TestSecatorRunnerTasks(BaseTestCase):
    """Test cases for SecatorRunner task execution."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.runner = SecatorRunner()
        self.domain = Domain.objects.create(name="testdomain.com")

    def tearDown(self):
        """Clean up test data."""
        Domain.objects.all().delete()
        super().tearDown()

    @patch("reNgine.secator.runner.os.makedirs")
    @patch("reNgine.secator.runner.Task")
    @patch("reNgine.secator.runner.TemplateLoader")
    def test_run_tasks_multiple_success(self, mock_template_loader, mock_task_class, mock_makedirs):
        """Test successful execution of multiple tasks."""
        mock_template = MagicMock()
        mock_template_loader.return_value = mock_template

        mock_task_instance = MagicMock()
        mock_task_instance.run.return_value = {"items": [], "stats": {}}
        mock_task_class.return_value = mock_task_instance
        mock_task_class.__name__ = "Task"

        task_names = ["subfinder", "httpx", "nuclei"]
        result = self.runner.run_tasks(
            task_names=task_names,
            targets=["testdomain.com"],
            scan_history_id=1,
            domain_id=self.domain.id,
            config={},
            profiles={},
        )

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["task_names"], task_names)
        self.assertEqual(result["tasks_executed"], 3)
        self.assertEqual(len(result["results"]), 3)

        self.assertEqual(mock_template_loader.call_count, 3)
        for call_args in mock_template_loader.call_args_list:
            config_dict = call_args[0][0]
            self.assertEqual(config_dict["type"], "task")
            self.assertIn(config_dict["name"], task_names)

    @patch("reNgine.secator.runner.os.makedirs")
    @patch("reNgine.secator.runner.Task")
    @patch("reNgine.secator.runner.TemplateLoader")
    def test_run_tasks_partial_failure(self, mock_template_loader, mock_task_class, mock_makedirs):
        """Test execution with some tasks failing."""
        mock_template = MagicMock()
        mock_template_loader.return_value = mock_template

        mock_task_instance = MagicMock()
        mock_task_class.__name__ = "Task"

        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 2:
                raise Exception("Task failed")
            return {"items": [], "stats": {}}

        mock_task_instance.run.side_effect = side_effect
        mock_task_class.return_value = mock_task_instance

        task_names = ["subfinder", "httpx", "nuclei"]
        result = self.runner.run_tasks(
            task_names=task_names,
            targets=["testdomain.com"],
            scan_history_id=1,
            domain_id=self.domain.id,
            config={},
            profiles={},
        )

        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["tasks_executed"], 3)
        self.assertEqual(result["results"][1]["result"]["status"], "error")

    @patch("reNgine.secator.runner.os.makedirs")
    @patch("reNgine.secator.runner.Task")
    @patch("reNgine.secator.runner.TemplateLoader")
    def test_run_task_single_delegates_to_run_tasks(self, mock_template_loader, mock_task_class, mock_makedirs):
        """Test that run_task delegates to run_tasks."""
        mock_template = MagicMock()
        mock_template_loader.return_value = mock_template

        mock_task_instance = MagicMock()
        mock_task_instance.run.return_value = {"items": [], "stats": {}}
        mock_task_class.return_value = mock_task_instance
        mock_task_class.__name__ = "Task"

        result = self.runner.run_task(
            task_name="subfinder",
            targets=["testdomain.com"],
            scan_history_id=1,
            domain_id=self.domain.id,
            config={},
            profiles={},
        )

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["task_name"], "subfinder")

        mock_template_loader.assert_called_once()
        config_dict = mock_template_loader.call_args[0][0]
        self.assertEqual(config_dict["type"], "task")
        self.assertEqual(config_dict["name"], "subfinder")

    @patch("reNgine.secator.runner.TemplateLoader")
    def test_run_tasks_empty_list(self, mock_template_loader):
        """Test handling of empty task list."""
        result = self.runner.run_tasks(
            task_names=[],
            targets=["testdomain.com"],
            scan_history_id=1,
            domain_id=self.domain.id,
            config={},
            profiles={},
        )

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["tasks_executed"], 0)
        self.assertEqual(result["results"], [])

    @patch("reNgine.secator.runner.os.makedirs")
    @patch("reNgine.secator.runner.Task")
    @patch("reNgine.secator.runner.TemplateLoader")
    def test_run_tasks_template_loader_dict_format(self, mock_template_loader, mock_task_class, mock_makedirs):
        """Test that TemplateLoader is called with correct dict format."""
        mock_template = MagicMock()
        mock_template_loader.return_value = mock_template

        mock_task_instance = MagicMock()
        mock_task_instance.run.return_value = {"items": [], "stats": {}}
        mock_task_class.return_value = mock_task_instance
        mock_task_class.__name__ = "Task"

        self.runner.run_tasks(
            task_names=["httpx"],
            targets=["testdomain.com"],
            scan_history_id=1,
            domain_id=self.domain.id,
            config={},
            profiles={},
        )

        mock_template_loader.assert_called_once()
        config_dict = mock_template_loader.call_args[0][0]

        self.assertIsInstance(config_dict, dict)
        self.assertEqual(config_dict["type"], "task")
        self.assertEqual(config_dict["name"], "httpx")
