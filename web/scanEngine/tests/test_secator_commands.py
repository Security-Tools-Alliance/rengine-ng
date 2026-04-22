"""
test_secator_commands.py

This file contains unit tests for the Secator management commands.
"""

import contextlib
from io import StringIO
import os
import sys
import tempfile
from unittest.mock import MagicMock, mock_open, patch

from django.core.management import call_command
from django.core.management.base import CommandError
import yaml

from scanEngine.models import SecatorProfile, SecatorScan, SecatorTask, SecatorWorkflow
from utils.test_base import BaseTestCase


def get_test_stdout():
    """
    Return stdout stream for test commands.
    If verbosity is 2 or more, return sys.stdout to display output.
    Otherwise, return StringIO() to suppress output.
    """
    verbosity = 1
    for arg in sys.argv:
        if arg.startswith("--verbosity="):
            with contextlib.suppress(ValueError, IndexError):
                verbosity = int(arg.split("=", 1)[1])
            break
        elif arg == "--verbosity" and sys.argv.index(arg) + 1 < len(sys.argv):
            with contextlib.suppress(ValueError, IndexError):
                verbosity = int(sys.argv[sys.argv.index(arg) + 1])
            break

    return sys.stdout if verbosity >= 2 else StringIO()


class TestSecatorCommands(BaseTestCase):
    """Test class for Secator management commands."""

    def setUp(self):
        """Set up test data."""
        super().setUp()

    @patch("scanEngine.management.commands.load_tasks.discover_tasks")
    @patch("scanEngine.management.commands.load_tasks.get_configs_by_type")
    def test_load_tasks_command(self, mock_get_configs, mock_discover_tasks):
        """Test the load_tasks management command."""
        mock_task1 = MagicMock()
        mock_task1.name = "subfinder"
        mock_task1.description = "Subdomain discovery tool."

        mock_task2 = MagicMock()
        mock_task2.name = "httpx"
        mock_task2.description = "HTTP probe tool."

        mock_task3 = MagicMock()
        mock_task3.name = "nuclei"
        mock_task3.description = "Vulnerability scanner."

        mock_get_configs.return_value = [mock_task1, mock_task2, mock_task3]

        mock_cls1 = MagicMock()
        mock_cls1.__name__ = "subfinder"
        mock_cls1.tags = ["dns", "recon"]
        mock_cls2 = MagicMock()
        mock_cls2.__name__ = "httpx"
        mock_cls2.tags = ["url", "probe"]
        mock_cls3 = MagicMock()
        mock_cls3.__name__ = "nuclei"
        mock_cls3.tags = ["vuln", "scan"]
        mock_discover_tasks.return_value = [mock_cls1, mock_cls2, mock_cls3]

        out = StringIO()
        call_command("load_tasks", stdout=out)

        self.assertTrue(SecatorTask.objects.filter(task_type="subfinder").exists())
        self.assertTrue(SecatorTask.objects.filter(task_type="httpx").exists())
        self.assertTrue(SecatorTask.objects.filter(task_type="nuclei").exists())
        task = SecatorTask.objects.get(task_type="subfinder")
        self.assertEqual(task.tags, ["dns", "recon"])

    @patch("scanEngine.management.commands.load_workflows.get_configs_by_type")
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data="""
type: workflow
name: subdomain_recon
alias: subdomain_recon
description: Subdomain reconnaissance workflow
scan_type: internet
workflow_type: builtin
tasks:
  subfinder:
    description: Find subdomains
  httpx:
    description: Probe HTTP services
""",
    )
    def test_load_workflows_command(self, mock_file, mock_get_configs):
        """Test the load_workflows management command."""
        # Mock TemplateLoader object for workflow
        mock_workflow = MagicMock()
        mock_workflow.name = "subdomain_recon"
        mock_workflow.alias = "subdomain_recon"
        mock_workflow.description = "Subdomain reconnaissance workflow"
        mock_workflow._path = "/path/to/workflow.yaml"
        mock_workflow.long_description = None

        mock_get_configs.return_value = [mock_workflow]

        # Run the command
        out = get_test_stdout()
        call_command("load_workflows", "--builtin-only", stdout=out)

        # Check that workflow was created (using name as key, not alias)
        workflow = SecatorWorkflow.objects.get(name="subdomain_recon")
        self.assertEqual(workflow.name, "subdomain_recon")
        self.assertEqual(workflow.alias, "subdomain_recon")
        self.assertEqual(workflow.display_name, "Subdomain Recon")
        self.assertEqual(workflow.get_display_name(), "Subdomain Recon")

    @patch("scanEngine.management.commands.load_scans.get_configs_by_type")
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data="""
type: scan
name: domain
description: Domain reconnaissance scan
workflows:
  subdomain_recon:
    description: Find subdomains
input_types:
  - domain
""",
    )
    def test_load_scans_command(self, mock_file, mock_get_configs):
        """Test the load_scans management command."""
        # Mock TemplateLoader object for scan
        mock_scan = MagicMock()
        mock_scan.name = "domain"
        mock_scan.description = "Domain reconnaissance scan"
        mock_scan._path = "/path/to/scan.yaml"
        mock_scan.long_description = None

        mock_get_configs.return_value = [mock_scan]

        # Run the command
        out = StringIO()
        call_command("load_scans", stdout=out)

        # Check that scan was created
        self.assertTrue(SecatorScan.objects.filter(name="domain").exists())

    def test_load_secator_all_command(self):
        """Test the load_secator_all management command."""
        with patch("scanEngine.management.commands.load_secator_all.call_command") as mock_call:
            # Run the command
            out = get_test_stdout()
            call_command("load_secator_all", stdout=out)

            # Check that all commands were called (tasks, profiles, workflows, scans)
            self.assertEqual(mock_call.call_count, 4)
            mock_call.assert_any_call("load_tasks")
            mock_call.assert_any_call("load_profiles")
            mock_call.assert_any_call("load_workflows")
            mock_call.assert_any_call("load_scans")

    def test_load_secator_all_tasks_only(self):
        """Test the load_secator_all command with tasks-only flag."""
        with patch("scanEngine.management.commands.load_secator_all.call_command") as mock_call:
            # Run the command with tasks-only
            out = StringIO()
            call_command("load_secator_all", tasks_only=True, stdout=out)

            # Check that only load_tasks was called
            self.assertEqual(mock_call.call_count, 1)
            mock_call.assert_called_with("load_tasks")

    def test_load_secator_all_workflows_only(self):
        """Test the load_secator_all command with workflows-only flag."""
        with patch("scanEngine.management.commands.load_secator_all.call_command") as mock_call:
            # Run the command with workflows-only
            out = StringIO()
            call_command("load_secator_all", workflows_only=True, stdout=out)

            # Check that only load_workflows was called
            self.assertEqual(mock_call.call_count, 1)
            mock_call.assert_called_with("load_workflows")

    def test_load_secator_all_scans_only(self):
        """Test the load_secator_all command with scans-only flag."""
        with patch("scanEngine.management.commands.load_secator_all.call_command") as mock_call:
            # Run the command with scans-only
            out = StringIO()
            call_command("load_secator_all", scans_only=True, stdout=out)

            # Check that only load_scans was called
            self.assertEqual(mock_call.call_count, 1)
            mock_call.assert_called_with("load_scans")

    def test_entrypoint_setup_calls_all_commands(self):
        """Test entrypoint_setup invokes migrations, setup_oauth, cron, load_secator_all, collectstatic."""
        with patch("scanEngine.management.commands.entrypoint_setup.call_command") as mock_call:
            out = StringIO()
            call_command("entrypoint_setup", stdout=out)
            self.assertGreaterEqual(mock_call.call_count, 6)
            calls = [c[0][0] for c in mock_call.call_args_list]
            self.assertEqual(calls[0], "makemigrations")
            self.assertEqual(calls[1], "migrate")
            self.assertEqual(calls[2], "setup_oauth")
            self.assertEqual(calls[3], "ensure_scheduled_scans_cron")
            self.assertEqual(calls[4], "load_secator_all")
            self.assertEqual(calls[5], "collectstatic")
            mock_call.assert_any_call("collectstatic", "--noinput")

    def test_entrypoint_setup_continues_when_optional_commands_fail(self):
        """Test entrypoint_setup still runs collectstatic when cron or load_secator_all raise."""
        with patch("scanEngine.management.commands.entrypoint_setup.call_command") as mock_call:

            def side_effect(cmd, *args, **kwargs):
                if cmd == "ensure_scheduled_scans_cron":
                    raise CommandError("cron not available")
                if cmd == "load_secator_all":
                    raise CommandError("load failed")
                return None

            mock_call.side_effect = side_effect
            out = StringIO()
            call_command("entrypoint_setup", stdout=out)
            calls = [c[0][0] for c in mock_call.call_args_list]
            self.assertIn("collectstatic", calls)


class TestSecatorLoaderBase(BaseTestCase):
    """Test class for SecatorLoaderBase functionality."""

    def setUp(self):
        """Set up test data."""
        super().setUp()

    def test_determine_scan_type_from_yaml(self):
        """Test the _determine_scan_type_from_yaml method."""
        from scanEngine.management.commands.secator_loader_base import SecatorLoaderBase

        command = SecatorLoaderBase()

        # Test internal network scan
        yaml_data = {
            "workflows": {
                "cidr_recon": {"description": "CIDR reconnaissance"},
                "nmap": {"description": "Port scanning"},
            }
        }
        scan_type = command._determine_scan_type_from_yaml(yaml_data)
        self.assertEqual(scan_type, "internal_network")

        # Test internet scan
        yaml_data = {
            "workflows": {
                "subdomain_recon": {"description": "Subdomain discovery"},
                "host_recon": {"description": "Host discovery"},
            }
        }
        scan_type = command._determine_scan_type_from_yaml(yaml_data)
        self.assertEqual(scan_type, "internet")


class TestLoadWorkflowsCommand(BaseTestCase):
    """
    Test class for the load_workflows management command.
    """

    def setUp(self):
        """
        Initial setup for the tests.
        """
        super().setUp()

    @patch("scanEngine.management.commands.load_workflows.get_configs_by_type")
    @patch(
        "scanEngine.management.commands.load_workflows.open",
        new_callable=mock_open,
        read_data="""
type: workflow
name: subdomain_recon
alias: subrec
description: Subdomain discovery
tags:
- recon
- dns
- takeovers
input_types:
- host
tasks:
  subfinder:
    description: List subdomains (passive)
  dnsx:
    description: Probe DNS records
""",
    )
    def test_load_builtin_workflows_success(self, mock_file, mock_get_configs):
        """
        Test successful loading of built-in workflows from Secator.
        """
        # Mock TemplateLoader object for workflow (set long_description to None to avoid MagicMock in DB)
        mock_workflow = MagicMock()
        mock_workflow.name = "subdomain_recon"
        mock_workflow.alias = "subdomain_recon"
        mock_workflow.description = "Subdomain discovery"
        mock_workflow._path = "/path/to/workflow.yaml"
        mock_workflow.long_description = None

        mock_get_configs.return_value = [mock_workflow]

        # Clear existing workflows
        SecatorWorkflow.objects.filter(workflow_type="builtin").delete()

        # Call the command
        out = StringIO()
        call_command("load_workflows", "--builtin-only", stdout=out)

        # Verify workflow was created (using loader name as key)
        workflow = SecatorWorkflow.objects.get(name="subdomain_recon")
        self.assertEqual(workflow.description, "Subdomain discovery")
        self.assertEqual(workflow.workflow_type, "builtin")
        self.assertEqual(workflow.scan_type, "internet")
        self.assertIn("subfinder", workflow.yaml_configuration)
        self.assertEqual(workflow.get_display_name(), "Subdomain Recon")

    @patch("scanEngine.management.commands.load_workflows.get_configs_by_type")
    def test_load_builtin_workflows_secator_failure(self, mock_get_configs):
        """
        Test handling of secator library failure.
        """
        # Mock the secator library failure
        mock_get_configs.side_effect = Exception("Failed to get workflows from secator")

        # Call the command
        out = StringIO()
        call_command("load_workflows", "--builtin-only", stdout=out)

        # Verify no workflows were created
        self.assertEqual(SecatorWorkflow.objects.filter(workflow_type="builtin").count(), 0)

    @patch("scanEngine.management.commands.load_workflows.get_configs_by_type")
    @patch("builtins.open", new_callable=mock_open)
    def test_load_builtin_workflows_file_not_found(self, mock_file, mock_get_configs):
        """
        Test handling of missing workflow file.
        """
        # Mock TemplateLoader object for workflow
        mock_workflow = MagicMock()
        mock_workflow.name = "subdomain_recon"
        mock_workflow.alias = "subdomain_recon"
        mock_workflow.description = "Subdomain discovery"
        mock_workflow._path = "/path/to/workflow.yaml"
        mock_workflow.long_description = None

        mock_get_configs.return_value = [mock_workflow]

        # Mock file not found - configure the mock to raise FileNotFoundError
        mock_file.side_effect = FileNotFoundError("File not found")

        # Call the command
        out = StringIO()
        call_command("load_workflows", "--builtin-only", stdout=out)

        # Verify no workflows were created
        self.assertEqual(SecatorWorkflow.objects.filter(workflow_type="builtin").count(), 0)

    @patch("scanEngine.management.commands.load_workflows.get_configs_by_type")
    @patch("builtins.open", new_callable=mock_open, read_data="invalid: yaml: content: [")
    def test_load_builtin_workflows_invalid_yaml(self, mock_file, mock_get_configs):
        """
        Test handling of invalid YAML content.
        """
        # Mock TemplateLoader object for workflow
        mock_workflow = MagicMock()
        mock_workflow.name = "subdomain_recon"
        mock_workflow.alias = "subdomain_recon"
        mock_workflow.description = "Subdomain discovery"
        mock_workflow._path = "/path/to/workflow.yaml"
        mock_workflow.long_description = None

        mock_get_configs.return_value = [mock_workflow]

        # Call the command
        out = StringIO()
        call_command("load_workflows", "--builtin-only", stdout=out)

        # Verify no workflows were created
        self.assertEqual(SecatorWorkflow.objects.filter(workflow_type="builtin").count(), 0)

    @patch("scanEngine.management.commands.load_workflows.get_configs_by_type")
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data="""
type: workflow
name: subdomain_recon
alias: subrec
description: Subdomain discovery
tasks:
  subfinder:
    description: List subdomains (passive)
""",
    )
    def test_load_builtin_workflows_update_existing(self, mock_file, mock_get_configs):
        """
        Test updating existing built-in workflows.
        """
        # Create an existing workflow (name must match loader name for get_or_create to find it)
        existing_workflow = SecatorWorkflow.objects.create(
            name="subdomain_recon",
            alias="subdomain_recon",
            description="Old description",
            workflow_type="builtin",
            yaml_configuration="old: config",
            scan_type="internal_network",
        )

        # Mock TemplateLoader object for workflow
        mock_workflow = MagicMock()
        mock_workflow.name = "subdomain_recon"
        mock_workflow.alias = "subdomain_recon"
        mock_workflow.description = "Subdomain discovery"
        mock_workflow._path = "/path/to/workflow.yaml"
        mock_workflow.long_description = None

        mock_get_configs.return_value = [mock_workflow]

        # Call the command
        out = StringIO()
        call_command("load_workflows", "--builtin-only", stdout=out)

        # Verify workflow was updated
        existing_workflow.refresh_from_db()
        self.assertEqual(existing_workflow.name, "subdomain_recon")
        self.assertEqual(existing_workflow.get_display_name(), "Subdomain Recon")
        self.assertEqual(existing_workflow.description, "Subdomain discovery")
        self.assertEqual(existing_workflow.scan_type, "internet")
        self.assertIn("subfinder", existing_workflow.yaml_configuration)

    def test_determine_scan_type_internal(self):
        """
        Test scan type determination for internal workflows.
        """
        from scanEngine.management.commands.secator_loader_base import SecatorLoaderBase

        command = SecatorLoaderBase()

        # Test with internal keywords
        workflow_data = {
            "workflows": {"nmap": {"description": "Port scan"}, "naabu": {"description": "Port discovery"}},
            "description": "Network reconnaissance",
        }

        scan_type = command._determine_scan_type_from_yaml(workflow_data)
        self.assertEqual(scan_type, "internal_network")

    def test_determine_scan_type_internet(self):
        """
        Test scan type determination for internet workflows.
        """
        from scanEngine.management.commands.secator_loader_base import SecatorLoaderBase

        command = SecatorLoaderBase()

        # Test with internet keywords
        workflow_data = {
            "workflows": {
                "subdomain_recon": {"description": "Subdomain discovery"},
                "host_recon": {"description": "Host discovery"},
            },
            "description": "Web reconnaissance",
        }

        scan_type = command._determine_scan_type_from_yaml(workflow_data)
        self.assertEqual(scan_type, "internet")


class TestLoadTasksCommand(BaseTestCase):
    """
    Test class for the load_tasks management command.
    """

    def setUp(self):
        """
        Initial setup for the tests.
        """
        super().setUp()

    @patch("scanEngine.management.commands.load_tasks.discover_tasks")
    @patch("scanEngine.management.commands.load_tasks.get_configs_by_type")
    def test_load_builtin_tasks_success(self, mock_get_configs, mock_discover_tasks):
        """Test successful loading of built-in tasks from Secator."""
        mock_task1 = MagicMock()
        mock_task1.name = "subfinder"
        mock_task1.description = "Subdomain discovery tool."

        mock_task2 = MagicMock()
        mock_task2.name = "httpx"
        mock_task2.description = "HTTP probe tool."

        mock_get_configs.return_value = [mock_task1, mock_task2]

        mock_cls1 = MagicMock()
        mock_cls1.__name__ = "subfinder"
        mock_cls1.tags = ["dns", "recon"]
        mock_cls2 = MagicMock()
        mock_cls2.__name__ = "httpx"
        mock_cls2.tags = ["url", "probe"]
        mock_discover_tasks.return_value = [mock_cls1, mock_cls2]

        SecatorTask.objects.filter(is_builtin=True).delete()

        out = get_test_stdout()
        call_command("load_tasks", stdout=out)

        task1 = SecatorTask.objects.get(name="subfinder")
        self.assertEqual(task1.task_type, "subfinder")
        self.assertEqual(task1.description, "Subdomain discovery tool.")
        self.assertEqual(task1.tags, ["dns", "recon"])
        self.assertTrue(task1.is_builtin)
        self.assertTrue(task1.is_active)

        task2 = SecatorTask.objects.get(name="httpx")
        self.assertEqual(task2.task_type, "httpx")
        self.assertEqual(task2.description, "HTTP probe tool.")
        self.assertEqual(task2.tags, ["url", "probe"])
        self.assertTrue(task2.is_builtin)
        self.assertTrue(task2.is_active)

    @patch("scanEngine.management.commands.load_tasks.get_configs_by_type")
    def test_load_builtin_tasks_secator_failure(self, mock_get_configs):
        """
        Test handling of secator library failure.
        """
        # Mock the secator library failure
        mock_get_configs.side_effect = Exception("Failed to get tasks from secator")

        # Call the command
        out = get_test_stdout()
        call_command("load_tasks", stdout=out)

        # Verify no tasks were created
        self.assertEqual(SecatorTask.objects.filter(is_builtin=True).count(), 0)

    @patch("scanEngine.management.commands.load_tasks.get_configs_by_type")
    def test_load_builtin_tasks_missing_name(self, mock_get_configs):
        """
        Test handling of task without name attribute.
        """
        # Mock task without name attribute
        mock_task1 = MagicMock()
        del mock_task1.name  # Remove name attribute
        mock_task1.description = "Some task"

        # Mock task with empty name
        mock_task2 = MagicMock()
        mock_task2.name = ""
        mock_task2.description = "Another task"

        # Mock valid task
        mock_task3 = MagicMock()
        mock_task3.name = "valid_task"
        mock_task3.description = "Valid task"
        mock_task3.category = "test"

        mock_get_configs.return_value = [mock_task1, mock_task2, mock_task3]

        # Clear existing tasks
        SecatorTask.objects.filter(is_builtin=True).delete()

        # Call the command
        out = get_test_stdout()
        call_command("load_tasks", stdout=out)

        # Verify only valid task was created
        self.assertEqual(SecatorTask.objects.filter(is_builtin=True).count(), 1)
        self.assertTrue(SecatorTask.objects.filter(name="valid_task").exists())

    @patch("scanEngine.management.commands.load_tasks.discover_tasks")
    @patch("scanEngine.management.commands.load_tasks.get_configs_by_type")
    def test_load_builtin_tasks_tags_from_discover(self, mock_get_configs, mock_discover_tasks):
        """Test that tags are loaded from Secator task classes (discover_tasks)."""
        mock_task = MagicMock()
        mock_task.name = "subfinder"
        mock_task.description = "Subdomain discovery tool."

        mock_get_configs.return_value = [mock_task]

        mock_cls = MagicMock()
        mock_cls.__name__ = "subfinder"
        mock_cls.tags = ["dns", "recon"]
        mock_discover_tasks.return_value = [mock_cls]

        SecatorTask.objects.filter(is_builtin=True).delete()

        out = get_test_stdout()
        call_command("load_tasks", stdout=out)

        task = SecatorTask.objects.get(name="subfinder")
        self.assertEqual(task.tags, ["dns", "recon"])

    @patch("scanEngine.management.commands.load_tasks.discover_tasks")
    @patch("scanEngine.management.commands.load_tasks.get_configs_by_type")
    def test_load_builtin_tasks_update_existing(self, mock_get_configs, mock_discover_tasks):
        """Test updating existing built-in tasks."""
        existing_task = SecatorTask.objects.create(
            name="subfinder",
            task_type="subfinder",
            description="Old description",
            tags=["old", "category"],
            is_builtin=True,
            is_active=False,
        )

        mock_task = MagicMock()
        mock_task.name = "subfinder"
        mock_task.description = "New description"

        mock_get_configs.return_value = [mock_task]

        mock_cls = MagicMock()
        mock_cls.__name__ = "subfinder"
        mock_cls.tags = ["dns", "recon"]
        mock_discover_tasks.return_value = [mock_cls]

        out = get_test_stdout()
        call_command("load_tasks", stdout=out)

        existing_task.refresh_from_db()
        self.assertEqual(existing_task.name, "subfinder")
        self.assertEqual(existing_task.description, "New description")
        self.assertEqual(existing_task.tags, ["dns", "recon"])
        self.assertTrue(existing_task.is_builtin)
        self.assertTrue(existing_task.is_active)

    @patch("scanEngine.management.commands.load_tasks.discover_tasks")
    @patch("scanEngine.management.commands.load_tasks.get_configs_by_type")
    def test_load_builtin_tasks_name_collision_skips_update(self, mock_get_configs, mock_discover_tasks):
        """Custom task with same name as Secator task is not overwritten; warning is logged."""
        custom_task = SecatorTask.objects.create(
            name="subfinder",
            task_type="subfinder",
            description="Custom description",
            tags=["custom"],
            is_builtin=False,
            is_active=True,
        )

        mock_task = MagicMock()
        mock_task.name = "subfinder"
        mock_task.description = "Secator description"

        mock_get_configs.return_value = [mock_task]

        mock_cls = MagicMock()
        mock_cls.__name__ = "subfinder"
        mock_cls.tags = ["dns", "recon"]
        mock_discover_tasks.return_value = [mock_cls]

        out = StringIO()
        call_command("load_tasks", stdout=out)

        custom_task.refresh_from_db()
        self.assertEqual(custom_task.description, "Custom description")
        self.assertEqual(custom_task.tags, ["custom"])
        self.assertFalse(custom_task.is_builtin)
        self.assertIn("Name collision", out.getvalue())


class TestLoadScansCommand(BaseTestCase):
    """
    Test class for the load_scans management command.
    """

    def setUp(self):
        """
        Initial setup for the tests.
        """
        super().setUp()

    @patch("scanEngine.management.commands.load_scans.get_configs_by_type")
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data="""
type: scan
name: domain
description: Domain reconnaissance scan
workflows:
  subdomain_recon:
    description: Find subdomains
input_types:
  - domain
""",
    )
    def test_load_builtin_scans_success(self, mock_file, mock_get_configs):
        """
        Test successful loading of built-in scans from Secator.
        """
        # Mock TemplateLoader object for scan
        mock_scan = MagicMock()
        mock_scan.name = "domain"
        mock_scan.description = "Domain reconnaissance scan"
        mock_scan._path = "/path/to/scan.yaml"
        mock_scan.long_description = None

        mock_get_configs.return_value = [mock_scan]

        # Clear existing scans
        SecatorScan.objects.filter(scan_config_type="builtin").delete()

        # Call the command
        out = get_test_stdout()
        call_command("load_scans", "--builtin-only", stdout=out)

        # Verify scan was created (using name as key, not alias)
        scan = SecatorScan.objects.get(name="domain")
        self.assertEqual(scan.description, "Domain reconnaissance scan")
        self.assertEqual(scan.scan_config_type, "builtin")
        self.assertEqual(scan.scan_type, "internet")
        self.assertIn("subdomain_recon", scan.yaml_configuration)
        self.assertTrue(scan.is_default)  # Domain scan is default

    @patch("scanEngine.management.commands.load_scans.get_configs_by_type")
    def test_load_builtin_scans_secator_failure(self, mock_get_configs):
        """
        Test handling of secator library failure.
        """
        # Mock the secator library failure
        mock_get_configs.side_effect = Exception("Failed to get scans from secator")

        # Call the command
        out = get_test_stdout()
        call_command("load_scans", "--builtin-only", stdout=out)

        # Verify no scans were created
        self.assertEqual(SecatorScan.objects.filter(scan_config_type="builtin").count(), 0)

    @patch("scanEngine.management.commands.load_scans.get_configs_by_type")
    @patch("builtins.open", new_callable=mock_open)
    def test_load_builtin_scans_file_not_found(self, mock_file, mock_get_configs):
        """
        Test handling of missing scan file.
        """
        # Mock TemplateLoader object for scan
        mock_scan = MagicMock()
        mock_scan.name = "domain"
        mock_scan.description = "Domain reconnaissance scan"
        mock_scan._path = "/path/to/scan.yaml"

        mock_get_configs.return_value = [mock_scan]

        # Mock file not found - configure the mock to raise FileNotFoundError
        mock_file.side_effect = FileNotFoundError("File not found")

        # Call the command
        out = get_test_stdout()
        call_command("load_scans", "--builtin-only", stdout=out)

        # Verify no scans were created
        self.assertEqual(SecatorScan.objects.filter(scan_config_type="builtin").count(), 0)

    @patch("scanEngine.management.commands.load_scans.get_configs_by_type")
    @patch("builtins.open", new_callable=mock_open, read_data="invalid: yaml: content: [")
    def test_load_builtin_scans_invalid_yaml(self, mock_file, mock_get_configs):
        """
        Test handling of invalid YAML content.
        """
        # Mock TemplateLoader object for scan
        mock_scan = MagicMock()
        mock_scan.name = "domain"
        mock_scan.description = "Domain reconnaissance scan"
        mock_scan._path = "/path/to/scan.yaml"

        mock_get_configs.return_value = [mock_scan]

        # Call the command
        out = get_test_stdout()
        call_command("load_scans", "--builtin-only", stdout=out)

        # Verify no scans were created
        self.assertEqual(SecatorScan.objects.filter(scan_config_type="builtin").count(), 0)

    @patch("scanEngine.management.commands.load_scans.get_configs_by_type")
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data="""
type: scan
name: domain
description: Domain reconnaissance scan
workflows:
  subdomain_recon:
    description: Find subdomains
input_types:
  - domain
""",
    )
    def test_load_builtin_scans_update_existing(self, mock_file, mock_get_configs):
        """
        Test updating existing built-in scans.
        """
        # Create an existing scan (using name as key)
        existing_scan = SecatorScan.objects.create(
            name="domain",
            description="Old description",
            scan_config_type="builtin",
            yaml_configuration="old: config",
            scan_type="internal_network",
            is_default=False,
        )

        # Mock TemplateLoader object for scan
        mock_scan = MagicMock()
        mock_scan.name = "domain"
        mock_scan.description = "Domain reconnaissance scan"
        mock_scan._path = "/path/to/scan.yaml"
        mock_scan.long_description = None

        mock_get_configs.return_value = [mock_scan]

        # Call the command
        out = get_test_stdout()
        call_command("load_scans", "--builtin-only", stdout=out)

        # Verify scan was updated via QuerySet.update() (not save())
        existing_scan.refresh_from_db()
        self.assertEqual(existing_scan.name, "domain")
        self.assertEqual(existing_scan.description, "Domain reconnaissance scan")
        self.assertEqual(existing_scan.scan_type, "internet")
        self.assertIn("subdomain_recon", existing_scan.yaml_configuration)
        self.assertTrue(existing_scan.is_default)  # Domain scan is default

    @patch("scanEngine.management.commands.load_scans.get_configs_by_type")
    def test_load_builtin_scans_missing_path(self, mock_get_configs):
        """
        Test handling of scan without _path attribute.
        """
        # Mock TemplateLoader object for scan without _path
        mock_scan = MagicMock()
        mock_scan.name = "domain"
        mock_scan.description = "Domain reconnaissance scan"
        mock_scan._path = None  # No path

        mock_get_configs.return_value = [mock_scan]

        # Clear existing scans
        SecatorScan.objects.filter(scan_config_type="builtin").delete()

        # Call the command
        out = get_test_stdout()
        call_command("load_scans", "--builtin-only", stdout=out)

        # Verify no scans were created
        self.assertEqual(SecatorScan.objects.filter(scan_config_type="builtin").count(), 0)


class TestLoadProfilesCommand(BaseTestCase):
    """
    Test class for the load_profiles management command.
    """

    def setUp(self):
        """
        Initial setup for the tests.
        """
        super().setUp()

    @patch("scanEngine.management.commands.load_profiles.get_configs_by_type")
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data="""
type: profile
name: test_profile
category: speed
description: Test speed profile
enforce: false
opts:
  rate_limit: 100
  delay: 0
""",
    )
    def test_load_profiles_command(self, mock_file, mock_get_configs):
        """Test the load_profiles management command."""
        # Mock TemplateLoader object for profile
        mock_profile = MagicMock()
        mock_profile.name = "test_profile"
        mock_profile.description = "Test speed profile"
        mock_profile._path = "/path/to/profile.yaml"

        mock_get_configs.return_value = [mock_profile]

        # Run the command
        out = get_test_stdout()
        call_command("load_profiles", "--builtin-only", stdout=out)

        # Check that profile was created
        profile = SecatorProfile.objects.filter(name="test_profile").first()
        self.assertIsNotNone(profile)
        self.assertEqual(profile.profile_type, "builtin")
        self.assertEqual(profile.category, "speed")
        self.assertEqual(profile.description, "Test speed profile")
        self.assertFalse(profile.enforce)

    @patch("scanEngine.management.commands.load_profiles.get_configs_by_type")
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data="""
type: profile
name: polite
category: speed
description: Polite speed profile
enforce: false
opts:
  rate_limit: 100
  delay: 0
""",
    )
    def test_load_profiles_sets_default_on_first_import(self, mock_file, mock_get_configs):
        """Test that default profiles are set on first import."""
        mock_profile = MagicMock()
        mock_profile.name = "polite"
        mock_profile.description = "Polite speed profile"
        mock_profile._path = "/path/to/polite.yaml"

        mock_get_configs.return_value = [mock_profile]

        # Run the command - first import
        out = get_test_stdout()
        call_command("load_profiles", "--builtin-only", stdout=out)

        # Check that profile was created and set as default
        profile = SecatorProfile.objects.filter(name="polite").first()
        self.assertIsNotNone(profile)
        self.assertTrue(profile.is_default)

    @patch("scanEngine.management.commands.load_profiles.get_configs_by_type")
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data="""
type: profile
name: polite
category: speed
description: Updated polite speed profile
enforce: false
opts:
  rate_limit: 150
  delay: 1
""",
    )
    def test_load_profiles_does_not_modify_default_on_update(self, mock_file, mock_get_configs):
        """Test that default status is not modified on subsequent imports."""
        # Create existing profile with is_default=False
        existing_profile = SecatorProfile.objects.create(
            name="polite",
            category="speed",
            description="Polite speed profile",
            enforce=False,
            opts=yaml.dump({"rate_limit": 100, "delay": 0}),
            profile_type="builtin",
            is_active=True,
            is_default=False,
        )

        mock_profile = MagicMock()
        mock_profile.name = "polite"
        mock_profile.description = "Updated polite speed profile"
        mock_profile._path = "/path/to/polite.yaml"

        mock_get_configs.return_value = [mock_profile]

        # Run the command - update existing profile
        out = get_test_stdout()
        call_command("load_profiles", "--builtin-only", stdout=out)

        # Check that is_default was not modified
        existing_profile.refresh_from_db()
        self.assertFalse(existing_profile.is_default)
        self.assertEqual(existing_profile.description, "Updated polite speed profile")

    @patch("scanEngine.management.commands.load_profiles.get_configs_by_type")
    def test_load_profiles_command_no_profiles(self, mock_get_configs):
        """Test the load_profiles command when no profiles are found."""
        mock_get_configs.return_value = []

        # Run the command
        out = get_test_stdout()
        call_command("load_profiles", "--builtin-only", stdout=out)

        # Verify no profiles were created
        self.assertEqual(SecatorProfile.objects.filter(profile_type="builtin").count(), 0)

    def test_load_profiles_full_keeps_config_dir_profiles_builtin(self) -> None:
        """Full CLI load must not reclassify reNgine-ng config/profiles YAML as custom (regression for load_secator_all)."""
        secator_yaml = """type: profile
name: secator_side_profile
category: general
description: Test secator-side profile
enforce: false
opts:
  rate_limit: 1
"""
        extra_yaml = """type: profile
name: extra_rengine_cfg_test
category: general
description: From reNgine config dir
enforce: false
opts:
  rate_limit: 2
"""
        with tempfile.TemporaryDirectory() as tmp:
            sec_path = os.path.join(tmp, "secator_p.yaml")
            with open(sec_path, "w", encoding="utf-8") as f:
                f.write(secator_yaml)
            prof_dir = os.path.join(tmp, "config", "profiles")
            os.makedirs(prof_dir, exist_ok=True)
            with open(os.path.join(prof_dir, "extra.yaml"), "w", encoding="utf-8") as f:
                f.write(extra_yaml)

            mock_profile = MagicMock()
            mock_profile.name = "secator_side_profile"
            mock_profile.description = "Test secator-side profile"
            mock_profile._path = sec_path

            with patch(
                "scanEngine.management.commands.load_profiles.get_configs_by_type",
                return_value=[mock_profile],
            ):
                with patch("scanEngine.management.commands.load_profiles.settings.BASE_DIR", tmp):
                    out = get_test_stdout()
                    call_command("load_profiles", stdout=out)

        extra = SecatorProfile.objects.filter(name="extra_rengine_cfg_test").first()
        self.assertIsNotNone(extra)
        self.assertEqual(extra.profile_type, "builtin")
        sec = SecatorProfile.objects.filter(name="secator_side_profile").first()
        self.assertIsNotNone(sec)
        self.assertEqual(sec.profile_type, "builtin")

    @patch("scanEngine.management.commands.check_secator_prefix.get_secator_prefix_diagnostic")
    def test_check_secator_prefix_ok_exits_zero(self, mock_diagnostic):
        """check_secator_prefix exits 0 when diagnostic reports ok."""
        mock_diagnostic.return_value = {
            "prefix_configured": "/home/secator/.secator/reports",
            "rengine_results": "/tmp/results",
            "rengine_results_exists": True,
            "rengine_results_readable": True,
            "paths_still_with_prefix": [],
            "count_paths_still_with_prefix": 0,
            "count_total_with_path": 0,
            "ok": True,
        }
        out = StringIO()
        err = StringIO()
        with self.assertRaises(SystemExit) as cm:
            call_command("check_secator_prefix", stdout=out, stderr=err)
        self.assertEqual(cm.exception.code, 0)
        self.assertIn("OK", out.getvalue())

    @patch("scanEngine.management.commands.check_secator_prefix.get_secator_prefix_diagnostic")
    def test_check_secator_prefix_failure_exits_one(self, mock_diagnostic):
        """check_secator_prefix exits 1 when diagnostic reports issues."""
        mock_diagnostic.return_value = {
            "prefix_configured": "/home/secator/.secator/reports",
            "rengine_results": "/nonexistent",
            "rengine_results_exists": False,
            "rengine_results_readable": False,
            "paths_still_with_prefix": ["/home/secator/.secator/reports/legacy.png"],
            "count_paths_still_with_prefix": 1,
            "count_total_with_path": 1,
            "ok": False,
        }
        out = StringIO()
        err = StringIO()
        with self.assertRaises(SystemExit) as cm:
            call_command("check_secator_prefix", stdout=out, stderr=err)
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("issues detected", err.getvalue())

    @patch("scanEngine.management.commands.check_secator_prefix.get_secator_prefix_diagnostic")
    def test_check_secator_prefix_quiet(self, mock_diagnostic):
        """check_secator_prefix --quiet only writes to stderr on failure."""
        mock_diagnostic.return_value = {
            "ok": False,
            "prefix_configured": "/x",
            "rengine_results": "/y",
            "rengine_results_exists": False,
            "rengine_results_readable": False,
            "paths_still_with_prefix": [],
            "count_paths_still_with_prefix": 0,
            "count_total_with_path": 0,
        }
        out = StringIO()
        err = StringIO()
        with self.assertRaises(SystemExit) as cm:
            call_command("check_secator_prefix", "--quiet", stdout=out, stderr=err)
        self.assertEqual(cm.exception.code, 1)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("check_secator_prefix", err.getvalue())
