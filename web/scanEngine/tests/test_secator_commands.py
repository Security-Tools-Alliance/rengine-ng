"""
test_secator_commands.py

This file contains unit tests for the Secator management commands.
"""

from io import StringIO
from unittest.mock import mock_open, patch

from django.core.management import call_command

from scanEngine.models import SecatorScan, SecatorTask, SecatorWorkflow
from utils.test_base import BaseTestCase


class TestSecatorCommands(BaseTestCase):
    """Test class for Secator management commands."""

    def setUp(self):
        """Set up test data."""
        super().setUp()

    @patch("scanEngine.management.commands.secator_loader_base.subprocess.run")
    def test_load_tasks_command(self, mock_run):
        """Test the load_tasks management command."""
        # Mock the secator command output
        mock_output = """
Usage: secator t [OPTIONS] COMMAND [ARGS...]

╭─ Commands ───────────────────────────────────────────────────────────────────╮
│ subfinder     dns/recon        Subdomain discovery tool.                    │
│ httpx         url/probe        HTTP probe tool.                             │
│ nuclei        vuln/scan        Vulnerability scanner.                       │
╰─────────────────────────────────────────────────────────────────────────────╯
"""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = mock_output
        mock_run.return_value.stderr = ""

        # Run the command
        out = StringIO()
        call_command("load_tasks", stdout=out)

        # Check that tasks were created
        self.assertTrue(SecatorTask.objects.filter(task_type="subfinder").exists())
        self.assertTrue(SecatorTask.objects.filter(task_type="httpx").exists())
        self.assertTrue(SecatorTask.objects.filter(task_type="nuclei").exists())

    @patch("scanEngine.management.commands.secator_loader_base.subprocess.run")
    @patch("builtins.open", new_callable=mock_open)
    def test_load_workflows_command(self, mock_file, mock_run):
        """Test the load_workflows management command."""
        # Mock the secator command output
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = "/path/to/workflow.yaml"

        # Mock the YAML file content
        yaml_content = """
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
"""
        mock_file.return_value.read.return_value = yaml_content

        # Run the command
        out = StringIO()
        call_command("load_workflows", stdout=out)

        # Check that workflow was created
        self.assertTrue(SecatorWorkflow.objects.filter(alias="subdomain_recon").exists())

    @patch("scanEngine.management.commands.secator_loader_base.subprocess.run")
    @patch("builtins.open", new_callable=mock_open)
    def test_load_scans_command(self, mock_file, mock_run):
        """Test the load_scans management command."""
        # Mock the secator command output
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = "/path/to/scan.yaml"

        # Mock the YAML file content
        yaml_content = """
type: scan
name: domain
description: Domain reconnaissance scan
workflows:
  subdomain_recon:
    description: Find subdomains
input_types:
  - domain
"""
        mock_file.return_value.read.return_value = yaml_content

        # Run the command
        out = StringIO()
        call_command("load_scans", stdout=out)

        # Check that scan was created
        self.assertTrue(SecatorScan.objects.filter(alias="domain").exists())

    def test_load_secator_all_command(self):
        """Test the load_secator_all management command."""
        with patch("scanEngine.management.commands.load_secator_all.call_command") as mock_call:
            # Run the command
            out = StringIO()
            call_command("load_secator_all", stdout=out)

            # Check that all commands were called
            self.assertEqual(mock_call.call_count, 3)
            mock_call.assert_any_call("load_tasks", force=False)
            mock_call.assert_any_call("load_workflows", force=False)
            mock_call.assert_any_call("load_scans", force=False)

    def test_load_secator_all_with_force(self):
        """Test the load_secator_all command with force flag."""
        with patch("scanEngine.management.commands.load_secator_all.call_command") as mock_call:
            # Run the command with force
            out = StringIO()
            call_command("load_secator_all", force=True, stdout=out)

            # Check that all commands were called with force
            self.assertEqual(mock_call.call_count, 3)
            mock_call.assert_any_call("load_tasks", force=True)
            mock_call.assert_any_call("load_workflows", force=True)
            mock_call.assert_any_call("load_scans", force=True)

    def test_load_secator_all_tasks_only(self):
        """Test the load_secator_all command with tasks-only flag."""
        with patch("scanEngine.management.commands.load_secator_all.call_command") as mock_call:
            # Run the command with tasks-only
            out = StringIO()
            call_command("load_secator_all", tasks_only=True, stdout=out)

            # Check that only load_tasks was called
            self.assertEqual(mock_call.call_count, 1)
            mock_call.assert_called_with("load_tasks", force=False)

    def test_load_secator_all_workflows_only(self):
        """Test the load_secator_all command with workflows-only flag."""
        with patch("scanEngine.management.commands.load_secator_all.call_command") as mock_call:
            # Run the command with workflows-only
            out = StringIO()
            call_command("load_secator_all", workflows_only=True, stdout=out)

            # Check that only load_workflows was called
            self.assertEqual(mock_call.call_count, 1)
            mock_call.assert_called_with("load_workflows", force=False)

    def test_load_secator_all_scans_only(self):
        """Test the load_secator_all command with scans-only flag."""
        with patch("scanEngine.management.commands.load_secator_all.call_command") as mock_call:
            # Run the command with scans-only
            out = StringIO()
            call_command("load_secator_all", scans_only=True, stdout=out)

            # Check that only load_scans was called
            self.assertEqual(mock_call.call_count, 1)
            mock_call.assert_called_with("load_scans", force=False)


class TestSecatorLoaderBase(BaseTestCase):
    """Test class for SecatorLoaderBase functionality."""

    def setUp(self):
        """Set up test data."""
        super().setUp()

    @patch("scanEngine.management.commands.secator_loader_base.subprocess.run")
    def test_execute_secator_command(self, mock_run):
        """Test the _execute_secator_command method."""
        from scanEngine.management.commands.secator_loader_base import SecatorLoaderBase

        # Mock the subprocess run
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "test output"
        mock_run.return_value.stderr = ""

        # Create a command instance
        command = SecatorLoaderBase()

        # Test the method
        result = command._execute_secator_command(["t"])

        # Check the result
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "test output")
        mock_run.assert_called_once()

    def test_parse_tasks_output(self):
        """Test the _parse_tasks_output method."""
        from scanEngine.management.commands.secator_loader_base import SecatorLoaderBase

        # Sample output
        output = """
Usage: secator t [OPTIONS] COMMAND [ARGS...]

╭─ Commands ───────────────────────────────────────────────────────────────────╮
│ subfinder     dns/recon        Subdomain discovery tool.                    │
│ httpx         url/probe        HTTP probe tool.                             │
╰─────────────────────────────────────────────────────────────────────────────╯
"""

        command = SecatorLoaderBase()
        tasks = command._parse_tasks_output(output)

        # Check the parsed tasks
        self.assertEqual(len(tasks), 2)
        self.assertEqual(tasks[0]["task_type"], "subfinder")
        self.assertEqual(tasks[0]["category"], "dns/recon")
        self.assertEqual(tasks[1]["task_type"], "httpx")
        self.assertEqual(tasks[1]["category"], "url/probe")

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
