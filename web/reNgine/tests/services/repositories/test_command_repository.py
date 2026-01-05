"""
Tests for Command repository functionality.
"""

from django.utils import timezone

from reNgine.services.repositories.command_repository import CommandRepository
from utils.test_base import BaseTestCase


class TestCommandRepository(BaseTestCase):
    """Test cases for CommandRepository."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.command_repo = CommandRepository()
        self.scan_history = self.data_generator.create_scan_history()
        self.scan_activity = self.data_generator.create_scan_activity()

    def test_save_from_secator_complete_data(self):
        """Test saving command with complete Secator data."""
        runner_data = {
            "name": "nuclei",
            "status": "SUCCESS",
            "cmd": "nuclei -l input.txt -jsonl -tags takeover",
            "output": "Test output",
            "return_code": 0,
            "start_time": "2026-01-03T19:36:51.506013",
            "end_time": "2026-01-03T19:36:55.616693",
            "elapsed": 4.11068,
            "errors": [],
            "warnings": ["Warning 1", "Warning 2"],
            "cwd": "/home/rengine",
        }

        result = self.command_repo.save_from_secator(runner_data, self.scan_history.id, self.scan_activity.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.name, "nuclei")
        self.assertEqual(result.status, "SUCCESS")
        self.assertEqual(result.command, "nuclei -l input.txt -jsonl -tags takeover")
        self.assertEqual(result.output, "Test output")
        self.assertEqual(result.return_code, 0)
        self.assertEqual(result.elapsed, 4.11068)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.warnings, ["Warning 1", "Warning 2"])
        self.assertEqual(result.cwd, "/home/rengine")
        self.assertEqual(result.scan_history.id, self.scan_history.id)
        self.assertEqual(result.activity.id, self.scan_activity.id)
        self.assertIsNotNone(result.time)
        self.assertIsNotNone(result.end_time)

    def test_save_from_secator_partial_data(self):
        """Test saving command with partial Secator data."""
        runner_data = {
            "name": "httpx",
            "cmd": "httpx -l input.txt",
            "output": "Partial output",
        }

        result = self.command_repo.save_from_secator(runner_data, self.scan_history.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.name, "httpx")
        self.assertEqual(result.command, "httpx -l input.txt")
        self.assertEqual(result.output, "Partial output")
        self.assertEqual(result.scan_history.id, self.scan_history.id)
        self.assertIsNone(result.activity)
        self.assertIsNotNone(result.time)

    def test_save_from_secator_with_config_name(self):
        """Test saving command when name is in config."""
        runner_data = {
            "config": {"name": "subfinder"},
            "cmd": "subfinder -d example.com",
            "output": "Output",
        }

        result = self.command_repo.save_from_secator(runner_data, self.scan_history.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.name, "subfinder")

    def test_save_from_secator_with_errors_and_warnings(self):
        """Test saving command with errors and warnings."""
        runner_data = {
            "name": "nuclei",
            "cmd": "nuclei -l input.txt",
            "output": "Output",
            "errors": ["Error 1", "Error 2"],
            "warnings": ["Warning 1"],
        }

        result = self.command_repo.save_from_secator(runner_data, self.scan_history.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.errors, ["Error 1", "Error 2"])
        self.assertEqual(result.warnings, ["Warning 1"])

    def test_save_from_secator_with_non_list_errors_warnings(self):
        """Test saving command when errors/warnings are not lists."""
        runner_data = {
            "name": "nuclei",
            "cmd": "nuclei -l input.txt",
            "output": "Output",
            "errors": "Single error string",
            "warnings": "Single warning string",
        }

        result = self.command_repo.save_from_secator(runner_data, self.scan_history.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.errors, ["Single error string"])
        self.assertEqual(result.warnings, ["Single warning string"])

    def test_save_from_secator_invalid_scan_history(self):
        """Test saving command with invalid scan_history_id."""
        runner_data = {
            "name": "nuclei",
            "cmd": "nuclei -l input.txt",
            "output": "Output",
        }

        result = self.command_repo.save_from_secator(runner_data, 99999)

        self.assertIsNone(result)

    def test_save_from_secator_invalid_activity(self):
        """Test saving command with invalid activity_id."""
        runner_data = {
            "name": "nuclei",
            "cmd": "nuclei -l input.txt",
            "output": "Output",
        }

        result = self.command_repo.save_from_secator(runner_data, self.scan_history.id, 99999)

        self.assertIsNotNone(result)
        self.assertEqual(result.scan_history.id, self.scan_history.id)
        self.assertIsNone(result.activity)

    def test_save_from_secator_missing_cmd_and_output(self):
        """Test saving command when both cmd and output are missing."""
        runner_data = {
            "name": "nuclei",
        }

        result = self.command_repo.save_from_secator(runner_data, self.scan_history.id)

        self.assertIsNone(result)

    def test_save_from_secator_invalid_date_format(self):
        """Test saving command with invalid date format."""
        runner_data = {
            "name": "nuclei",
            "cmd": "nuclei -l input.txt",
            "output": "Output",
            "start_time": "invalid-date",
            "end_time": "invalid-date",
        }

        result = self.command_repo.save_from_secator(runner_data, self.scan_history.id)

        self.assertIsNotNone(result)
        self.assertIsNotNone(result.time)

    def test_save_from_secator_update_existing(self):
        """Test updating existing command."""
        runner_data = {
            "name": "nuclei",
            "cmd": "nuclei -l input.txt",
            "output": "Initial output",
            "start_time": "2026-01-03T19:36:51.506013",
        }

        result1 = self.command_repo.save_from_secator(runner_data, self.scan_history.id, self.scan_activity.id)
        self.assertIsNotNone(result1)

        runner_data["output"] = "Updated output"
        runner_data["return_code"] = 1
        runner_data["end_time"] = "2026-01-03T19:36:55.616693"

        result2 = self.command_repo.save_from_secator(runner_data, self.scan_history.id, self.scan_activity.id)

        self.assertIsNotNone(result2)
        self.assertEqual(result1.id, result2.id)
        self.assertEqual(result2.output, "Updated output")
        self.assertEqual(result2.return_code, 1)
        self.assertIsNotNone(result2.end_time)

    def test_get_commands_for_scan(self):
        """Test getting commands for a scan history."""
        runner_data1 = {
            "name": "nuclei",
            "cmd": "nuclei -l input.txt",
            "output": "Output 1",
        }
        runner_data2 = {
            "name": "httpx",
            "cmd": "httpx -l input.txt",
            "output": "Output 2",
        }

        self.command_repo.save_from_secator(runner_data1, self.scan_history.id)
        self.command_repo.save_from_secator(runner_data2, self.scan_history.id)

        commands = self.command_repo.get_commands_for_scan(self.scan_history.id)

        self.assertEqual(len(commands), 2)
        self.assertIn(commands[0].name, ["nuclei", "httpx"])
        self.assertIn(commands[1].name, ["nuclei", "httpx"])

    def test_get_commands_for_activity(self):
        """Test getting commands for a scan activity."""
        runner_data1 = {
            "name": "nuclei",
            "cmd": "nuclei -l input.txt",
            "output": "Output 1",
        }
        runner_data2 = {
            "name": "httpx",
            "cmd": "httpx -l input.txt",
            "output": "Output 2",
        }

        self.command_repo.save_from_secator(runner_data1, self.scan_history.id, self.scan_activity.id)
        self.command_repo.save_from_secator(runner_data2, self.scan_history.id, self.scan_activity.id)

        commands = self.command_repo.get_commands_for_activity(self.scan_activity.id)

        self.assertEqual(len(commands), 2)
        self.assertIn(commands[0].name, ["nuclei", "httpx"])
        self.assertIn(commands[1].name, ["nuclei", "httpx"])

    def test_get_commands_for_invalid_scan(self):
        """Test getting commands for invalid scan history."""
        commands = self.command_repo.get_commands_for_scan(99999)
        self.assertEqual(commands, [])

    def test_get_commands_for_invalid_activity(self):
        """Test getting commands for invalid activity."""
        commands = self.command_repo.get_commands_for_activity(99999)
        self.assertEqual(commands, [])

    def test_save_from_secator_with_iso_date_with_z(self):
        """Test parsing ISO date with Z suffix."""
        runner_data = {
            "name": "nuclei",
            "cmd": "nuclei -l input.txt",
            "output": "Output",
            "start_time": "2026-01-03T19:36:51.506013Z",
            "end_time": "2026-01-03T19:36:55.616693Z",
        }

        result = self.command_repo.save_from_secator(runner_data, self.scan_history.id)

        self.assertIsNotNone(result)
        self.assertIsNotNone(result.time)
        self.assertIsNotNone(result.end_time)

    def test_save_from_secator_with_datetime_object(self):
        """Test saving command when start_time/end_time are datetime objects."""
        start_time = timezone.now()
        end_time = timezone.now()

        runner_data = {
            "name": "nuclei",
            "cmd": "nuclei -l input.txt",
            "output": "Output",
            "start_time": start_time,
            "end_time": end_time,
        }

        result = self.command_repo.save_from_secator(runner_data, self.scan_history.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.time, start_time)
        self.assertEqual(result.end_time, end_time)

    def test_save_from_secator_with_elapsed_int(self):
        """Test saving command when elapsed is an integer (seconds)."""
        runner_data = {
            "name": "nuclei",
            "cmd": "nuclei -l input.txt",
            "output": "Output",
            "elapsed": 30,
        }

        result = self.command_repo.save_from_secator(runner_data, self.scan_history.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.elapsed, 30.0)

    def test_save_from_secator_with_elapsed_float_decimal(self):
        """Test saving command when elapsed is a float with decimal (real-world example)."""
        runner_data = {
            "name": "nuclei",
            "cmd": "nuclei -l input.txt",
            "output": "Output",
            "elapsed": 253.096803,
        }

        result = self.command_repo.save_from_secator(runner_data, self.scan_history.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.elapsed, 253.096803)

    def test_save_from_secator_with_invalid_elapsed(self):
        """Test saving command with invalid elapsed type."""
        runner_data = {
            "name": "nuclei",
            "cmd": "nuclei -l input.txt",
            "output": "Output",
            "elapsed": {"invalid": "type"},
        }

        result = self.command_repo.save_from_secator(runner_data, self.scan_history.id)

        self.assertIsNotNone(result)
        self.assertIsNone(result.elapsed)

    def test_save_from_secator_with_empty_errors_warnings(self):
        """Test updating existing command with empty errors/warnings lists."""
        runner_data = {
            "name": "nuclei",
            "cmd": "nuclei -l input.txt",
            "output": "Initial output",
            "errors": ["Error 1"],
            "warnings": ["Warning 1"],
            "start_time": "2026-01-03T19:36:51.506013",
        }

        result1 = self.command_repo.save_from_secator(runner_data, self.scan_history.id)
        self.assertIsNotNone(result1)
        self.assertEqual(result1.errors, ["Error 1"])
        self.assertEqual(result1.warnings, ["Warning 1"])

        runner_data["errors"] = []
        runner_data["warnings"] = []

        result2 = self.command_repo.save_from_secator(runner_data, self.scan_history.id)
        self.assertIsNotNone(result2)
        self.assertEqual(result1.id, result2.id)
        self.assertEqual(result2.errors, ["Error 1"])
        self.assertEqual(result2.warnings, ["Warning 1"])

    def test_save_from_secator_ancestor_id_from_node_id_with_dot(self):
        """Test extracting ancestor_id from node_id when it contains a dot."""
        runner_data = {
            "name": "httpx/tls",
            "cmd": "httpx -u example.com",
            "output": "Output",
            "config": {
                "type": "task",
                "node_id": "subdomain_recon.httpx/tls",
            },
            "context": {
                "ancestor_id": "wrong_ancestor",  # Should be ignored
            },
        }

        result = self.command_repo.save_from_secator(runner_data, self.scan_history.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.ancestor_id, "subdomain_recon")
        self.assertEqual(result.node_id, "subdomain_recon.httpx/tls")

    def test_save_from_secator_ancestor_id_from_node_id_with_slash(self):
        """Test extracting ancestor_id from node_id with task name containing slash."""
        runner_data = {
            "name": "httpx/probe",
            "cmd": "httpx -l input.txt",
            "output": "Output",
            "config": {
                "type": "task",
                "node_id": "subdomain_recon.httpx/probe",
            },
        }

        result = self.command_repo.save_from_secator(runner_data, self.scan_history.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.ancestor_id, "subdomain_recon")

    def test_save_from_secator_ancestor_id_from_node_id_no_dot(self):
        """Test that ancestor_id is None when node_id doesn't contain a dot."""
        runner_data = {
            "name": "subdomain_recon",
            "cmd": "subfinder -d example.com",
            "output": "Output",
            "config": {
                "type": "workflow",
                "node_id": "subdomain_recon",  # No dot, so no ancestor
            },
        }

        result = self.command_repo.save_from_secator(runner_data, self.scan_history.id)

        self.assertIsNotNone(result)
        self.assertIsNone(result.ancestor_id)
        self.assertEqual(result.node_id, "subdomain_recon")

    def test_save_from_secator_ancestor_id_fallback_to_api(self):
        """Test that ancestor_id falls back to API value when node_id has no dot."""
        runner_data = {
            "name": "task",
            "cmd": "task command",
            "output": "Output",
            "config": {
                "type": "task",
                "node_id": "simple_task",  # No dot
            },
            "context": {
                "ancestor_id": "workflow_from_api",
            },
        }

        result = self.command_repo.save_from_secator(runner_data, self.scan_history.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.ancestor_id, "workflow_from_api")

    def test_save_from_secator_ancestor_id_no_node_id(self):
        """Test that ancestor_id uses API value when node_id is None."""
        runner_data = {
            "name": "task",
            "cmd": "task command",
            "output": "Output",
            "config": {
                "type": "task",
            },
            "context": {
                "ancestor_id": "workflow_from_api",
            },
        }

        result = self.command_repo.save_from_secator(runner_data, self.scan_history.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.ancestor_id, "workflow_from_api")

    def test_save_from_secator_ancestor_id_node_id_priority(self):
        """Test that node_id takes priority over API ancestor_id when both are present."""
        runner_data = {
            "name": "gau",
            "cmd": "gau example.com",
            "output": "Output",
            "config": {
                "type": "task",
                "node_id": "subdomain_recon.gau",
            },
            "context": {
                "ancestor_id": "wrong_workflow",  # Should be ignored
            },
        }

        result = self.command_repo.save_from_secator(runner_data, self.scan_history.id)

        self.assertIsNotNone(result)
        self.assertEqual(result.ancestor_id, "subdomain_recon")  # From node_id, not API
