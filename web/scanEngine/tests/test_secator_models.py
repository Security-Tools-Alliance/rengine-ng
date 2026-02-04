"""
test_secator_models.py

This file contains unit tests for the Secator models (SecatorScan, SecatorWorkflow, SecatorTask).
"""

from django.core.exceptions import PermissionDenied

from scanEngine.models import SecatorScan, SecatorTask, SecatorWorkflow
from utils.test_base import BaseTestCase


class TestSecatorWorkflow(BaseTestCase):
    """Test class for SecatorWorkflow model."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.workflow_data = {
            "name": "Test Workflow",
            "alias": "test_workflow",
            "description": "A test workflow",
            "scan_type": "internet",
            "yaml_configuration": """
type: workflow
name: test_workflow
description: A test workflow
tasks:
  subfinder:
    description: Find subdomains
  httpx:
    description: Probe HTTP services
""",
            "is_active": True,
        }

    def test_create_builtin_workflow(self):
        """Test creating a built-in workflow."""
        workflow = SecatorWorkflow.objects.create(workflow_type="builtin", **self.workflow_data)
        self.assertEqual(workflow.workflow_type, "builtin")
        self.assertFalse(workflow.can_modify())
        self.assertFalse(workflow.can_delete())

    def test_create_custom_workflow(self):
        """Test creating a custom workflow."""
        workflow = SecatorWorkflow.objects.create(workflow_type="custom", **self.workflow_data)
        self.assertEqual(workflow.workflow_type, "custom")
        self.assertTrue(workflow.can_modify())
        self.assertTrue(workflow.can_delete())

    def test_parse_yaml_config(self):
        """Test YAML configuration parsing."""
        workflow = SecatorWorkflow.objects.create(workflow_type="custom", **self.workflow_data)
        config = workflow._parse_yaml_config()
        self.assertIsInstance(config, dict)
        self.assertEqual(config.get("type"), "workflow")
        self.assertEqual(config.get("name"), "test_workflow")

    def test_get_tasks(self):
        """Test getting tasks from YAML configuration."""
        workflow = SecatorWorkflow.objects.create(workflow_type="custom", **self.workflow_data)
        tasks = workflow.get_tasks()
        self.assertIsInstance(tasks, dict)
        self.assertIn("subfinder", tasks)
        self.assertIn("httpx", tasks)

    def test_get_structured_tasks_without_groups(self):
        """Test getting structured tasks from workflow without groups."""
        workflow = SecatorWorkflow.objects.create(workflow_type="custom", **self.workflow_data)
        structured = workflow.get_structured_tasks()

        self.assertIsInstance(structured, list)
        self.assertEqual(len(structured), 2)

        # Check that both items are tasks (not groups)
        for item in structured:
            self.assertEqual(item["type"], "task")
            self.assertIn(item["name"], ["subfinder", "httpx"])
            self.assertIsNone(item["group"])

    def test_get_structured_tasks_with_groups(self):
        """Test getting structured tasks from workflow with groups."""
        workflow_data = {
            "name": "Test Workflow with Groups",
            "alias": "test_workflow_groups",
            "description": "A test workflow with groups",
            "scan_type": "internet",
            "yaml_configuration": """
type: workflow
name: test_workflow_groups
description: A test workflow with groups
tasks:
  _group/discover:
    netdetect:
      description: Discover network
    arp:
      description: ARP scan
  prompt:
    description: Manual prompt
  _group/probe:
    arpscan:
      description: ARP scan
    fping:
      description: ICMP ping
  search_vulns:
    description: Search vulnerabilities
""",
            "is_active": True,
        }
        workflow = SecatorWorkflow.objects.create(workflow_type="custom", **workflow_data)
        structured = workflow.get_structured_tasks()

        self.assertIsInstance(structured, list)
        self.assertEqual(len(structured), 4)

        # Check first group
        self.assertEqual(structured[0]["type"], "group")
        self.assertEqual(structured[0]["name"], "_group/discover")
        self.assertEqual(structured[0]["display_name"], "discover")
        self.assertEqual(len(structured[0]["tasks"]), 2)
        self.assertIn("netdetect", structured[0]["tasks"])
        self.assertIn("arp", structured[0]["tasks"])

        # Check individual task
        self.assertEqual(structured[1]["type"], "task")
        self.assertEqual(structured[1]["name"], "prompt")
        self.assertIsNone(structured[1]["group"])

        # Check second group
        self.assertEqual(structured[2]["type"], "group")
        self.assertEqual(structured[2]["name"], "_group/probe")
        self.assertEqual(structured[2]["display_name"], "probe")
        self.assertEqual(len(structured[2]["tasks"]), 2)
        self.assertIn("arpscan", structured[2]["tasks"])
        self.assertIn("fping", structured[2]["tasks"])

        # Check second individual task
        self.assertEqual(structured[3]["type"], "task")
        self.assertEqual(structured[3]["name"], "search_vulns")
        self.assertIsNone(structured[3]["group"])

    def test_get_tasks_count(self):
        """Test getting total count of individual tasks."""
        workflow_data = {
            "name": "Test Workflow Count",
            "alias": "test_workflow_count",
            "description": "A test workflow for counting",
            "scan_type": "internet",
            "yaml_configuration": """
type: workflow
name: test_workflow_count
description: A test workflow for counting
tasks:
  _group/discover:
    netdetect:
      description: Discover network
    arp:
      description: ARP scan
  prompt:
    description: Manual prompt
  _group/probe:
    arpscan:
      description: ARP scan
    fping:
      description: ICMP ping
    nmap:
      description: Port scan
  search_vulns:
    description: Search vulnerabilities
""",
            "is_active": True,
        }
        workflow = SecatorWorkflow.objects.create(workflow_type="custom", **workflow_data)

        # Should count: 2 (from _group/discover) + 1 (prompt) + 3 (from _group/probe) + 1 (search_vulns) = 7
        count = workflow.get_tasks_count()
        self.assertEqual(count, 7)

    def test_get_structured_tasks_empty(self):
        """Test getting structured tasks from workflow with no tasks."""
        workflow_data = {
            "name": "Test Workflow Empty",
            "alias": "test_workflow_empty",
            "description": "A test workflow with no tasks",
            "scan_type": "internet",
            "yaml_configuration": """
type: workflow
name: test_workflow_empty
description: A test workflow with no tasks
tasks: {}
""",
            "is_active": True,
        }
        workflow = SecatorWorkflow.objects.create(workflow_type="custom", **workflow_data)
        structured = workflow.get_structured_tasks()

        self.assertIsInstance(structured, list)
        self.assertEqual(len(structured), 0)

        count = workflow.get_tasks_count()
        self.assertEqual(count, 0)

    def test_get_structured_tasks_with_group_no_suffix(self):
        """Test getting structured tasks from workflow with _group without suffix."""
        workflow_data = {
            "name": "Test Workflow Group No Suffix",
            "alias": "test_workflow_group_no_suffix",
            "description": "A test workflow with _group without suffix",
            "scan_type": "internet",
            "yaml_configuration": """
type: workflow
name: test_workflow_group_no_suffix
description: A test workflow with _group without suffix
tasks:
  _group:
    jswhois:
      description: Get WHOIS information
    httpx:
      description: Run HTTP probe
    getasn:
      description: Get ASN from domain
  wafw00f:
    description: Check WAF
""",
            "is_active": True,
        }
        workflow = SecatorWorkflow.objects.create(workflow_type="custom", **workflow_data)
        structured = workflow.get_structured_tasks()

        self.assertIsInstance(structured, list)
        self.assertEqual(len(structured), 2)

        # Check group without suffix
        self.assertEqual(structured[0]["type"], "group")
        self.assertEqual(structured[0]["name"], "_group")
        self.assertEqual(structured[0]["display_name"], "tasks")
        self.assertEqual(len(structured[0]["tasks"]), 3)
        self.assertIn("jswhois", structured[0]["tasks"])
        self.assertIn("httpx", structured[0]["tasks"])
        self.assertIn("getasn", structured[0]["tasks"])

        # Check individual task
        self.assertEqual(structured[1]["type"], "task")
        self.assertEqual(structured[1]["name"], "wafw00f")
        self.assertIsNone(structured[1]["group"])

        # Check count
        count = workflow.get_tasks_count()
        self.assertEqual(count, 4)  # 3 from group + 1 individual

    def test_builtin_workflow_modification_blocked(self):
        """Test that built-in workflows cannot be modified."""
        workflow = SecatorWorkflow.objects.create(workflow_type="builtin", **self.workflow_data)

        # Try to modify
        workflow.name = "Modified Name"
        with self.assertRaises(PermissionDenied):
            workflow.save()

    def test_builtin_workflow_deletion_blocked(self):
        """Test that built-in workflows cannot be deleted."""
        workflow = SecatorWorkflow.objects.create(workflow_type="builtin", **self.workflow_data)

        with self.assertRaises(PermissionDenied):
            workflow.delete()

    def test_builtin_workflow_bypass_constraints(self):
        """Test that management commands can bypass constraints."""
        workflow = SecatorWorkflow.objects.create(workflow_type="builtin", **self.workflow_data)

        # Should work with bypass
        workflow.name = "Modified Name"
        workflow.save(bypass_builtin_constraints=True)
        workflow.refresh_from_db()
        self.assertEqual(workflow.name, "Modified Name")

        # Should work with bypass for deletion
        workflow.delete(bypass_builtin_constraints=True)
        self.assertFalse(SecatorWorkflow.objects.filter(id=workflow.id).exists())


class TestSecatorTask(BaseTestCase):
    """Test class for SecatorTask model."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.task_data = {
            "name": "Test Task",
            "task_type": "subfinder",
            "tags": ["dns", "recon"],
            "description": "A test task",
            "is_builtin": True,
            "is_active": True,
        }

    def test_create_builtin_task(self):
        """Test creating a built-in task."""
        task = SecatorTask.objects.create(**self.task_data)
        self.assertTrue(task.is_builtin)
        self.assertFalse(task.can_modify())
        self.assertFalse(task.can_delete())

    def test_create_custom_task(self):
        """Test creating a custom task."""
        task_data = self.task_data.copy()
        task_data["is_builtin"] = False
        task = SecatorTask.objects.create(**task_data)
        self.assertFalse(task.is_builtin)
        self.assertTrue(task.can_modify())
        self.assertTrue(task.can_delete())

    def test_builtin_task_modification_blocked(self):
        """Test that built-in tasks cannot be modified."""
        task = SecatorTask.objects.create(**self.task_data)

        # Try to modify
        task.name = "Modified Name"
        with self.assertRaises(PermissionDenied):
            task.save()

    def test_builtin_task_deletion_blocked(self):
        """Test that built-in tasks cannot be deleted."""
        task = SecatorTask.objects.create(**self.task_data)

        with self.assertRaises(PermissionDenied):
            task.delete()

    def test_builtin_task_bypass_constraints(self):
        """Test that management commands can bypass constraints."""
        task = SecatorTask.objects.create(**self.task_data)

        # Should work with bypass
        task.name = "Modified Name"
        task.save(bypass_builtin_constraints=True)
        task.refresh_from_db()
        self.assertEqual(task.name, "Modified Name")

        # Should work with bypass for deletion
        task.delete(bypass_builtin_constraints=True)
        self.assertFalse(SecatorTask.objects.filter(id=task.id).exists())


class TestSecatorScan(BaseTestCase):
    """Test class for SecatorScan model."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.scan_data = {
            "name": "Test Scan",
            "description": "A test scan",
            "scan_type": "internet",
            "scan_config_type": "builtin",
            "yaml_configuration": """
type: scan
name: domain
description: Domain reconnaissance scan
workflows:
  subdomain_recon:
    description: Find subdomains
  host_recon:
    description: Host discovery
input_types:
  - domain
""",
            "is_default": True,
            "is_active": True,
        }

    def test_create_builtin_scan(self):
        """Test creating a built-in scan."""
        scan = SecatorScan.objects.create(**self.scan_data)
        self.assertEqual(scan.scan_config_type, "builtin")
        self.assertFalse(scan.can_modify())
        self.assertFalse(scan.can_delete())

    def test_create_custom_scan(self):
        """Test creating a custom scan."""
        scan_data = self.scan_data.copy()
        scan_data["scan_config_type"] = "custom"
        scan = SecatorScan.objects.create(**scan_data)
        self.assertEqual(scan.scan_config_type, "custom")
        self.assertTrue(scan.can_modify())
        self.assertTrue(scan.can_delete())

    def test_parse_yaml_config(self):
        """Test YAML configuration parsing."""
        scan = SecatorScan.objects.create(**self.scan_data)
        config = scan._parse_yaml_config()
        self.assertIsInstance(config, dict)
        self.assertEqual(config.get("type"), "scan")
        self.assertEqual(config.get("name"), "domain")

    def test_get_workflows(self):
        """Test getting workflows from YAML configuration."""
        scan = SecatorScan.objects.create(**self.scan_data)
        workflows = scan.get_workflows()
        self.assertIsInstance(workflows, dict)
        self.assertIn("subdomain_recon", workflows)
        self.assertIn("host_recon", workflows)

    def test_get_input_types(self):
        """Test getting input types from YAML configuration."""
        scan = SecatorScan.objects.create(**self.scan_data)
        input_types = scan.get_input_types()
        self.assertIsInstance(input_types, list)
        self.assertIn("domain", input_types)

    def test_get_display_name(self):
        """Test get_display_name returns name with underscores replaced by spaces, preserving case."""
        scan = SecatorScan.objects.create(**self.scan_data)
        self.assertEqual(scan.get_display_name(), "Test Scan")
        scan.name = "subdomain_recon"
        self.assertEqual(scan.get_display_name(), "subdomain recon")

    def test_builtin_scan_modification_blocked(self):
        """Test that built-in scans cannot be modified."""
        scan = SecatorScan.objects.create(**self.scan_data)

        # Try to modify
        scan.name = "Modified Name"
        with self.assertRaises(PermissionDenied):
            scan.save()

    def test_builtin_scan_deletion_blocked(self):
        """Test that built-in scans cannot be deleted."""
        scan = SecatorScan.objects.create(**self.scan_data)

        with self.assertRaises(PermissionDenied):
            scan.delete()

    def test_builtin_scan_bypass_constraints(self):
        """Test that management commands can bypass constraints."""
        scan = SecatorScan.objects.create(**self.scan_data)

        # Should work with bypass
        scan.name = "Modified Name"
        scan.save(bypass_builtin_constraints=True)
        scan.refresh_from_db()
        self.assertEqual(scan.name, "Modified Name")

        # Should work with bypass for deletion
        scan.delete(bypass_builtin_constraints=True)
        self.assertFalse(SecatorScan.objects.filter(id=scan.id).exists())

    def test_invalid_yaml_handling(self):
        """Test handling of invalid YAML configuration."""
        scan_data = self.scan_data.copy()
        scan_data["yaml_configuration"] = "invalid: yaml: content: ["
        scan = SecatorScan.objects.create(**scan_data)

        # Should return empty dict for invalid YAML
        config = scan._parse_yaml_config()
        self.assertEqual(config, {})

        workflows = scan.get_workflows()
        self.assertEqual(workflows, {})

        input_types = scan.get_input_types()
        self.assertEqual(input_types, [])
