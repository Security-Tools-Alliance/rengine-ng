"""
test_secator_models.py

This file contains unit tests for the Secator models (SecatorScan, SecatorWorkflow, SecatorTask).
"""


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

    def test_builtin_workflow_modification_blocked(self):
        """Test that built-in workflows cannot be modified."""
        workflow = SecatorWorkflow.objects.create(workflow_type="builtin", **self.workflow_data)

        # Try to modify
        workflow.name = "Modified Name"
        with self.assertRaises(PermissionError):
            workflow.save()

    def test_builtin_workflow_deletion_blocked(self):
        """Test that built-in workflows cannot be deleted."""
        workflow = SecatorWorkflow.objects.create(workflow_type="builtin", **self.workflow_data)

        with self.assertRaises(PermissionError):
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
            "category": "dns/recon",
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
        with self.assertRaises(PermissionError):
            task.save()

    def test_builtin_task_deletion_blocked(self):
        """Test that built-in tasks cannot be deleted."""
        task = SecatorTask.objects.create(**self.task_data)

        with self.assertRaises(PermissionError):
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
            "alias": "domain",
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

    def test_builtin_scan_modification_blocked(self):
        """Test that built-in scans cannot be modified."""
        scan = SecatorScan.objects.create(**self.scan_data)

        # Try to modify
        scan.name = "Modified Name"
        with self.assertRaises(PermissionError):
            scan.save()

    def test_builtin_scan_deletion_blocked(self):
        """Test that built-in scans cannot be deleted."""
        scan = SecatorScan.objects.create(**self.scan_data)

        with self.assertRaises(PermissionError):
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
