"""
Unit tests for InputTypeService.
"""

from unittest.mock import patch

from reNgine.secator.services.input_type_service import (
    InputTypeService,
    _template_from_yaml_string,
)
from utils.test_base import BaseTestCase


class TestInputTypeService(BaseTestCase):
    """Test cases for InputTypeService."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.data_generator.create_essential_scan_engine_setup()
        self.secator_workflow = self.data_generator.create_secator_workflow()
        self.secator_scan = self.data_generator.create_secator_scan()
        self.secator_task = self.data_generator.create_secator_task()

    @patch.object(InputTypeService, "get_input_types_for_workflow")
    def test_get_input_types_by_workflow_id(self, mock_get):
        """get_input_types with workflow_id resolves and returns input_types."""
        mock_get.return_value = ["url", "host"]
        result = InputTypeService.get_input_types(workflow_id=self.secator_workflow.id)
        mock_get.assert_called_once_with(self.secator_workflow.name)
        self.assertEqual(result, ["url", "host"])

    @patch.object(InputTypeService, "get_input_types_for_workflow")
    def test_get_input_types_by_workflow_name(self, mock_get):
        """get_input_types with workflow_name returns input_types."""
        mock_get.return_value = ["host"]
        result = InputTypeService.get_input_types(workflow_name=self.secator_workflow.name)
        mock_get.assert_called_once_with(self.secator_workflow.name)
        self.assertEqual(result, ["host"])

    @patch.object(InputTypeService, "get_input_types_for_scan")
    def test_get_input_types_by_scan_id(self, mock_get):
        """get_input_types with scan_id resolves and returns input_types."""
        mock_get.return_value = ["domain"]
        result = InputTypeService.get_input_types(scan_id=self.secator_scan.id)
        mock_get.assert_called_once_with(self.secator_scan.name)
        self.assertEqual(result, ["domain"])

    @patch.object(InputTypeService, "get_input_types_for_scan")
    def test_get_input_types_by_scan_name(self, mock_get):
        """get_input_types with scan_name returns input_types."""
        mock_get.return_value = ["domain"]
        result = InputTypeService.get_input_types(scan_name="domain")
        mock_get.assert_called_once_with("domain")
        self.assertEqual(result, ["domain"])

    @patch.object(InputTypeService, "get_input_types_for_task")
    def test_get_input_types_by_task_id(self, mock_get):
        """get_input_types with task_id resolves and returns input_types."""
        mock_get.return_value = ["url"]
        result = InputTypeService.get_input_types(task_id=self.secator_task.id)
        mock_get.assert_called_once_with(self.secator_task.task_type)
        self.assertEqual(result, ["url"])

    @patch.object(InputTypeService, "get_input_types_for_task")
    def test_get_input_types_by_task_name(self, mock_get):
        """get_input_types with task_name returns input_types."""
        mock_get.return_value = ["url"]
        result = InputTypeService.get_input_types(task_name=self.secator_task.task_type)
        mock_get.assert_called_once_with(self.secator_task.task_type)
        self.assertEqual(result, ["url"])

    def test_get_input_types_raises_when_none_provided(self):
        """get_input_types raises ValueError when no workflow/scan/task provided."""
        with self.assertRaises(ValueError) as ctx:
            InputTypeService.get_input_types()
        self.assertIn("Exactly one", str(ctx.exception))

    def test_get_input_types_raises_when_multiple_provided(self):
        """get_input_types raises ValueError when more than one of workflow/scan/task provided."""
        with self.assertRaises(ValueError) as ctx:
            InputTypeService.get_input_types(
                workflow_id=self.secator_workflow.id,
                scan_id=self.secator_scan.id,
            )
        self.assertIn("Exactly one", str(ctx.exception))

    def test_get_input_types_raises_when_workflow_name_empty(self):
        """get_input_types raises ValueError when workflow_name is empty or whitespace."""
        with self.assertRaises(ValueError) as ctx:
            InputTypeService.get_input_types(workflow_name="")
        self.assertIn("workflow_name must be non-empty", str(ctx.exception))
        with self.assertRaises(ValueError) as ctx:
            InputTypeService.get_input_types(workflow_name="   ")
        self.assertIn("workflow_name must be non-empty", str(ctx.exception))

    def test_get_input_types_raises_when_scan_name_empty(self):
        """get_input_types raises ValueError when scan_name is empty or whitespace."""
        with self.assertRaises(ValueError) as ctx:
            InputTypeService.get_input_types(scan_name="")
        self.assertIn("scan_name must be non-empty", str(ctx.exception))

    def test_get_input_types_raises_when_task_name_empty(self):
        """get_input_types raises ValueError when task_name is empty or whitespace."""
        with self.assertRaises(ValueError) as ctx:
            InputTypeService.get_input_types(task_name="")
        self.assertIn("task_name must be non-empty", str(ctx.exception))

    @patch("reNgine.secator.services.input_type_service.TemplateLoader")
    def test_get_input_types_for_workflow_builtin(self, mock_loader):
        """get_input_types_for_workflow loads config and returns input_types for builtin."""
        mock_loader.return_value = {"input_types": ["url", "host"]}
        self.secator_workflow.workflow_type = "builtin"
        self.secator_workflow.save()
        result = InputTypeService.get_input_types_for_workflow(self.secator_workflow.name)
        self.assertEqual(result, ["url", "host"])

    @patch("reNgine.secator.services.input_type_service.TemplateLoader")
    def test_get_input_types_for_workflow_empty_config(self, mock_loader):
        """get_input_types_for_workflow returns empty list when no input_types in config."""
        mock_loader.return_value = {}
        self.secator_workflow.workflow_type = "builtin"
        self.secator_workflow.save()
        result = InputTypeService.get_input_types_for_workflow(self.secator_workflow.name)
        self.assertEqual(result, [])

    @patch("reNgine.secator.services.input_type_service._template_from_yaml_string")
    def test_get_input_types_for_workflow_custom_uses_template_from_yaml(self, mock_template):
        """get_input_types_for_workflow uses _template_from_yaml_string for custom workflows."""
        mock_template.return_value = type(
            "Config", (), {"get": lambda s, k, d=None: ["ip", "cidr_range"] if k == "input_types" else d}
        )()
        self.secator_workflow.workflow_type = "custom"
        self.secator_workflow.yaml_configuration = "name: test\ninput_types:\n  - ip\n  - cidr_range\n"
        self.secator_workflow.save()
        result = InputTypeService.get_input_types_for_workflow(self.secator_workflow.name)
        mock_template.assert_called_once_with("name: test\ninput_types:\n  - ip\n  - cidr_range\n")
        self.assertEqual(result, ["ip", "cidr_range"])

    @patch("reNgine.secator.services.input_type_service.TemplateLoader")
    def test_template_from_yaml_string_raises_on_none(self, mock_loader):
        """_template_from_yaml_string raises ValueError when YAML loads to None (empty/invalid)."""
        with self.assertRaises(ValueError) as ctx:
            _template_from_yaml_string("")
        self.assertIn("Got None", str(ctx.exception))
        mock_loader.assert_not_called()

    @patch("reNgine.secator.services.input_type_service.TemplateLoader")
    def test_template_from_yaml_string_raises_on_non_dict(self, mock_loader):
        """_template_from_yaml_string raises ValueError when YAML is not a dict."""
        with self.assertRaises(ValueError) as ctx:
            _template_from_yaml_string("- a\n- b\n")
        self.assertIn("dictionary", str(ctx.exception))
        mock_loader.assert_not_called()
