"""
Input type service - retrieves Secator workflow/scan/task input_types from configs.
"""

from typing import Any, List

from secator.template import TemplateLoader
import yaml


INPUT_TYPE_NORMALIZE: dict = {"host_port": "host:port"}


def _normalize_input_types(types: List[str]) -> List[str]:
    """
    Normalize input type strings to canonical Secator form (e.g. host_port -> host:port).
    Preserves order and deduplicates after replacement.
    """
    seen: set = set()
    result: List[str] = []
    for t in types or []:
        if not isinstance(t, str):
            continue
        raw = t.strip()
        canonical = INPUT_TYPE_NORMALIZE.get(raw.lower(), raw)
        if canonical and canonical not in seen:
            seen.add(canonical)
            result.append(canonical)
    return result


def _template_from_yaml_string(yaml_content: str) -> TemplateLoader:
    """
    Load TemplateLoader from YAML string without passing the string as a path.

    Secator's TemplateLoader(input=string) evaluates Path(input).exists() and
    treats a long YAML string as a path, causing Errno 36 (File name too long).
    Parse YAML to dict first and pass input=dict so TemplateLoader uses it as config.
    """
    loaded: Any = yaml.safe_load(yaml_content)
    if loaded is None:
        raise ValueError(
            "Secator YAML configuration must be a non-empty dictionary. Got None (e.g. empty or invalid YAML)."
        )
    if not isinstance(loaded, dict):
        raise ValueError(
            "Secator YAML configuration must be a dictionary (key-value map). Got invalid type from YAML content."
        )
    return TemplateLoader(input=loaded)


class InputTypeService:
    """Service to extract input_types from Secator workflow, scan, or task configs."""

    @staticmethod
    def get_input_types_for_workflow(workflow_name: str) -> List[str]:
        """
        Get input_types for a workflow by name.

        Args:
            workflow_name: Workflow name (from SecatorWorkflow.name)

        Returns:
            List of input type strings (e.g. ['url'], ['host', 'ip'])
        """
        from scanEngine.models import SecatorWorkflow

        workflow_obj = SecatorWorkflow.objects.get(name=workflow_name)
        config = (
            TemplateLoader(name=f"workflows/{workflow_name}")
            if workflow_obj.workflow_type == "builtin"
            else _template_from_yaml_string(workflow_obj.yaml_configuration or "")
        )
        raw = list(config.get("input_types", []) or [])
        return _normalize_input_types(raw)

    @staticmethod
    def get_input_types_for_scan(scan_name: str) -> List[str]:
        """
        Get input_types for a scan by name.

        Args:
            scan_name: Scan name (from SecatorScan.name)

        Returns:
            List of input type strings
        """
        from scanEngine.models import SecatorScan

        scan_obj = SecatorScan.objects.get(name=scan_name)
        config = (
            TemplateLoader(name=f"scan/{scan_name}")
            if scan_obj.scan_config_type == "builtin"
            else _template_from_yaml_string(scan_obj.yaml_configuration or "")
        )
        raw = list(config.get("input_types", []) or [])
        return _normalize_input_types(raw)

    @staticmethod
    def get_input_types_for_task(task_name: str) -> List[str]:
        """
        Get input_types for a task by type name (Secator task type, e.g. 'httpx', 'nuclei').

        Args:
            task_name: Task type name (from SecatorTask.task_type)

        Returns:
            List of input type strings (from task class input_types)
        """
        from secator.runners import Task

        task_cls = Task.get_task_class(task_name)
        if task_cls is None:
            return []
        return list(getattr(task_cls, "input_types", []) or [])

    @classmethod
    def get_input_types(
        cls,
        *,
        workflow_id: int = None,
        scan_id: int = None,
        task_id: int = None,
        workflow_name: str = None,
        scan_name: str = None,
        task_name: str = None,
    ) -> List[str]:
        """
        Get input_types for the given workflow, scan, or task (exactly one must be provided).

        Args:
            workflow_id: SecatorWorkflow ID (resolved to name)
            scan_id: SecatorScan ID (resolved to name)
            task_id: SecatorTask ID (resolved to task_type)
            workflow_name: Workflow name (used if workflow_id not set)
            scan_name: Scan name (used if scan_id not set)
            task_name: Task type name (used if task_id not set)

        Returns:
            List of input type strings

        Raises:
            ValueError: If none or more than one of workflow/scan/task is specified
        """
        from scanEngine.models import SecatorScan, SecatorTask, SecatorWorkflow

        has_workflow = workflow_id is not None or workflow_name is not None
        has_scan = scan_id is not None or scan_name is not None
        has_task = task_id is not None or task_name is not None
        if sum([has_workflow, has_scan, has_task]) != 1:
            raise ValueError(
                "Exactly one entity type (workflow, scan, or task) must be specified, via either its id or name."
            )
        if workflow_name is not None and not (workflow_name and workflow_name.strip()):
            raise ValueError("workflow_name must be non-empty when provided.")
        if scan_name is not None and not (scan_name and scan_name.strip()):
            raise ValueError("scan_name must be non-empty when provided.")
        if task_name is not None and not (task_name and task_name.strip()):
            raise ValueError("task_name must be non-empty when provided.")
        if has_workflow and workflow_id is not None and workflow_name is not None:
            raise ValueError("Provide either workflow_id or workflow_name, not both.")
        if has_scan and scan_id is not None and scan_name is not None:
            raise ValueError("Provide either scan_id or scan_name, not both.")
        if has_task and task_id is not None and task_name is not None:
            raise ValueError("Provide either task_id or task_name, not both.")

        if workflow_id is not None:
            name = SecatorWorkflow.objects.values_list("name", flat=True).get(id=workflow_id)
            return cls.get_input_types_for_workflow(name)
        if workflow_name:
            return cls.get_input_types_for_workflow(workflow_name)

        if scan_id is not None:
            name = SecatorScan.objects.values_list("name", flat=True).get(id=scan_id)
            return cls.get_input_types_for_scan(name)
        if scan_name:
            return cls.get_input_types_for_scan(scan_name)

        if task_id is not None:
            task_type = SecatorTask.objects.values_list("task_type", flat=True).get(id=task_id)
            return cls.get_input_types_for_task(task_type)
        if task_name:
            return cls.get_input_types_for_task(task_name)

        raise ValueError(
            "Exactly one entity type (workflow, scan, or task) must be specified, via either its id or name."
        )
