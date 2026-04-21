"""
Standalone script run inside the Secator worker container.
Reads a job JSON file and executes the Secator workflow/scan/tasks with API hooks.
Do not import reNgine - only secator and stdlib.
Usage:
  python worker_run_job.py <job.json>
  python worker_run_job.py revoke <celery_id>
"""

from __future__ import annotations

import json
from pathlib import Path
import sys


def _run_revoke_mode(celery_id: str) -> None:
    """Revoke a Celery task using Secator (same as local control.revoke_task)."""
    try:
        from secator.celery import revoke_task

        revoke_task(celery_id)
        sys.exit(0)
    except Exception as e:
        print(f"Revoke failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python worker_run_job.py <job.json> | revoke <celery_id>", file=sys.stderr)
        sys.exit(1)
    if sys.argv[1] == "revoke":
        if len(sys.argv) < 3:
            print("Usage: python worker_run_job.py revoke <celery_id>", file=sys.stderr)
            sys.exit(1)
        _run_revoke_mode(sys.argv[2])
    job_path = Path(sys.argv[1])
    if not job_path.exists():
        print(f"Job file not found: {job_path}", file=sys.stderr)
        sys.exit(1)
    with job_path.open() as f:
        job = json.load(f)

    execution_mode = job.get("execution_mode")
    targets = job.get("targets") or []
    context = job.get("context") or {}
    run_opts_data = job.get("run_opts") or {}
    raw_profiles = run_opts_data.get("profiles") or []

    try:
        from secator.runners import Scan, Task, Workflow
        from secator.template import TemplateLoader
    except ImportError as e:
        print(f"Secator import failed: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        from secator.hooks.api import HOOKS

        hooks = HOOKS
    except ImportError:
        hooks = {}

    profile_loaders = []
    for p in raw_profiles:
        if not p:
            continue
        if isinstance(p, dict):
            profile_loaders.append(TemplateLoader(p))
        else:
            profile_loaders.append(TemplateLoader(name=f"profiles/{p}"))
    run_opts = {**run_opts_data, "profiles": profile_loaders}
    run_opts["sync"] = False

    def _run_success(result) -> bool:
        """
        Consider run successful from Secator runner.run() return value.
        Prefer explicit status when Secator exposes it (e.g. result.status or result.get("status"));
        otherwise use heuristics: list of outputs -> success, dict with status key -> check value.
        If Secator adds a stable success/exception API, prefer that to avoid misclassifying on format changes.
        """
        if isinstance(result, dict):
            explicit = result.get("status") or result.get("success")
            if explicit is not None:
                return explicit is True or explicit == "success"
            return False
        if isinstance(result, list):
            return True
        return False

    try:
        if execution_mode == "workflow":
            workflow_name = job.get("workflow_name")
            if not workflow_name:
                print("workflow_name required", file=sys.stderr)
                sys.exit(1)
            config = TemplateLoader(name=f"workflows/{workflow_name}")
            runner = Workflow(config, inputs=targets, hooks=hooks, run_opts=run_opts, context=context)
        elif execution_mode == "scan":
            scan_type = job.get("scan_type")
            if not scan_type:
                print("scan_type required", file=sys.stderr)
                sys.exit(1)
            config = TemplateLoader(name=f"scans/{scan_type}")
            runner = Scan(config, inputs=targets, hooks=hooks, run_opts=run_opts, context=context)
        elif execution_mode == "tasks":
            task_names = job.get("task_names") or []
            if not task_names:
                print("task_names required", file=sys.stderr)
                sys.exit(1)
            all_success = True
            for task_name in task_names:
                config = TemplateLoader({"type": "task", "name": task_name})
                runner = Task(config, inputs=targets, hooks=hooks, run_opts=run_opts, context=context)
                result = runner.run()
                if not _run_success(result):
                    all_success = False
            sys.exit(0 if all_success else 1)
        else:
            print(f"Unknown execution_mode: {execution_mode}", file=sys.stderr)
            sys.exit(1)

        if execution_mode in ("workflow", "scan"):
            result = runner.run()
            sys.exit(0 if _run_success(result) else 1)
    except Exception as e:
        print(f"Run failed: {e}", file=sys.stderr)
        sys.exit(1)
