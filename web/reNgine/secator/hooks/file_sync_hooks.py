"""
File synchronization hooks for Secator results.

This module provides hooks to synchronize Secator output files
to the RENGINE_RESULTS directory structure for web interface compatibility.
"""

import os
import shutil
from typing import Any, Dict, List, Optional

from celery.utils.log import get_task_logger

from reNgine.settings import RENGINE_RESULTS


logger = get_task_logger(__name__)


class FileSyncHooks:
    """Hooks for synchronizing Secator files to RENGINE_RESULTS structure."""

    def __init__(self, scan_history_id: int, domain_id: int, domain_name: str):
        """
        Initialize file sync hooks.

        Args:
            scan_history_id: ID of the scan history
            domain_id: ID of the domain
            domain_name: Name of the domain for organizing files
        """
        self.scan_history_id = scan_history_id
        self.domain_id = domain_id
        self.domain_name = domain_name
        self.domain_results_dir = os.path.join(RENGINE_RESULTS, domain_name)

        # Ensure domain directory exists
        os.makedirs(self.domain_results_dir, exist_ok=True)

        logger.info(f"FileSyncHooks initialized for domain: {domain_name}")
        logger.info(f"Results directory: {self.domain_results_dir}")

    def on_workflow_start(self, workflow_name: str, targets: List[str]) -> None:
        """
        Called when a workflow starts.

        Args:
            workflow_name: Name of the workflow
            targets: List of targets
        """
        logger.info(f"Workflow {workflow_name} started for {len(targets)} targets")

        # Create scan-specific subdirectory
        scan_dir = os.path.join(self.domain_results_dir, f"scan_{self.scan_history_id}")
        os.makedirs(scan_dir, exist_ok=True)

        # Create a scan info file
        scan_info = {
            "workflow_name": workflow_name,
            "targets": targets,
            "scan_history_id": self.scan_history_id,
            "domain_name": self.domain_name,
        }

        import json

        scan_info_file = os.path.join(scan_dir, "scan_info.json")
        with open(scan_info_file, "w") as f:
            json.dump(scan_info, f, indent=2)

    def on_task_start(self, task_name: str, target: str) -> None:
        """
        Called when a task starts.

        Args:
            task_name: Name of the task
            target: Target being processed
        """
        logger.debug(f"Task {task_name} started for target: {target}")

    def on_task_complete(self, task_name: str, target: str, output_files: List[str]) -> None:
        """
        Called when a task completes.

        Args:
            task_name: Name of the task
            target: Target that was processed
            output_files: List of output files generated
        """
        if not output_files:
            return

        logger.info(f"Task {task_name} completed for {target}, syncing {len(output_files)} files")

        # Create task-specific directory
        task_dir = os.path.join(self.domain_results_dir, f"scan_{self.scan_history_id}", task_name)
        os.makedirs(task_dir, exist_ok=True)

        # Copy files to RENGINE_RESULTS structure
        for file_path in output_files:
            if os.path.exists(file_path):
                filename = os.path.basename(file_path)
                dest_path = os.path.join(task_dir, filename)

                try:
                    shutil.copy2(file_path, dest_path)
                    logger.debug(f"Copied {file_path} to {dest_path}")
                except Exception as e:
                    logger.error(f"Failed to copy {file_path} to {dest_path}: {e}")

    def on_workflow_complete(self, workflow_name: str, results: Dict[str, Any]) -> None:
        """
        Called when a workflow completes.

        Args:
            workflow_name: Name of the workflow
            results: Workflow results
        """
        logger.info(f"Workflow {workflow_name} completed")

        # Create a summary file
        scan_dir = os.path.join(self.domain_results_dir, f"scan_{self.scan_history_id}")
        summary_file = os.path.join(scan_dir, "workflow_summary.json")

        import json

        with open(summary_file, "w") as f:
            json.dump(results, f, indent=2, default=str)

    def sync_file(self, source_path: str, relative_dest: str = None) -> Optional[str]:
        """
        Sync a single file to the domain results directory.

        Args:
            source_path: Path to the source file
            relative_dest: Relative destination path (optional)

        Returns:
            Destination path if successful, None otherwise
        """
        if not os.path.exists(source_path):
            logger.warning(f"Source file does not exist: {source_path}")
            return None

        if relative_dest is None:
            relative_dest = os.path.basename(source_path)

        dest_path = os.path.join(self.domain_results_dir, relative_dest)

        # Ensure destination directory exists
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)

        try:
            shutil.copy2(source_path, dest_path)
            logger.debug(f"Synced {source_path} to {dest_path}")
            return dest_path
        except Exception as e:
            logger.error(f"Failed to sync {source_path} to {dest_path}: {e}")
            return None

    def get_domain_results_path(self) -> str:
        """
        Get the domain results directory path.

        Returns:
            Path to the domain results directory
        """
        return self.domain_results_dir

    def list_scan_files(self, scan_id: int = None) -> List[str]:
        """
        List files for a specific scan.

        Args:
            scan_id: Scan ID (defaults to current scan)

        Returns:
            List of file paths
        """
        if scan_id is None:
            scan_id = self.scan_history_id

        scan_dir = os.path.join(self.domain_results_dir, f"scan_{scan_id}")

        if not os.path.exists(scan_dir):
            return []

        files = []
        for root, dirs, filenames in os.walk(scan_dir):
            for filename in filenames:
                files.append(os.path.join(root, filename))

        return files
