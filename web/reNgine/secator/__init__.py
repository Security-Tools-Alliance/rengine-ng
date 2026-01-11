"""
Secator integration module for reNgine.

This module provides all Secator-related functionality:
- Runner: Interface with Secator library
- Orchestrator: High-level scan orchestration
- Config: Configuration conversion
- Parser: Result parsing
- Control: Scan lifecycle control
- Progress: Progress synchronization
- Tasks: Celery task functions
"""

from reNgine.secator.config import SecatorConfigConverter
from reNgine.secator.control import SecatorScanController
from reNgine.secator.orchestrator import ScanOrchestrator
from reNgine.secator.parser import SecatorParser
from reNgine.secator.progress import SecatorProgressSync
from reNgine.secator.runner import SecatorRunner
from reNgine.secator.service import handle_scan_error, start_secator_scan
from reNgine.secator.tasks import build_enriched_targets, initiate_secator_scan


__all__ = [
    "SecatorRunner",
    "SecatorConfigConverter",
    "SecatorParser",
    "SecatorScanController",
    "ScanOrchestrator",
    "SecatorProgressSync",
    "initiate_secator_scan",
    "build_enriched_targets",
    "start_secator_scan",
    "handle_scan_error",
]
