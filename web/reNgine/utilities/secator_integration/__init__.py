"""
Secator integration package for reNgine.

This package provides integration between reNgine's distributed processing system
and Secator workflows, following SOLID, KISS, and DRY principles.

Key components:
1. SecatorDistributedProcessor - Main integration interface
2. ReNgineToSecatorConverter - Converts legacy scan engines to Secator workflows
3. SecatorConfig - Configuration management for Secator integration
4. SecatorWorkflowManager - Manages Secator workflows and execution
"""

from .config import SecatorConfig
from .converter import ReNgineToSecatorConverter
from .manager import SecatorWorkflowManager
from .processor import SecatorDistributedProcessor


__all__ = ["SecatorDistributedProcessor", "ReNgineToSecatorConverter", "SecatorConfig", "SecatorWorkflowManager"]
