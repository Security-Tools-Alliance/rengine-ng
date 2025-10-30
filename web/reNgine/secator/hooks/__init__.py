"""
Secator hooks module.
All hooks are now API-only (no Django dependencies).
"""

from .database_hooks import DatabaseHooks
from .progress_hooks import ProgressHooks


__all__ = ["DatabaseHooks", "ProgressHooks"]
