"""
Secator integration module for reNgine.

This module provides the interface between reNgine and Secator,
allowing reNgine to use Secator as a library for orchestrated scanning.
"""

from .runner import SecatorRunner
from .parser import SecatorParser
from .config import SecatorConfigConverter

__all__ = ["SecatorRunner", "SecatorParser", "SecatorConfigConverter"]
