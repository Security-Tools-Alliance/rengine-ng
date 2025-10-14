"""
Secator integration module for reNgine.

This module provides the interface between reNgine and Secator,
allowing reNgine to use Secator as a library for orchestrated scanning.
"""

from .config import SecatorConfigConverter
from .parser import SecatorParser
from .runner import SecatorRunner


__all__ = ["SecatorRunner", "SecatorParser", "SecatorConfigConverter"]
