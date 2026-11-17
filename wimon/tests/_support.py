"""Shared test helpers."""

from __future__ import annotations


class SkipTest(Exception):
    """Raised when a test needs capture input that is not available."""
