"""
SIGMA Rule Integration for Log Parser Toolkit.

Public API:
    SigmaRule         — Parses and evaluates a single SIGMA rule dict.
    SigmaAnalyzer     — Middleware that evaluates loaded rules against log records.
    load_rules_from_path — Load all .yml/.yaml rules from a file or directory.
"""

from .evaluator import SigmaRule
from .loader import SigmaAnalyzer, load_rules_from_path

__all__ = ["SigmaRule", "SigmaAnalyzer", "load_rules_from_path"]
