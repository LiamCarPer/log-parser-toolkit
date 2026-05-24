"""
IOC Extraction Engine for Log Parser Toolkit.

Public API:
    IOCExtractor — Middleware that extracts IOCs from log records
                   and writes a structured JSON report.
"""

from .extractor import IOCExtractor

__all__ = ["IOCExtractor"]
