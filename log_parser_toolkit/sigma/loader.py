"""
SIGMA rule loader and middleware.

Provides:
    load_rules_from_path(path)  — Load .yml/.yaml SIGMA rules from a file or directory.
    SigmaAnalyzer               — Middleware that evaluates loaded rules and enriches logs.

Requires PyYAML (optional dependency):
    pip install "log-parser-toolkit[sigma]"
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .evaluator import SigmaRule

logger = logging.getLogger(__name__)


def load_rules_from_path(path: str) -> List[SigmaRule]:
    """
    Load SIGMA detection rules from a single YAML file or a directory of YAML files.

    Parameters
    ----------
    path:
        Path to a ``.yml``/``.yaml`` file or a directory containing them.
        Sub-directories are also searched (recursive glob).

    Returns
    -------
    list[SigmaRule]
        All successfully parsed rules, ordered by filename.

    Raises
    ------
    ImportError
        If PyYAML is not installed.
    FileNotFoundError
        If *path* does not exist.
    """
    try:
        import yaml  # type: ignore[import]
    except ImportError:
        raise ImportError(
            "PyYAML is required to load SIGMA rules. "
            "Install it with: pip install \"log-parser-toolkit[sigma]\""
        )

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"SIGMA rules path not found: {path}")

    if p.is_file():
        files = [p]
    else:
        files = sorted(p.glob("**/*.yml")) + sorted(p.glob("**/*.yaml"))

    rules: List[SigmaRule] = []
    for f in files:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                rule_dict = yaml.safe_load(fh)
            if isinstance(rule_dict, dict) and "detection" in rule_dict:
                rules.append(SigmaRule(rule_dict, source_file=str(f)))
            else:
                logger.debug("Skipping %s: missing 'detection' key", f)
        except Exception as exc:
            logger.warning("Could not load SIGMA rule %s: %s", f, exc)

    return rules


class SigmaAnalyzer:
    """
    Middleware layer that evaluates a set of SIGMA rules against every log record.

    Integrates with the existing pipeline via the standard ``.analyze()`` interface
    expected by ``api.parse_stream()``.

    Each matched rule adds an entry to ``log['sigma_alerts']`` and updates the
    shared ``is_alert`` / ``alert_reason`` flat fields so alerts flow into the
    existing alert routing (``--alert-file``) and dashboard statistics.

    MITRE ATT&CK metadata is resolved from the rule's tags (e.g. ``attack.t1110.001``)
    and cross-referenced against the project's ``mitre_mappings.json`` lookup table
    when available.

    Parameters
    ----------
    rules_path:
        File or directory of SIGMA rules to load (requires PyYAML).
    """

    def __init__(self, rules_path: str):
        self.rules: List[SigmaRule] = load_rules_from_path(rules_path)
        logger.info("Loaded %d SIGMA rules from %s", len(self.rules), rules_path)
        self._mitre_by_id = self._build_mitre_index()

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _build_mitre_index() -> Dict[str, Dict[str, str]]:
        """Build a technique_id → mapping dict from mitre_mappings.json."""
        try:
            from log_parser_toolkit.analyzer.middleware import MITRE_MAPPINGS
            return {v["technique_id"]: v for v in MITRE_MAPPINGS.values() if "technique_id" in v}
        except Exception:
            return {}

    def _resolve_mitre(self, rule: SigmaRule) -> Optional[Dict[str, str]]:
        """Return the MITRE mapping dict for the rule's first ATT&CK tag, if known."""
        tech_id = rule.mitre_technique_id()
        if tech_id:
            return self._mitre_by_id.get(tech_id)
        return None

    # ------------------------------------------------------------------ #
    # Middleware interface                                                 #
    # ------------------------------------------------------------------ #

    def analyze(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate all loaded rules against *log*.

        Modifies *log* in-place:
          - ``sigma_alerts``      (list)  — one entry per matched rule
          - ``sigma_rule_titles`` (str)   — semicolon-joined rule titles
          - ``sigma_levels``      (str)   — semicolon-joined severity levels
          - ``is_alert``          (bool)  — set True if any rule fires
          - ``alert_reason``      (str)   — updated with SIGMA rule titles
        """
        if log.get("error"):
            return log

        # Initialise list only once (StatefulSecurityAnalyzer may have set it earlier)
        if "sigma_alerts" not in log:
            log["sigma_alerts"] = []

        matched: List[SigmaRule] = []
        for rule in self.rules:
            if rule.matches(log):
                matched.append(rule)

        if not matched:
            return log

        # Build per-rule alert dicts
        for rule in matched:
            sigma_alert: Dict[str, Any] = {
                "rule_title": rule.title,
                "rule_id": rule.id,
                "level": rule.level,
                "description": rule.description,
                "tags": rule.tags,
            }
            mitre = self._resolve_mitre(rule)
            if mitre:
                sigma_alert["mitre_attack"] = mitre
            log["sigma_alerts"].append(sigma_alert)

        # Flat fields (CSV / SQLite compatible)
        log["sigma_rule_titles"] = "; ".join(r.title for r in matched)
        log["sigma_levels"] = "; ".join(r.level for r in matched)

        # Integrate with shared alert infrastructure
        log["is_alert"] = True
        sigma_reason = "SIGMA: " + "; ".join(r.title for r in matched)
        existing = log.get("alert_reason") or ""
        log["alert_reason"] = (existing + "; " + sigma_reason).lstrip("; ")

        return log

    def __len__(self) -> int:
        return len(self.rules)
