"""
SIGMA rule evaluator.

Implements a lightweight, dependency-free evaluator for the SIGMA detection
rule format (https://github.com/SigmaHQ/sigma). Supports the field modifiers
and condition operators needed for the rules bundled with this toolkit.

Supported field modifiers:
    (none)      — Case-insensitive exact match
    |contains   — Case-insensitive substring match
    |startswith — Case-insensitive prefix match
    |endswith   — Case-insensitive suffix match
    |re         — Case-insensitive regex match
    |all        — Modifier that changes list evaluation from ANY to ALL

Supported condition operators:
    and, or, not, ( )
    1 of <pattern>   — At least one named selection matching the wildcard fires
    all of <pattern> — All named selections matching the wildcard must fire
    1 of them        — At least one selection fires
    all of them      — All selections must fire
"""

import re
import logging
from fnmatch import fnmatch
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class SigmaConditionParser:
    """
    Recursive-descent parser for SIGMA condition expressions.

    Grammar (simplified):
        expr    := or_expr
        or_expr := and_expr ('or' and_expr)*
        and_expr:= not_expr ('and' not_expr)*
        not_expr:= 'not' not_expr | primary
        primary := '(' expr ')'
                 | quantifier
                 | identifier
        quantifier := ('1'|'all') 'of' pattern
        identifier := WORD (may contain '*' wildcard)
    """

    def __init__(self, condition: str, selections: Dict[str, Any]):
        self.tokens = self._tokenize(condition)
        self.selections = selections
        self.pos = 0
        self.log: Dict[str, Any] = {}

    # ------------------------------------------------------------------ #
    # Tokenisation                                                         #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _tokenize(condition: str) -> List[str]:
        """Insert spaces around parentheses then split on whitespace."""
        cond = re.sub(r"\(", " ( ", condition)
        cond = re.sub(r"\)", " ) ", cond)
        return [t for t in cond.split() if t]

    # ------------------------------------------------------------------ #
    # Public entry point                                                   #
    # ------------------------------------------------------------------ #

    def evaluate(self, log: Dict[str, Any]) -> bool:
        """Evaluate the condition expression against *log*."""
        self.log = log
        self.pos = 0
        return self._parse_or()

    # ------------------------------------------------------------------ #
    # Parser helpers                                                       #
    # ------------------------------------------------------------------ #

    def _current(self) -> Optional[str]:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos].lower()
        return None

    def _consume(self) -> str:
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    # ------------------------------------------------------------------ #
    # Recursive-descent grammar rules                                     #
    # ------------------------------------------------------------------ #

    def _parse_or(self) -> bool:
        left = self._parse_and()
        while self._current() == "or":
            self._consume()
            right = self._parse_and()
            left = left or right
        return left

    def _parse_and(self) -> bool:
        left = self._parse_not()
        while self._current() == "and":
            self._consume()
            right = self._parse_not()
            left = left and right
        return left

    def _parse_not(self) -> bool:
        if self._current() == "not":
            self._consume()
            return not self._parse_not()
        return self._parse_primary()

    def _parse_primary(self) -> bool:
        current = self._current()
        if current is None:
            return False

        # Parenthesised sub-expression
        if current == "(":
            self._consume()
            val = self._parse_or()
            if self._current() == ")":
                self._consume()
            return val

        # Quantifiers: "1 of <pattern>" or "all of <pattern>"
        # Use lookahead to distinguish from a bare selection named "1" or "all"
        if current in ("1", "all") and (
            self.pos + 1 < len(self.tokens)
            and self.tokens[self.pos + 1].lower() == "of"
        ):
            quantifier = self._consume()   # '1' or 'all'
            self._consume()                # 'of'
            pattern = self._consume() if self.pos < len(self.tokens) else "them"
            return self._evaluate_quantifier(quantifier, pattern)

        # Regular identifier (selection name, optionally with * wildcard)
        name = self._consume()
        return self._evaluate_selection_name(name)

    # ------------------------------------------------------------------ #
    # Quantifier evaluation                                               #
    # ------------------------------------------------------------------ #

    def _evaluate_quantifier(self, quantifier: str, pattern: str) -> bool:
        if pattern.lower() == "them":
            candidates = list(self.selections.keys())
        else:
            candidates = [k for k in self.selections if fnmatch(k, pattern)]

        results = [self._eval_named_selection(name) for name in candidates]

        if quantifier == "1":
            return any(results)
        if quantifier == "all":
            return all(results) if results else False
        return False

    def _evaluate_selection_name(self, name: str) -> bool:
        if "*" in name:
            candidates = [k for k in self.selections if fnmatch(k, name)]
            return any(self._eval_named_selection(c) for c in candidates)
        return self._eval_named_selection(name)

    def _eval_named_selection(self, name: str) -> bool:
        selection = self.selections.get(name)
        if selection is None:
            return False
        return self._match_selection(selection)

    # ------------------------------------------------------------------ #
    # Selection matching                                                   #
    # ------------------------------------------------------------------ #

    def _match_selection(self, selection: Any) -> bool:
        """
        A selection is either:
          - a dict  → all field conditions must match (AND)
          - a list  → OR across list items (each item may itself be a dict)
        """
        if isinstance(selection, dict):
            return all(
                self._match_field(field_mod, expected)
                for field_mod, expected in selection.items()
            )
        if isinstance(selection, list):
            return any(self._match_selection(item) for item in selection)
        return False

    def _match_field(self, field_modifier: str, expected: Any) -> bool:
        """
        Evaluate a single field condition, respecting modifiers.

        field_modifier examples:
            'process'            → exact match
            'message|contains'   → substring
            'user_agent|re'      → regex
            'status|contains|all'→ all list values must be substrings
        """
        parts = field_modifier.split("|")
        field = parts[0]
        modifiers = parts[1:]

        actual = self.log.get(field)

        # Explicit null checks
        if expected is None:
            return actual is None
        if actual is None:
            return False

        actual_str = str(actual)

        # 'all' modifier: list treated as AND; otherwise OR (default SIGMA behaviour)
        require_all = "all" in modifiers
        base_mods = [m for m in modifiers if m != "all"]
        primary_mod = base_mods[0] if base_mods else None

        values = expected if isinstance(expected, list) else [expected]

        def _single_match(val: Any) -> bool:
            val_str = str(val) if val is not None else ""
            if primary_mod is None:
                return actual_str.lower() == val_str.lower()
            if primary_mod == "contains":
                return val_str.lower() in actual_str.lower()
            if primary_mod == "startswith":
                return actual_str.lower().startswith(val_str.lower())
            if primary_mod == "endswith":
                return actual_str.lower().endswith(val_str.lower())
            if primary_mod == "re":
                return bool(re.search(val_str, actual_str, re.IGNORECASE))
            # Unknown modifier — fall back to exact match
            logger.debug("Unknown SIGMA field modifier: '%s'", primary_mod)
            return actual_str.lower() == val_str.lower()

        if require_all:
            return all(_single_match(v) for v in values)
        return any(_single_match(v) for v in values)


# --------------------------------------------------------------------------- #
# SigmaRule                                                                    #
# --------------------------------------------------------------------------- #


class SigmaRule:
    """
    Represents a single parsed SIGMA detection rule.

    Parameters
    ----------
    rule_dict:
        A dictionary parsed from a SIGMA YAML file.
    source_file:
        Optional path string for logging/display purposes.
    """

    def __init__(self, rule_dict: Dict[str, Any], source_file: str = ""):
        self.title: str = rule_dict.get("title", "Unnamed Rule")
        self.id: str = rule_dict.get("id", "")
        self.status: str = rule_dict.get("status", "experimental")
        self.level: str = rule_dict.get("level", "medium")
        self.description: str = rule_dict.get("description", "")
        self.author: str = rule_dict.get("author", "")
        self.tags: List[str] = rule_dict.get("tags", [])
        self.logsource: Dict[str, str] = rule_dict.get("logsource", {})
        self.source_file: str = source_file

        detection = rule_dict.get("detection", {})
        self.condition: str = str(detection.get("condition", "selection"))
        # All keys except 'condition' are named selections
        self.selections: Dict[str, Any] = {
            k: v for k, v in detection.items() if k != "condition"
        }

        self._parser = SigmaConditionParser(self.condition, self.selections)

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def matches(self, log: Dict[str, Any]) -> bool:
        """
        Return True if *log* satisfies this rule's detection condition.
        Always returns False (never raises) so a bad rule won't crash the pipeline.
        """
        try:
            return self._parser.evaluate(log)
        except Exception as exc:
            logger.debug("Error evaluating rule '%s': %s", self.title, exc)
            return False

    def mitre_technique_id(self) -> Optional[str]:
        """
        Parse the first ATT&CK technique tag (e.g. 'attack.t1110.001')
        and return it in canonical form ('T1110.001').
        """
        for tag in self.tags:
            m = re.match(r"^attack\.(t\d+(?:\.\d+)?)", tag, re.IGNORECASE)
            if m:
                return m.group(1).upper()
        return None

    def __repr__(self) -> str:
        return f"SigmaRule(title={self.title!r}, level={self.level!r})"
