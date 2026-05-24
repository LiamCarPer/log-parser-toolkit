"""
Tests for the SIGMA rule evaluator and SigmaAnalyzer middleware.

The evaluator (SigmaRule) is tested with rule dicts so PyYAML is NOT required.
The loader (load_rules_from_path) is tested with a skip guard if PyYAML is absent.
"""

import pytest
from log_parser_toolkit.sigma.evaluator import SigmaRule, SigmaConditionParser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_rule(detection: dict, level: str = "medium", tags: list | None = None) -> SigmaRule:
    """Build a SigmaRule from a minimal detection dict."""
    return SigmaRule({
        "title": "Test Rule",
        "id": "test-0000-0000-0000-000000000000",
        "detection": detection,
        "level": level,
        "tags": tags or [],
    })


# ---------------------------------------------------------------------------
# Field modifier: exact match (no modifier)
# ---------------------------------------------------------------------------

def test_exact_match_hit():
    rule = make_rule({"selection": {"process": "sshd"}, "condition": "selection"})
    assert rule.matches({"process": "sshd"}) is True


def test_exact_match_miss():
    rule = make_rule({"selection": {"process": "sshd"}, "condition": "selection"})
    assert rule.matches({"process": "cron"}) is False


def test_exact_match_case_insensitive():
    rule = make_rule({"selection": {"process": "SSHD"}, "condition": "selection"})
    assert rule.matches({"process": "sshd"}) is True


def test_missing_field_does_not_match():
    rule = make_rule({"selection": {"process": "sshd"}, "condition": "selection"})
    assert rule.matches({"hostname": "server1"}) is False


# ---------------------------------------------------------------------------
# Field modifier: |contains
# ---------------------------------------------------------------------------

def test_contains_hit():
    rule = make_rule({
        "selection": {"message|contains": "Failed password"},
        "condition": "selection",
    })
    assert rule.matches({"message": "Failed password for user from 10.0.0.1"}) is True


def test_contains_miss():
    rule = make_rule({
        "selection": {"message|contains": "Failed password"},
        "condition": "selection",
    })
    assert rule.matches({"message": "Accepted publickey for user1"}) is False


# ---------------------------------------------------------------------------
# Field modifier: |startswith / |endswith
# ---------------------------------------------------------------------------

def test_startswith_hit():
    rule = make_rule({
        "selection": {"user_agent|startswith": "sqlmap"},
        "condition": "selection",
    })
    assert rule.matches({"user_agent": "sqlmap/1.5.11#stable"}) is True


def test_endswith_hit():
    rule = make_rule({
        "selection": {"request|endswith": "HTTP/1.1"},
        "condition": "selection",
    })
    assert rule.matches({"request": "GET /index.html HTTP/1.1"}) is True


# ---------------------------------------------------------------------------
# Field modifier: |re
# ---------------------------------------------------------------------------

def test_regex_hit():
    rule = make_rule({
        "selection": {"message|re": r"Failed password for \S+ from \d+\.\d+\.\d+\.\d+"},
        "condition": "selection",
    })
    assert rule.matches({"message": "Failed password for root from 1.2.3.4"}) is True


def test_regex_miss():
    rule = make_rule({
        "selection": {"message|re": r"^Accepted publickey"},
        "condition": "selection",
    })
    assert rule.matches({"message": "Failed password for root from 1.2.3.4"}) is False


# ---------------------------------------------------------------------------
# List values (OR by default)
# ---------------------------------------------------------------------------

def test_list_values_any_match():
    rule = make_rule({
        "selection": {"user_agent|contains": ["sqlmap", "nikto", "nmap"]},
        "condition": "selection",
    })
    assert rule.matches({"user_agent": "nikto/2.1.6"}) is True
    assert rule.matches({"user_agent": "Mozilla/5.0"}) is False


# ---------------------------------------------------------------------------
# List values with |all modifier (AND semantics)
# ---------------------------------------------------------------------------

def test_list_values_all_modifier():
    rule = make_rule({
        "selection": {"message|contains|all": ["Failed", "password"]},
        "condition": "selection",
    })
    assert rule.matches({"message": "Failed to verify password"}) is True
    assert rule.matches({"message": "Failed login attempt"}) is False  # missing "password"


# ---------------------------------------------------------------------------
# AND within a selection (multiple field conditions)
# ---------------------------------------------------------------------------

def test_multiple_fields_and():
    rule = make_rule({
        "selection": {
            "process": "sshd",
            "message|contains": "Failed password",
        },
        "condition": "selection",
    })
    assert rule.matches({"process": "sshd", "message": "Failed password for root"}) is True
    assert rule.matches({"process": "cron", "message": "Failed password for root"}) is False


# ---------------------------------------------------------------------------
# Compound conditions: and / or / not
# ---------------------------------------------------------------------------

def test_condition_and():
    rule = make_rule({
        "sel_process": {"process": "sudo"},
        "sel_root": {"message|contains": "USER=root"},
        "condition": "sel_process and sel_root",
    })
    assert rule.matches({"process": "sudo", "message": "user1: USER=root; CMD=ls"}) is True
    assert rule.matches({"process": "sudo", "message": "user1: USER=user2; CMD=ls"}) is False


def test_condition_or():
    rule = make_rule({
        "sel_root": {"message|contains": "USER=root"},
        "sel_bash": {"message|contains": "/bin/bash"},
        "condition": "sel_root or sel_bash",
    })
    assert rule.matches({"message": "user1: USER=root; CMD=ls"}) is True
    assert rule.matches({"message": "user1: USER=user1; CMD=/bin/bash"}) is True
    assert rule.matches({"message": "user1: USER=user1; CMD=/bin/sh"}) is False


def test_condition_not():
    rule = make_rule({
        "selection": {"process": "sshd"},
        "filter": {"message|contains": "Accepted"},
        "condition": "selection and not filter",
    })
    # sshd with rejection → match
    assert rule.matches({"process": "sshd", "message": "Failed password for root"}) is True
    # sshd with accepted → no match (filtered)
    assert rule.matches({"process": "sshd", "message": "Accepted publickey for user1"}) is False


# ---------------------------------------------------------------------------
# Parentheses
# ---------------------------------------------------------------------------

def test_condition_parentheses():
    rule = make_rule({
        "sel_a": {"process": "sshd"},
        "sel_b": {"process": "sudo"},
        "sel_c": {"message|contains": "root"},
        "condition": "(sel_a or sel_b) and sel_c",
    })
    assert rule.matches({"process": "sshd", "message": "root login failed"}) is True
    assert rule.matches({"process": "sudo", "message": "USER=root"}) is True
    assert rule.matches({"process": "cron", "message": "root task"}) is False


# ---------------------------------------------------------------------------
# Quantifiers: 1 of / all of
# ---------------------------------------------------------------------------

def test_quantifier_1_of_them():
    rule = make_rule({
        "sel_a": {"process": "sshd"},
        "sel_b": {"process": "sudo"},
        "condition": "1 of them",
    })
    assert rule.matches({"process": "sshd"}) is True
    assert rule.matches({"process": "cron"}) is False


def test_quantifier_all_of_them():
    rule = make_rule({
        "sel_a": {"message|contains": "Failed"},
        "sel_b": {"message|contains": "root"},
        "condition": "all of them",
    })
    assert rule.matches({"message": "Failed password for root"}) is True
    assert rule.matches({"message": "Failed password for user1"}) is False


def test_quantifier_1_of_wildcard():
    rule = make_rule({
        "sel_ssh": {"process": "sshd"},
        "sel_sudo": {"process": "sudo"},
        "sel_cron": {"process": "cron"},
        "condition": "1 of sel_s*",
    })
    assert rule.matches({"process": "sshd"}) is True   # matches sel_ssh
    assert rule.matches({"process": "sudo"}) is True   # matches sel_sudo
    assert rule.matches({"process": "cron"}) is False  # sel_cron not in sel_s*


# ---------------------------------------------------------------------------
# MITRE technique ID extraction from tags
# ---------------------------------------------------------------------------

def test_mitre_technique_id_parsed():
    rule = SigmaRule({
        "title": "Test",
        "detection": {"selection": {"process": "sshd"}, "condition": "selection"},
        "tags": ["attack.credential_access", "attack.t1110.001"],
    })
    assert rule.mitre_technique_id() == "T1110.001"


def test_mitre_technique_id_none_when_no_technique_tag():
    rule = SigmaRule({
        "title": "Test",
        "detection": {"selection": {"process": "sshd"}, "condition": "selection"},
        "tags": ["attack.credential_access"],
    })
    assert rule.mitre_technique_id() is None


# ---------------------------------------------------------------------------
# Matches never raises
# ---------------------------------------------------------------------------

def test_bad_rule_does_not_raise():
    """A rule with a broken condition should silently return False."""
    rule = SigmaRule({
        "title": "Broken",
        "detection": {
            "selection": {"process": "sshd"},
            "condition": "nonexistent_selection",
        },
    })
    assert rule.matches({"process": "sshd"}) is False


# ---------------------------------------------------------------------------
# SigmaAnalyzer middleware (no YAML required — uses pre-built SigmaRule)
# ---------------------------------------------------------------------------

def test_sigma_analyzer_enriches_log():
    """SigmaAnalyzer sets sigma_alerts, is_alert, and flat fields on a match."""
    from log_parser_toolkit.sigma.loader import SigmaAnalyzer

    rule = make_rule({
        "selection": {"process": "sshd", "message|contains": "Failed password"},
        "condition": "selection",
    }, tags=["attack.credential_access", "attack.t1110.001"])

    analyzer = SigmaAnalyzer.__new__(SigmaAnalyzer)
    analyzer.rules = [rule]
    analyzer._mitre_by_id = SigmaAnalyzer._build_mitre_index()

    log = {"process": "sshd", "message": "Failed password for root from 10.0.0.1"}
    result = analyzer.analyze(log)

    assert result["is_alert"] is True
    assert "SIGMA" in result["alert_reason"]
    assert len(result["sigma_alerts"]) == 1
    assert result["sigma_alerts"][0]["rule_title"] == "Test Rule"
    assert result["sigma_rule_titles"] == "Test Rule"
    assert result["sigma_levels"] == "medium"


def test_sigma_analyzer_no_match_does_not_set_alert():
    from log_parser_toolkit.sigma.loader import SigmaAnalyzer

    rule = make_rule({
        "selection": {"process": "sshd"},
        "condition": "selection",
    })

    analyzer = SigmaAnalyzer.__new__(SigmaAnalyzer)
    analyzer.rules = [rule]
    analyzer._mitre_by_id = {}

    log = {"process": "cron", "message": "session opened for user root"}
    result = analyzer.analyze(log)

    assert "is_alert" not in result
    assert result.get("sigma_alerts", []) == []


def test_sigma_analyzer_skips_error_records():
    from log_parser_toolkit.sigma.loader import SigmaAnalyzer

    rule = make_rule({"selection": {"process": "sshd"}, "condition": "selection"})

    analyzer = SigmaAnalyzer.__new__(SigmaAnalyzer)
    analyzer.rules = [rule]
    analyzer._mitre_by_id = {}

    error_row = {"error": "unmatched", "raw_line": "..."}
    result = analyzer.analyze(error_row)
    assert "is_alert" not in result


# ---------------------------------------------------------------------------
# load_rules_from_path (requires PyYAML)
# ---------------------------------------------------------------------------

yaml = pytest.importorskip("yaml", reason="PyYAML not installed — skipping loader tests")


def test_load_rules_from_directory(tmp_path):
    from log_parser_toolkit.sigma.loader import load_rules_from_path

    rule_content = """
title: Temp SSH Rule
id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
detection:
  selection:
    process: sshd
    message|contains: 'Failed password'
  condition: selection
level: low
tags:
  - attack.t1110.001
"""
    (tmp_path / "rule.yml").write_text(rule_content)
    rules = load_rules_from_path(str(tmp_path))
    assert len(rules) == 1
    assert rules[0].title == "Temp SSH Rule"
    assert rules[0].matches({"process": "sshd", "message": "Failed password for root"})
    assert not rules[0].matches({"process": "cron", "message": "something else"})


def test_load_rules_skips_invalid_yaml(tmp_path):
    from log_parser_toolkit.sigma.loader import load_rules_from_path

    (tmp_path / "bad.yml").write_text("this: is: not: valid: yaml: [")
    rules = load_rules_from_path(str(tmp_path))
    assert rules == []


def test_load_rules_from_bundled_sigma_rules():
    """The bundled sigma_rules/ directory should load without errors."""
    import os
    from log_parser_toolkit.sigma.loader import load_rules_from_path

    sigma_dir = os.path.join(
        os.path.dirname(__file__), "..", "sigma_rules"
    )
    if not os.path.isdir(sigma_dir):
        pytest.skip("sigma_rules/ directory not found")

    rules = load_rules_from_path(sigma_dir)
    assert len(rules) >= 5, f"Expected at least 5 bundled rules, got {len(rules)}"
    levels = {r.level for r in rules}
    assert levels & {"low", "medium", "high"}
