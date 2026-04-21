# Implementation Plan - Security Engine Enhancements and Repository Cleanup

This plan addresses documentation overhaul, security rule expansion, logic bug fixes in the middleware, and repository cleanup.

## Objective
*   Align documentation with the toolkit's current security-first capabilities.
*   Fix the multi-alert logic bug in the analyzer middleware.
*   Expand security coverage to Windows logs.
*   Improve repository hygiene by removing untracked database files and updating `.gitignore`.

## Key Files & Context
*   `README.md`: Needs documentation for rules, CLI flags, and a new security engine section.
*   `analyzer/middleware.py`: `analyze()` method needs to collect all alerts instead of breaking after the first one.
*   `analyzer/rules.py`: Add `WindowsFailedLogonRule`.
*   `log_parser.py`: Add `--analyze` CLI flag and handle multiple alerts in output.
*   `.gitignore`: Add `*.db` and `test.db`.
*   `tests/test_analyzer.py`: Update tests for multi-alert logic.

## Implementation Steps

### 1. Repository Hygiene
*   Remove `test.db` from the project root.
*   Update `.gitignore` to exclude `*.db` and specifically `test.db`.

### 2. Security Engine Enhancements
#### 2.1. Expand Security Rules (`analyzer/rules.py`)
*   Implement `WindowsFailedLogonRule`: Detects bursts of Event ID 4625 (Audit Failure) in Windows logs.
*   Follow the existing threshold/window pattern used in `SSHBruteForceRule`.

#### 2.2. Fix Multi-Alert Middleware Bug (`analyzer/middleware.py`)
*   Refactor `StatefulSecurityAnalyzer.analyze()`:
    *   Initialize an `alerts` list within the log record.
    *   Collect *all* matching rules into this list (remove the `break`).
    *   Update Threat Intelligence logic to append to the `alerts` list if the score is high.
    *   Consolidate `is_alert`, `alert_reason`, and `details` at the top level for backward compatibility with CSV/DB outputs (joining multiple alerts with `;`).

#### 2.3. CLI Flag & Output Logic (`log_parser.py`)
*   Add the `--analyze` flag to the `argparse` configuration.
*   Ensure the `StatefulSecurityAnalyzer` only runs if `--analyze` is passed (or keep it on by default but documented if preferred - user asked for documentation of the flag).
    *   *Decision*: Add `--analyze` flag. Default to `True` for backward compatibility or `False` to follow typical "only do what's asked" CLI behavior. Given the "Security Analysis Engine" focus, I'll add it as a flag that can be enabled.
*   Update the dashboard summary to handle multiple alerts per line if necessary (the joined strings should handle this fine for the counters).

### 3. Documentation & Samples
#### 3.1. README Overhaul
*   Remove TOC entry and section for "Future Enhancements" (if they are actually labeled as such).
*   Add "Security Analysis Engine" section documenting the 5 rules (SSH, Privilege Escalation, Web Scanning, UA Anomaly, Windows Failed Logon).
*   Document the `--analyze` flag.
*   Add a "Real-world Alert Output" example showing a JSON alert with multiple reasons and Threat Intel enrichment.

#### 3.2. Sample Alerts
*   Create `samples/alerts_sample.json` with 5-10 realistic alerts (JSON format).

### 4. Verification & Testing
*   Update `tests/test_analyzer.py` to verify that multiple alerts are captured for a single log entry.
*   Add a test case for the new `WindowsFailedLogonRule`.
*   Run all tests using `pytest tests/`.
*   Verify `test.db` is gone and ignored by git.

## Migration & Rollback
*   The change to `alert_reason` (joined string) is a minor breaking change for any scripts parsing the CSV output that expect a single reason.
*   Rollback: Revert changes to `middleware.py` and `log_parser.py`.
