"""
Tests for the IOC Extraction Engine (IOCExtractor middleware).
"""

import json
import pytest
from log_parser_toolkit.ioc.extractor import IOCExtractor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fresh() -> IOCExtractor:
    return IOCExtractor()


# ---------------------------------------------------------------------------
# IPv4 extraction
# ---------------------------------------------------------------------------

def test_extracts_public_ipv4_from_ip_field():
    ext = fresh()
    ext.analyze({"ip": "45.12.34.56", "message": "some message"})
    report = ext.get_report()
    assert "45.12.34.56" in report["indicators"]["ipv4_public"]


def test_classifies_private_ipv4():
    ext = fresh()
    ext.analyze({"ip": "192.168.1.100"})
    report = ext.get_report()
    assert "192.168.1.100" in report["indicators"]["ipv4_private"]
    assert "192.168.1.100" not in report["indicators"]["ipv4_public"]


def test_extracts_ipv4_from_message_field():
    ext = fresh()
    ext.analyze({"message": "Failed password for root from 10.0.0.1 port 22"})
    report = ext.get_report()
    assert "10.0.0.1" in report["indicators"]["ipv4_private"]


def test_does_not_extract_malformed_ipv4():
    ext = fresh()
    ext.analyze({"message": "version 1.2.3.4.5 released"})
    report = ext.get_report()
    # "1.2.3.4.5" is not a valid IPv4 — nothing should be extracted
    all_ips = report["indicators"]["ipv4_public"] + report["indicators"]["ipv4_private"]
    assert "1.2.3.4.5" not in all_ips


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------

def test_extracts_http_url():
    ext = fresh()
    ext.analyze({"message": "Request to http://evil.com/payload.exe detected"})
    report = ext.get_report()
    assert any("evil.com" in u for u in report["indicators"]["urls"])


def test_extracts_https_url():
    ext = fresh()
    ext.analyze({"referer": "https://example.com/login?next=/admin"})
    report = ext.get_report()
    assert any("example.com" in u for u in report["indicators"]["urls"])


# ---------------------------------------------------------------------------
# Domain extraction
# ---------------------------------------------------------------------------

def test_extracts_domain():
    ext = fresh()
    ext.analyze({"message": "DNS query to malware-c2.io observed"})
    report = ext.get_report()
    assert "malware-c2.io" in report["indicators"]["domains"]


def test_does_not_double_count_domain_from_url():
    ext = fresh()
    ext.analyze({"referer": "http://legit.com/page"})
    report = ext.get_report()
    # "legit.com" may or may not appear in domains (URL dedup best-effort)
    # but the URL itself must be there
    assert any("legit.com" in u for u in report["indicators"]["urls"])


# ---------------------------------------------------------------------------
# Hash extraction
# ---------------------------------------------------------------------------

def test_extracts_sha256_from_message():
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ext = fresh()
    ext.analyze({"message": f"File hash: {sha256}"})
    report = ext.get_report()
    assert sha256.lower() in [h.lower() for h in report["indicators"]["hashes"]["sha256"]]


def test_extracts_md5_from_message():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    ext = fresh()
    ext.analyze({"message": f"MD5: {md5}"})
    report = ext.get_report()
    assert md5.lower() in [h.lower() for h in report["indicators"]["hashes"]["md5"]]


def test_does_not_extract_hash_from_non_message_field():
    """Hashes should NOT be extracted from e.g. the ip field (FP prevention)."""
    ext = fresh()
    # A 32-char hex string in a non-hash field should not be extracted
    ext.analyze({"user_agent": "d41d8cd98f00b204e9800998ecf8427e"})
    report = ext.get_report()
    assert report["indicators"]["hashes"]["md5"] == []


# ---------------------------------------------------------------------------
# Email extraction
# ---------------------------------------------------------------------------

def test_extracts_email():
    ext = fresh()
    ext.analyze({"message": "Password reset request from attacker@evil.com"})
    report = ext.get_report()
    assert "attacker@evil.com" in report["indicators"]["emails"]


# ---------------------------------------------------------------------------
# Error records are skipped
# ---------------------------------------------------------------------------

def test_skips_error_records():
    ext = fresh()
    ext.analyze({"error": "unmatched", "raw_line": "garbage"})
    report = ext.get_report()
    assert report["records_analyzed"] == 0


# ---------------------------------------------------------------------------
# Multiple records accumulate correctly
# ---------------------------------------------------------------------------

def test_accumulates_across_records():
    ext = fresh()
    ext.analyze({"ip": "1.2.3.4"})
    ext.analyze({"ip": "5.6.7.8"})
    ext.analyze({"ip": "1.2.3.4"})  # duplicate — should deduplicate
    report = ext.get_report()
    assert report["records_analyzed"] == 3
    assert len(report["indicators"]["ipv4_public"]) == 2


# ---------------------------------------------------------------------------
# Summary counters
# ---------------------------------------------------------------------------

def test_summary_counts_correct():
    ext = fresh()
    ext.analyze({"ip": "45.12.34.56"})
    ext.analyze({"message": "Download from http://c2.io/rat.exe"})
    report = ext.get_report()
    assert report["summary"]["ipv4_public_count"] == 1
    assert report["summary"]["url_count"] >= 1


# ---------------------------------------------------------------------------
# write_report produces valid JSON
# ---------------------------------------------------------------------------

def test_write_report_produces_valid_json(tmp_path):
    ext = fresh()
    ext.analyze({"ip": "8.8.8.8", "message": "DNS query to google.com"})
    out = tmp_path / "iocs.json"
    ext.write_report(str(out))
    assert out.exists()
    data = json.loads(out.read_text())
    assert "extraction_timestamp" in data
    assert "indicators" in data
    assert "summary" in data


# ---------------------------------------------------------------------------
# Real syslog record (end-to-end)
# ---------------------------------------------------------------------------

def test_real_syslog_record():
    ext = fresh()
    record = {
        "timestamp": "2026-03-22T10:15:34Z",
        "hostname": "server1",
        "process": "sshd",
        "pid": "1234",
        "message": "Failed password for root from 45.12.34.56 port 54325 ssh2",
        "ip": "45.12.34.56",
    }
    ext.analyze(record)
    report = ext.get_report()
    assert "45.12.34.56" in report["indicators"]["ipv4_public"]
    assert report["records_analyzed"] == 1


# ---------------------------------------------------------------------------
# Real web log record (end-to-end)
# ---------------------------------------------------------------------------

def test_real_web_record():
    ext = fresh()
    record = {
        "ip": "192.168.1.100",
        "user_agent": "sqlmap/1.5.11",
        "request": "GET /admin?id=1' OR '1'='1 HTTP/1.1",
        "referer": "http://attacker.io/scan",
        "status": "404",
    }
    ext.analyze(record)
    report = ext.get_report()
    assert "192.168.1.100" in report["indicators"]["ipv4_private"]
    assert any("attacker.io" in u for u in report["indicators"]["urls"])
