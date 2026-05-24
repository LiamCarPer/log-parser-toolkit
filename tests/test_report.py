import os
import tempfile
import json
from log_parser_toolkit.analyzer.report import write_html_report, get_html_template

def test_write_html_report_creates_file():
    report_data = {
        "metadata": {
            "timestamp": "2026-05-24T12:00:00Z",
            "format": "web",
            "input_desc": "test.log",
            "duration_seconds": 0.123
        },
        "stats": {
            "total": 10,
            "matched": 8,
            "unmatched": 2,
            "alerts": 1
        },
        "top_ips": [("1.2.3.4", 5)],
        "top_status": [("200", 6), ("404", 2)],
        "alert_breakdown": [("Suspicious User-Agent", 1)],
        "recent_alerts": [
            {
                "timestamp": "2026-05-24T12:00:00Z",
                "ip": "1.2.3.4",
                "is_alert": True,
                "alert_reason": "Suspicious User-Agent",
                "details": "Malicious scanner user agent",
                "mitre_technique_ids": "T1595.002",
                "mitre_tactics": "Reconnaissance"
            }
        ],
        "ioc_report": {
            "summary": {
                "total_unique_iocs": 1,
                "ipv4_public_count": 1,
                "ipv4_private_count": 0,
                "ipv6_count": 0,
                "domain_count": 0,
                "url_count": 0,
                "hash_count": 0,
                "email_count": 0
            },
            "indicators": {
                "ipv4_public": ["1.2.3.4"],
                "ipv4_private": [],
                "ipv6": [],
                "domains": [],
                "urls": [],
                "hashes": {"sha256": [], "sha1": [], "md5": []},
                "emails": []
            }
        }
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = os.path.join(tmpdir, "report.html")
        write_html_report(report_path, report_data)
        
        assert os.path.exists(report_path)
        
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
            
        assert "Threat Intelligence & Analysis Dashboard" in content
        assert "reportData" in content
        assert "1.2.3.4" in content
        assert "Suspicious User-Agent" in content
        assert "T1595.002" in content
