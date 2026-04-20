import pytest
from datetime import datetime, timedelta
from analyzer.rules import SSHBruteForceRule, PrivilegeEscalationRule, WebScanningRule
from analyzer.middleware import StatefulSecurityAnalyzer
from analyzer.threat_intel import ThreatIntelCache
from unittest.mock import patch, MagicMock

def test_ssh_brute_force_rule():
    rule = SSHBruteForceRule(threshold=3, window_seconds=60)
    
    # 1st fail
    log1 = {"process": "sshd", "message": "Failed password for user1 from 192.168.1.100", "timestamp": "Mar 22 10:00:00"}
    assert rule.evaluate(log1) is None
    
    # 2nd fail
    log2 = {"process": "sshd", "message": "Failed password for user1 from 192.168.1.100", "timestamp": "Mar 22 10:00:10"}
    assert rule.evaluate(log2) is None
    
    # 3rd fail -> Alert
    log3 = {"process": "sshd", "message": "Failed password for user1 from 192.168.1.100", "timestamp": "Mar 22 10:00:20"}
    alert = rule.evaluate(log3)
    assert alert is not None
    assert alert["is_alert"] is True
    assert alert["alert_reason"] == "SSH Brute Force"

def test_privilege_escalation_rule():
    rule = PrivilegeEscalationRule()
    
    # Normal sudo
    log1 = {"process": "sudo", "message": "user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=user2 ; COMMAND=/usr/bin/ls"}
    assert rule.evaluate(log1) is None
    
    # Sudo to root
    log2 = {"process": "sudo", "message": "user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/usr/bin/ls"}
    alert = rule.evaluate(log2)
    assert alert is not None
    assert alert["alert_reason"] == "Privilege Escalation"
    
    # /bin/bash
    log3 = {"process": "sudo", "message": "user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=user1 ; COMMAND=/bin/bash"}
    alert = rule.evaluate(log3)
    assert alert is not None
    assert "bash" in alert["details"]

def test_web_scanning_rule():
    rule = WebScanningRule(threshold=3, window_seconds=60)
    
    # 404s
    log1 = {"ip": "1.2.3.4", "status": "404", "timestamp": "22/Mar/2026:10:00:00 +0000"}
    assert rule.evaluate(log1) is None
    
    log2 = {"ip": "1.2.3.4", "status": "404", "timestamp": "22/Mar/2026:10:00:01 +0000"}
    assert rule.evaluate(log2) is None
    
    log3 = {"ip": "1.2.3.4", "status": "500", "timestamp": "22/Mar/2026:10:00:02 +0000"}
    alert = rule.evaluate(log3)
    assert alert is not None
    assert alert["alert_reason"] == "Web Directory Scanning"

def test_analyzer_middleware():
    analyzer = StatefulSecurityAnalyzer()
    
    # Test SSH Brute Force through middleware
    logs = [
        {"process": "sshd", "message": "Failed password for user1 from 10.0.0.1", "timestamp": "Mar 22 10:00:00"},
        {"process": "sshd", "message": "Failed password for user1 from 10.0.0.1", "timestamp": "Mar 22 10:00:01"},
        {"process": "sshd", "message": "Failed password for user1 from 10.0.0.1", "timestamp": "Mar 22 10:00:02"},
        {"process": "sshd", "message": "Failed password for user1 from 10.0.0.1", "timestamp": "Mar 22 10:00:03"},
        {"process": "sshd", "message": "Failed password for user1 from 10.0.0.1", "timestamp": "Mar 22 10:00:04"},
    ]
    
    for i, log in enumerate(logs):
        enriched = analyzer.analyze(log)
        if i < 4:
            assert "is_alert" not in enriched
        else:
            assert enriched["is_alert"] is True
            assert enriched["alert_reason"] == "SSH Brute Force"

def test_threat_intel_cache():
    cache = ThreatIntelCache(api_key="fake_key")
    
    # Mock urllib.request.urlopen
    with patch("urllib.request.urlopen") as mock_url_open:
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"data": {"abuseConfidenceScore": 95}}'
        mock_response.__enter__.return_value = mock_response
        mock_url_open.return_value = mock_response
        
        # 1st call - should fetch from "API"
        score = cache.get_threat_score("8.8.8.8")
        assert score == 95
        assert mock_url_open.call_count == 1
        
        # 2nd call - should fetch from cache
        score2 = cache.get_threat_score("8.8.8.8")
        assert score2 == 95
        assert mock_url_open.call_count == 1 # Still 1

def test_analyzer_with_threat_intel():
    analyzer = StatefulSecurityAnalyzer(abuseipdb_key="fake_key")
    
    with patch("analyzer.threat_intel.ThreatIntelCache.get_threat_score") as mock_get_score:
        mock_get_score.return_value = 90
        
        log = {"ip": "1.2.3.4", "status": "200", "timestamp": "22/Mar/2026:10:00:00 +0000"}
        enriched = analyzer.analyze(log)
        
        assert enriched["threat_score"] == 90
        assert enriched["is_alert"] is True
        assert enriched["alert_reason"] == "Known Malicious IP"
