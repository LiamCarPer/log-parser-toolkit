from typing import Dict, Any, List, Optional
from .rules import SecurityRule, SSHBruteForceRule, PrivilegeEscalationRule, WebScanningRule
from .threat_intel import ThreatIntelCache

class StatefulSecurityAnalyzer:
    """
    A middleware layer that analyzes logs for threats and enriches them with intelligence.
    Sits between parsing and output.
    """
    def __init__(self, abuseipdb_key: Optional[str] = None):
        # Initialize rules
        self.rules: List[SecurityRule] = [
            SSHBruteForceRule(),
            PrivilegeEscalationRule(),
            WebScanningRule()
        ]
        # Initialize threat intel cache
        self.intel_cache = ThreatIntelCache(abuseipdb_key)

    def analyze(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes a single log record.
        Returns the enriched record (modifies it in place).
        """
        if log.get("error"):
            # Don't analyze logs that failed parsing
            return log

        # 1. Evaluate detection rules
        for rule in self.rules:
            alert = rule.evaluate(log)
            if alert:
                log.update(alert)
                # We apply the first alert found. 
                # This could be extended to allow multiple alerts.
                break
        
        # 2. Enrich with Threat Intelligence
        # Use existing IP field or try to extract it from message
        ip = log.get('ip')
        if ip:
            score = self.intel_cache.get_threat_score(ip)
            if score is not None:
                log['threat_score'] = score
                
                # Automatically alert if AbuseIPDB score is high (e.g., > 80%)
                if score >= 80:
                    log['is_alert'] = True
                    # Don't overwrite more specific rule alert reasons
                    if not log.get('alert_reason'):
                        log['alert_reason'] = "Known Malicious IP"
                        log['details'] = f"IP {ip} has high AbuseIPDB score: {score}"
        
        return log
