import json
import os
from typing import Dict, Any, List, Optional
import logging
try:
    import geoip2.database
except ImportError:
    geoip2 = None

from .rules import SecurityRule, SSHBruteForceRule, PrivilegeEscalationRule, WebScanningRule, UserAgentAnomalyRule, WindowsFailedLogonRule
from .threat_intel import ThreatIntelCache

logger = logging.getLogger(__name__)

# Load MITRE ATT&CK mappings from the bundled JSON file at import time.
_MITRE_MAPPINGS_PATH = os.path.join(os.path.dirname(__file__), "mitre_mappings.json")

def _load_mitre_mappings() -> Dict[str, Any]:
    """Loads the MITRE ATT&CK technique mappings from the bundled JSON file."""
    try:
        with open(_MITRE_MAPPINGS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"Could not load MITRE ATT&CK mappings from {_MITRE_MAPPINGS_PATH}: {e}")
        return {}

MITRE_MAPPINGS: Dict[str, Any] = _load_mitre_mappings()


class StatefulSecurityAnalyzer:
    """
    A middleware layer that analyzes logs for threats and enriches them with intelligence.
    Sits between parsing and output.

    Enrichment performed per record:
      1. Evaluate all registered SecurityRule instances.
      2. Enrich matched alerts with MITRE ATT&CK technique metadata.
      3. Query the ThreatIntelCache (AbuseIPDB) for the source IP.
      4. Perform GeoIP lookup (country / city / ASN / ISP) if a database is configured.
      5. Consolidate all alert metadata into flat fields for CSV/SQLite compatibility.
    """
    def __init__(self, abuseipdb_key: Optional[str] = None, geoip_db_path: Optional[str] = None):
        # Initialize rules
        self.rules: List[SecurityRule] = [
            SSHBruteForceRule(),
            PrivilegeEscalationRule(),
            WebScanningRule(),
            UserAgentAnomalyRule(),
            WindowsFailedLogonRule()
        ]
        # Initialize threat intel cache
        self.intel_cache = ThreatIntelCache(abuseipdb_key)

        # Initialize GeoIP reader
        self.geoip_reader = None
        if geoip_db_path and geoip2:
            try:
                self.geoip_reader = geoip2.database.Reader(geoip_db_path)
            except Exception as e:
                logger.error(f"Failed to load GeoIP database: {e}")

    @staticmethod
    def _enrich_alert_with_mitre(alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Looks up the alert_reason in the MITRE mappings and injects the
        ``mitre_attack`` sub-dict if a mapping exists.
        """
        reason = alert.get("alert_reason", "")
        mapping = MITRE_MAPPINGS.get(reason)
        if mapping:
            alert["mitre_attack"] = mapping
        return alert

    def analyze(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes a single log record.
        Returns the enriched record (modifies it in place).
        """
        if log.get("error"):
            # Don't analyze logs that failed parsing
            return log

        # Initialize alerts list
        log["alerts"] = []

        # 1. Evaluate detection rules
        for rule in self.rules:
            alert = rule.evaluate(log)
            if alert:
                # Enrich the individual alert with MITRE ATT&CK metadata
                alert = self._enrich_alert_with_mitre(alert)
                log["alerts"].append(alert)

        # 2. Enrich with Threat Intelligence & GeoIP
        ip = log.get('ip')
        if ip:
            # Threat Intel
            score = self.intel_cache.get_threat_score(ip)
            if score is not None:
                log['threat_score'] = score
                if score >= 80:
                    ti_alert = {
                        "is_alert": True,
                        "alert_reason": "Known Malicious IP",
                        "details": f"IP {ip} has high AbuseIPDB score: {score}"
                    }
                    ti_alert = self._enrich_alert_with_mitre(ti_alert)
                    log["alerts"].append(ti_alert)

            # GeoIP Enrichment
            if self.geoip_reader:
                try:
                    response = self.geoip_reader.city(ip)
                    log['country'] = response.country.name
                    log['city'] = response.city.name

                    # ASN info might require a different database, but GeoLite2 City
                    # usually has some info or the geoip2 lib handles it if possible.
                    # Note: For true ASN lookup, a GeoLite2-ASN.mmdb is typically needed.
                    # We'll try to get it if the reader supports it.
                    try:
                        asn_response = self.geoip_reader.asn(ip)
                        log['asn'] = asn_response.autonomous_system_number
                        log['isp'] = asn_response.autonomous_system_organization
                    except Exception:
                        pass
                except Exception:
                    # Ignore lookup failures for internal/unmapped IPs
                    pass

        # 3. Consolidate alerts for flat output formats (CSV/SQLite)
        if log["alerts"]:
            log["is_alert"] = True
            log["alert_reason"] = "; ".join([a.get("alert_reason", "Unknown") for a in log["alerts"]])
            log["details"] = "; ".join([a.get("details", "") for a in log["alerts"]])
            # Flat MITRE fields: join all unique technique IDs and tactics for CSV/SQLite
            mitre_ids = []
            mitre_tactics = []
            for a in log["alerts"]:
                mitre = a.get("mitre_attack", {})
                if mitre.get("technique_id") and mitre["technique_id"] not in mitre_ids:
                    mitre_ids.append(mitre["technique_id"])
                if mitre.get("tactic") and mitre["tactic"] not in mitre_tactics:
                    mitre_tactics.append(mitre["tactic"])
            log["mitre_technique_ids"] = "; ".join(mitre_ids) if mitre_ids else None
            log["mitre_tactics"] = "; ".join(mitre_tactics) if mitre_tactics else None

        return log

    def close(self):
        if self.geoip_reader:
            self.geoip_reader.close()
