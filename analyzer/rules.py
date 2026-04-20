import re
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from collections import deque
from datetime import datetime
from parsers.utils import extract_ip, parse_timestamp

class SecurityRule(ABC):
    """
    Abstract base class for all detection rules.
    """
    @abstractmethod
    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Evaluates a log record and returns alert details if it matches, else None.
        """
        pass

class SSHBruteForceRule(SecurityRule):
    """
    Rule 1 (Velocity/Threshold): 5 failed logins from the same IP within 60 seconds.
    """
    def __init__(self, threshold: int = 5, window_seconds: int = 60):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.ip_history = {} # IP -> deque of timestamps

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        process = log.get('process')
        message = log.get('message', '')
        
        if process == 'sshd' and 'Failed password' in message:
            # Extract IP from message if not already present
            ip = log.get('ip') or extract_ip(message)
            if not ip:
                return None
            
            timestamp = parse_timestamp(log.get('timestamp'))
            
            if ip not in self.ip_history:
                self.ip_history[ip] = deque()
            
            history = self.ip_history[ip]
            history.append(timestamp)
            
            # Remove events outside the window
            while history and (timestamp - history[0]).total_seconds() > self.window_seconds:
                history.popleft()
            
            if len(history) >= self.threshold:
                return {
                    "is_alert": True,
                    "alert_reason": "SSH Brute Force",
                    "details": f"Detected {len(history)} failed logins from {ip} within {self.window_seconds}s"
                }
        return None

class PrivilegeEscalationRule(SecurityRule):
    """
    Rule 2 (Keyword Match): Sudo usage to root or spawning /bin/bash.
    """
    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        process = log.get('process')
        message = log.get('message', '')
        
        if process == 'sudo':
            if 'USER=root' in message or '/bin/bash' in message:
                return {
                    "is_alert": True,
                    "alert_reason": "Privilege Escalation",
                    "details": f"Sudo privilege escalation detected: {message}"
                }
        return None

class WebScanningRule(SecurityRule):
    """
    Rule 3 (Spike Detection): High volume of 404/5xx errors from an IP.
    """
    def __init__(self, threshold: int = 10, window_seconds: int = 60):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.ip_errors = {} # IP -> deque of timestamps

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ip = log.get('ip')
        status = log.get('status')
        
        if ip and status:
            try:
                status_int = int(status)
            except ValueError:
                return None
                
            if status_int >= 400:
                timestamp = parse_timestamp(log.get('timestamp'))
                
                if ip not in self.ip_errors:
                    self.ip_errors[ip] = deque()
                
                errors = self.ip_errors[ip]
                errors.append(timestamp)
                
                # Remove events outside the window
                while errors and (timestamp - errors[0]).total_seconds() > self.window_seconds:
                    errors.popleft()
                
                if len(errors) >= self.threshold:
                    return {
                        "is_alert": True,
                        "alert_reason": "Web Directory Scanning",
                        "details": f"Detected {len(errors)} error responses (4xx/5xx) from {ip} within {self.window_seconds}s"
                    }
        return None

class UserAgentAnomalyRule(SecurityRule):
    """
    Rule 4 (Anomaly Detection): Flagging suspicious or weaponized user agents.
    """
    SUSPICIOUS_UA = {
        'sqlmap', 'nmap', 'nikto', 'dirbuster', 'gobuster', 
        'python-requests', 'curl', 'zgrab', 'masscan'
    }

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ua = log.get('user_agent', '')
        if not ua or ua == '-':
            return {
                "is_alert": True,
                "alert_reason": "Missing User-Agent",
                "details": "Request sent with missing or empty User-Agent string."
            }
        
        ua_lower = ua.lower()
        for suspect in self.SUSPICIOUS_UA:
            if suspect in ua_lower:
                return {
                    "is_alert": True,
                    "alert_reason": "Suspicious User-Agent",
                    "details": f"Detected potential automated tool/scanner: {suspect}"
                }
        return None
