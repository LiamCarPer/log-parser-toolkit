import re
from typing import List, Dict, Any
from .base import BaseParser

class LinuxSyslogParser(BaseParser):
    """
    Parses standard Linux syslog files.
    """
    
    # Regex to match: "Mar 22 10:15:30 server1 sshd[1234]: Accepted publickey..."
    # Components: Timestamp, Hostname, Process(PID), Message
    LOG_PATTERN = re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<process>[a-zA-Z0-9_-]+)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.*)$"
    )

    def parse(self) -> List[Dict[str, Any]]:
        parsed_data = []
        with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = self.LOG_PATTERN.match(line.strip())
                if match:
                    parsed_data.append(match.groupdict())
                else:
                    # Capture unparsed lines for debugging or partial data
                    parsed_data.append({"raw_line": line.strip(), "error": "unmatched"})
        return parsed_data
