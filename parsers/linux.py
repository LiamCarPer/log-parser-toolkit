import re
from typing import Iterator, Dict, Any, List
from .base import BaseParser

class LinuxSyslogParser(BaseParser):
    """
    Parses standard Linux syslog files.
    """
    FORMAT_NAME = "linux"
    
    LOG_PATTERN = re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<process>[a-zA-Z0-9_-]+)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.*)$"
    )
    IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    def get_fields(self) -> List[str]:
        return ["timestamp", "hostname", "process", "pid", "message", "ip", "raw_line", "error"]

    def parse(self) -> Iterator[Dict[str, Any]]:
        fields = self.get_fields()
        if not self._file:
            raise RuntimeError("Parser must be used as a context manager (using 'with').")
            
        for line in self._file:
                match = self.LOG_PATTERN.match(line.strip())
                res = {f: None for f in fields}
                if match:
                    res.update(match.groupdict())
                    # Enrichment: extract IP from message if possible (e.g. for sshd)
                    ip_match = self.IP_REGEX.search(res['message'])
                    if ip_match:
                        res['ip'] = ip_match.group(0)
                else:
                    res.update({"raw_line": line.strip(), "error": "unmatched"})
                yield res
