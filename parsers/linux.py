import re
from typing import Iterator, Dict, Any
from .base import BaseParser

class LinuxSyslogParser(BaseParser):
    """
    Parses standard Linux syslog files.
    """
    
    LOG_PATTERN = re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<process>[a-zA-Z0-9_-]+)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.*)$"
    )

    def get_fields(self) -> list[str]:
        return ["timestamp", "hostname", "process", "pid", "message", "raw_line", "error"]

    def parse(self) -> Iterator[Dict[str, Any]]:
        fields = self.get_fields()
        with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = self.LOG_PATTERN.match(line.strip())
                res = {f: None for f in fields}
                if match:
                    res.update(match.groupdict())
                else:
                    res.update({"raw_line": line.strip(), "error": "unmatched"})
                yield res
