import re
from typing import Iterator, Dict, Any
from .base import BaseParser

class WebLogParser(BaseParser):
    """
    Parses Apache/Nginx combined log format files.
    """
    
    LOG_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status>\d{3})\s+'
        r'(?P<bytes>\S+)\s+'
        r'"(?P<referer>[^"]*)"\s+'
        r'"(?P<user_agent>[^"]*)"$'
    )

    def get_fields(self) -> list[str]:
        return ["ip", "ident", "user", "timestamp", "request", "status", "bytes", "referer", "user_agent", "raw_line", "error"]

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
