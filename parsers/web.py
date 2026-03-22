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

    def parse(self) -> Iterator[Dict[str, Any]]:
        with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = self.LOG_PATTERN.match(line.strip())
                if match:
                    yield match.groupdict()
                else:
                    yield {"raw_line": line.strip(), "error": "unmatched"}
