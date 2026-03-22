import re
from typing import List, Dict, Any
from .base import BaseParser

class WebLogParser(BaseParser):
    """
    Parses Apache/Nginx combined log format files.
    """
    
    # Common Log Format + Combined
    # Example: 127.0.0.1 - - [22/Mar/2026:10:15:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0..."
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

    def parse(self) -> List[Dict[str, Any]]:
        parsed_data = []
        with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = self.LOG_PATTERN.match(line.strip())
                if match:
                    parsed_data.append(match.groupdict())
                else:
                    parsed_data.append({"raw_line": line.strip(), "error": "unmatched"})
        return parsed_data
