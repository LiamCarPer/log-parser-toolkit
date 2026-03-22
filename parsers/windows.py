import csv
from typing import Iterator, Dict, Any
from .base import BaseParser

class WindowsLogParser(BaseParser):
    """
    Parses Windows Event Logs that have been exported to CSV format.
    """

    def parse(self) -> Iterator[Dict[str, Any]]:
        with open(self.file_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                yield dict(row)
