import csv
from typing import Iterator, Dict, Any
from .base import BaseParser

class WindowsLogParser(BaseParser):
    """
    Parses Windows Event Logs that have been exported to CSV format.
    """

    def get_fields(self) -> list[str]:
        with open(self.file_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
            reader = csv.reader(f)
            header = next(reader, [])
            return header + ["raw_line", "error"]

    def parse(self) -> Iterator[Dict[str, Any]]:
        fields = self.get_fields()
        with open(self.file_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                res = {f: None for f in fields}
                res.update(dict(row))
                yield res
