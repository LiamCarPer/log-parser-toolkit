import csv
from typing import Iterator, Dict, Any
from .base import BaseParser

class WindowsLogParser(BaseParser):
    """
    Parses Windows Event Logs that have been exported to CSV format.
    """
    FORMAT_NAME = "windows"
    REQUIRED_COLUMNS = {"TimeCreated", "Id", "LevelDisplayName", "ProviderName", "Message"}

    def __init__(self, file_path: str):
        super().__init__(file_path)
        self.encoding = 'utf-8-sig'

    def get_fields(self) -> list[str]:
        with open(self.file_path, 'r', encoding=self.encoding, errors='ignore') as f:
            reader = csv.reader(f)
            header = next(reader, [])
            
        header_set = set(header)
        if not self.REQUIRED_COLUMNS.issubset(header_set):
            missing = self.REQUIRED_COLUMNS - header_set
            raise ValueError(f"Invalid Windows Event Log CSV schema. Missing columns: {missing}")
            
        return header + ["raw_line", "error"]

    def parse(self) -> Iterator[Dict[str, Any]]:
        fields = self.get_fields()
        if not self._file:
            raise RuntimeError("Parser must be used as a context manager (using 'with').")
            
        reader = csv.DictReader(self._file)
        for row in reader:
                res = {f: None for f in fields}
                res.update(dict(row))
                yield res
