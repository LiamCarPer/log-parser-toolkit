import csv
from typing import Iterator, Dict, Any, List, Optional
from .base import BaseParser
from .utils import normalize_timestamp

class WindowsLogParser(BaseParser):
    """
    Parses Windows Event Logs that have been exported to CSV format.
    """
    FORMAT_NAME = "windows"
    REQUIRED_COLUMNS = {"TimeCreated", "Id", "LevelDisplayName", "ProviderName", "Message"}

    def __init__(self, file_path: str, encoding: Optional[str] = None, **kwargs):
        # kwargs to consume custom_pattern if passed by factory
        super().__init__(file_path, encoding=encoding)
        if not encoding and file_path != "-":
            self.encoding = 'utf-8-sig'

    def get_fields(self) -> List[str]:
        # Handle fields differently for stdin if needed, but for now we assume 
        # file_path provides a way to get headers if not stdin.
        # If stdin, we have to read the first line of the stream.
        
        if self.file_path == "-":
            # This is tricky because get_fields is called before parse()
            # and might consume the header.
            return list(self.REQUIRED_COLUMNS) + ["raw_line", "error"] # Fallback

        with open(self.file_path, 'r', encoding=self.encoding, errors='ignore') as f:
            reader = csv.reader(f)
            header = next(reader, [])
            
        header_set = set(header)
        if not self.REQUIRED_COLUMNS.issubset(header_set):
            missing = self.REQUIRED_COLUMNS - header_set
            raise ValueError(f"Invalid Windows Event Log CSV schema. Missing columns: {missing}")
            
        return header + ["raw_line", "error"]

    def parse(self) -> Iterator[Dict[str, Any]]:
        if not self._file:
            raise RuntimeError("Parser must be used as a context manager (using 'with').")
            
        reader = csv.DictReader(self._file)
        # We don't know the fields in advance if streaming stdin
        for row in reader:
                # Normalization for Windows Time: 3/22/2026 10:15:00 AM
                if "TimeCreated" in row:
                    row["TimeCreated"] = normalize_timestamp(row["TimeCreated"], ["%m/%d/%Y %I:%M:%S %p"])
                yield row
