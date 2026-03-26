from abc import ABC, abstractmethod
from typing import Iterator, Dict, Any
import os

class BaseParser(ABC):
    """
    Abstract base class for all log parsers.
    """
    
    FORMAT_NAME = ""

    def __init__(self, file_path: str):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Log file not found: {file_path}")
        self.file_path = file_path
        self._file = None
        self.encoding = 'utf-8'

    def __enter__(self):
        self._file = open(self.file_path, 'r', encoding=self.encoding, errors='ignore')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._file:
            self._file.close()
    @abstractmethod
    def get_fields(self) -> list[str]:
        """
        Returns the list of field names that this parser produces.
        """
        pass

    @abstractmethod
    def parse(self) -> Iterator[Dict[str, Any]]:
        """
        Parses the log file and yields dictionaries,
        where each dictionary represents a parsed log line.
        """
        pass
