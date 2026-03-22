from abc import ABC, abstractmethod
from typing import List, Dict, Any
import os

class BaseParser(ABC):
    """
    Abstract base class for all log parsers.
    """
    
    def __init__(self, file_path: str):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Log file not found: {file_path}")
        self.file_path = file_path

    @abstractmethod
    def parse(self) -> List[Dict[str, Any]]:
        """
        Parses the log file and returns a list of dictionaries,
        where each dictionary represents a parsed log line.
        """
        pass
