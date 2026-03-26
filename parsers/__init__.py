from .base import BaseParser
from .linux import LinuxSyslogParser
from .web import WebLogParser
from .windows import WindowsLogParser

def get_available_parsers():
    """
    Returns a dictionary mapping FORMAT_NAME to the parser class.
    """
    parsers = {}
    for cls in BaseParser.__subclasses__():
        if cls.FORMAT_NAME:
            parsers[cls.FORMAT_NAME] = cls
    return parsers

def get_parser(format_name: str, file_path: str) -> BaseParser:
    """
    Factory function to instantiate the correct parser.
    """
    parsers = get_available_parsers()
    if format_name not in parsers:
        raise ValueError(f"Unknown format '{format_name}'. Available formats: {list(parsers.keys())}")
    return parsers[format_name](file_path)