from datetime import datetime
from typing import Optional, List

def normalize_timestamp(ts_str: str, formats: List[str]) -> str:
    """
    Parses a timestamp string using a list of formats and returns ISO 8601 string.
    If parsing fails, returns the original string.
    """
    if not ts_str:
        return ts_str
        
    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str, fmt)
            # If no year is present (syslog), assume current year
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            # Ensure it outputs in a clean ISO format
            return dt.isoformat() + "Z" if dt.tzinfo is None else dt.isoformat()
        except ValueError:
            continue
            
    return ts_str
