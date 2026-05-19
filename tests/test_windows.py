import pytest
from log_parser_toolkit.parsers.windows import WindowsLogParser

def test_windows_log_parser_success(tmp_path):
    p = tmp_path / "sample_windows.csv"
    content = 'TimeCreated,Id,LevelDisplayName,ProviderName,Message\n'
    content += '"3/22/2026 10:15:00 AM",4624,Information,Microsoft-Windows-Security-Auditing,"An account was successfully logged on."\n'
    p.write_text(content)
    
    with WindowsLogParser(str(p)) as parser:
        parsed = list(parser.parse())
    
    assert len(parsed) == 1
    
    assert parsed[0]['TimeCreated'] == '2026-03-22T10:15:00Z'
    assert parsed[0]['Id'] == '4624'
    assert parsed[0]['LevelDisplayName'] == 'Information'
    assert parsed[0]['ProviderName'] == 'Microsoft-Windows-Security-Auditing'
    assert parsed[0]['Message'] == 'An account was successfully logged on.'

def test_windows_log_parser_invalid_schema(tmp_path):
    p = tmp_path / "invalid_schema.csv"
    # Missing 'Message' column
    content = 'TimeCreated,Id,LevelDisplayName,ProviderName\n'
    content += '"3/22/2026 10:15:00 AM",4624,Information,Microsoft-Windows-Security-Auditing\n'
    p.write_text(content)
    
    with WindowsLogParser(str(p)) as parser:
        with pytest.raises(ValueError) as excinfo:
            parser.get_fields()
        
        assert "Missing columns" in str(excinfo.value)
        assert "Message" in str(excinfo.value)
