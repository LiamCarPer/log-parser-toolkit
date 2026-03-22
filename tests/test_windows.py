import os
import tempfile
import pytest
from parsers.windows import WindowsLogParser

@pytest.fixture
def sample_windowslog():
    content = 'TimeCreated,Id,LevelDisplayName,ProviderName,Message\n'
    content += '"3/22/2026 10:15:00 AM",4624,Information,Microsoft-Windows-Security-Auditing,"An account was successfully logged on."\n'
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(content)
        file_path = f.name
    
    yield file_path
    os.remove(file_path)

def test_windows_log_parser(sample_windowslog):
    parser = WindowsLogParser(sample_windowslog)
    parsed = parser.parse()
    
    assert len(parsed) == 1
    
    assert parsed[0]['TimeCreated'] == '3/22/2026 10:15:00 AM'
    assert parsed[0]['Id'] == '4624'
    assert parsed[0]['LevelDisplayName'] == 'Information'
    assert parsed[0]['ProviderName'] == 'Microsoft-Windows-Security-Auditing'
    assert parsed[0]['Message'] == 'An account was successfully logged on.'
