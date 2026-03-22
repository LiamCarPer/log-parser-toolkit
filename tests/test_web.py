import os
import tempfile
import pytest
from parsers.web import WebLogParser

@pytest.fixture
def sample_weblog():
    content = '127.0.0.1 - - [22/Mar/2026:10:15:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(content)
        file_path = f.name
    
    yield file_path
    os.remove(file_path)

def test_web_log_parser(sample_weblog):
    parser = WebLogParser(sample_weblog)
    parsed = list(parser.parse())
    
    assert len(parsed) == 1
    
    assert parsed[0]['ip'] == '127.0.0.1'
    assert parsed[0]['ident'] == '-'
    assert parsed[0]['user'] == '-'
    assert parsed[0]['timestamp'] == '22/Mar/2026:10:15:00 +0000'
    assert parsed[0]['request'] == 'GET /index.html HTTP/1.1'
    assert parsed[0]['status'] == '200'
    assert parsed[0]['bytes'] == '1024'
    assert parsed[0]['referer'] == '-'
    assert parsed[0]['user_agent'] == 'Mozilla/5.0'
