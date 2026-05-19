import pytest
from log_parser_toolkit.parsers.web import WebLogParser

def test_web_log_parser_success(tmp_path):
    p = tmp_path / "sample_web.log"
    content = '127.0.0.1 - - [22/Mar/2026:10:15:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
    p.write_text(content)
    
    with WebLogParser(str(p)) as parser:
        parsed = list(parser.parse())
    
    assert len(parsed) == 1
    
    assert parsed[0]['ip'] == '127.0.0.1'
    assert parsed[0]['ident'] == '-'
    assert parsed[0]['user'] == '-'
    assert parsed[0]['timestamp'] == '2026-03-22T10:15:00+00:00'
    assert parsed[0]['request'] == 'GET /index.html HTTP/1.1'
    assert parsed[0]['status'] == '200'
    assert parsed[0]['bytes'] == '1024'
    assert parsed[0]['referer'] == '-'
    assert parsed[0]['user_agent'] == 'Mozilla/5.0'

def test_web_log_parser_unmatched(tmp_path):
    p = tmp_path / "malformed.log"
    p.write_text("This is not a web log line\n")
    
    with WebLogParser(str(p)) as parser:
        parsed = list(parser.parse())
    
    assert len(parsed) == 1
    assert parsed[0]['error'] == 'unmatched'
    assert parsed[0]['raw_line'] == "This is not a web log line"
