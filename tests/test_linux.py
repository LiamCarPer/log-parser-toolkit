import pytest
from parsers.linux import LinuxSyslogParser

def test_linux_syslog_parser_success(tmp_path):
    d = tmp_path / "logs"
    d.mkdir()
    p = d / "sample_syslog.log"
    content = "Mar 22 10:15:30 server1 sshd[1234]: Accepted publickey for user1 from 192.168.1.100 port 50432 ssh2\n"
    content += "Mar 22 10:20:45 server2 kernel: [ 1234.567890] iptables denied: IN=eth0 OUT=\n"
    p.write_text(content)
    
    with LinuxSyslogParser(str(p)) as parser:
        parsed = list(parser.parse())
    
    assert len(parsed) == 2
    
    assert parsed[0]['timestamp'] == '2026-03-22T10:15:30Z'
    assert parsed[0]['hostname'] == 'server1'
    assert parsed[0]['process'] == 'sshd'
    assert parsed[0]['pid'] == '1234'
    assert parsed[0]['message'] == 'Accepted publickey for user1 from 192.168.1.100 port 50432 ssh2'
    
    assert parsed[1]['timestamp'] == '2026-03-22T10:20:45Z'
    assert parsed[1]['hostname'] == 'server2'
    assert parsed[1]['process'] == 'kernel'
    assert parsed[1]['pid'] is None
    assert parsed[1]['message'] == '[ 1234.567890] iptables denied: IN=eth0 OUT='

def test_linux_syslog_parser_unmatched(tmp_path):
    p = tmp_path / "malformed.log"
    p.write_text("This is not a syslog line\n")
    
    with LinuxSyslogParser(str(p)) as parser:
        parsed = list(parser.parse())
    
    assert len(parsed) == 1
    assert parsed[0]['error'] == 'unmatched'
    assert parsed[0]['raw_line'] == "This is not a syslog line"
