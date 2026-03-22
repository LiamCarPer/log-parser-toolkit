import os
import tempfile
import pytest
from parsers.linux import LinuxSyslogParser

@pytest.fixture
def sample_syslog():
    content = "Mar 22 10:15:30 server1 sshd[1234]: Accepted publickey for user1 from 192.168.1.100 port 50432 ssh2\n"
    content += "Mar 22 10:20:45 server2 kernel: [ 1234.567890] iptables denied: IN=eth0 OUT=\n"
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(content)
        file_path = f.name
    
    yield file_path
    os.remove(file_path)

def test_linux_syslog_parser(sample_syslog):
    parser = LinuxSyslogParser(sample_syslog)
    parsed = list(parser.parse())
    
    assert len(parsed) == 2
    
    assert parsed[0]['timestamp'] == 'Mar 22 10:15:30'
    assert parsed[0]['hostname'] == 'server1'
    assert parsed[0]['process'] == 'sshd'
    assert parsed[0]['pid'] == '1234'
    assert parsed[0]['message'] == 'Accepted publickey for user1 from 192.168.1.100 port 50432 ssh2'
    
    assert parsed[1]['timestamp'] == 'Mar 22 10:20:45'
    assert parsed[1]['hostname'] == 'server2'
    assert parsed[1]['process'] == 'kernel'
    assert parsed[1]['pid'] is None
    assert parsed[1]['message'] == '[ 1234.567890] iptables denied: IN=eth0 OUT='
