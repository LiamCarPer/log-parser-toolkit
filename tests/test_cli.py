import os
import json
import csv
import pytest
from log_parser_toolkit.cli import main
import sys
from unittest.mock import patch

def test_cli_linux_to_json(tmp_path):
    # Setup input file
    input_file = tmp_path / "syslog.log"
    input_file.write_text("Mar 22 10:15:30 server1 sshd[1234]: Accepted publickey for user1 from 192.168.1.100 port 50432 ssh2\n")
    
    # Setup output file path
    output_file = tmp_path / "output.json"
    
    # Simulate CLI arguments
    test_args = [
        "log_parser.py",
        "--input", str(input_file),
        "--format", "linux",
        "--output", str(output_file),
        "--type", "json"
    ]
    
    with patch.object(sys, 'argv', test_args):
        main()
    
    # Verify output
    assert output_file.exists()
    with open(output_file, 'r') as f:
        data = json.load(f)
    
    assert len(data) == 1
    assert data[0]['hostname'] == 'server1'
    assert data[0]['process'] == 'sshd'

def test_cli_strict_mode_fail(tmp_path):
    input_file = tmp_path / "mixed.log"
    input_file.write_text("Mar 22 10:15:30 server1 sshd[1234]: valid line\nInvalid line\n")
    output_file = tmp_path / "output.json"
    
    test_args = [
        "log_parser.py",
        "--input", str(input_file),
        "--format", "linux",
        "--output", str(output_file),
        "--type", "json",
        "--strict"
    ]
    
    with patch.object(sys, 'argv', test_args):
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 1

def test_cli_error_file_routing(tmp_path):
    input_file = tmp_path / "mixed.log"
    input_file.write_text("Mar 22 10:15:30 server1 sshd[1234]: valid line\nInvalid line\n")
    output_file = tmp_path / "output.json"
    error_file = tmp_path / "errors.log"
    
    test_args = [
        "log_parser.py",
        "--input", str(input_file),
        "--format", "linux",
        "--output", str(output_file),
        "--type", "json",
        "--error-file", str(error_file)
    ]
    
    with patch.object(sys, 'argv', test_args):
        main()
    
    # Verify error file contains the invalid line
    assert error_file.exists()
    error_content = error_file.read_text().strip()
    assert error_content == "Invalid line"
    
    # Verify primary output contains both (one with error)
    with open(output_file, 'r') as f:
        data = json.load(f)
    assert len(data) == 2
    assert data[1]['error'] == 'unmatched'

def test_cli_invalid_format(tmp_path):
    input_file = tmp_path / "any.log"
    input_file.write_text("any content")
    output_file = tmp_path / "output.json"
    
    test_args = [
        "log_parser.py",
        "--input", str(input_file),
        "--format", "non_existent_format",
        "--output", str(output_file),
        "--type", "json"
    ]
    
    with patch.object(sys, 'argv', test_args):
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 2
