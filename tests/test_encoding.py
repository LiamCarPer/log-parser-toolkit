import pytest
from log_parser import main
import sys
from unittest.mock import patch
import json

def test_cli_encoding_latin1(tmp_path):
    # Setup latin-1 encoded input file
    input_file = tmp_path / "latin1.log"
    # Create content with a non-utf8 character (e.g., 'ñ')
    content = "Mar 22 10:15:30 server1 process: message with ñ\n"
    with open(input_file, 'w', encoding='latin-1') as f:
        f.write(content)
        
    output_file = tmp_path / "output.json"
    
    # Simulate CLI arguments with explicit encoding
    test_args = [
        "log_parser.py",
        "--input", str(input_file),
        "--format", "linux",
        "--output", str(output_file),
        "--type", "json",
        "--encoding", "latin-1"
    ]
    
    with patch.object(sys, 'argv', test_args):
        main()
    
    # Verify output
    assert output_file.exists()
    with open(output_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    assert len(data) == 1
    assert "ñ" in data[0]['message']

def test_cli_encoding_utf16(tmp_path):
    # Setup utf-16 encoded input file
    input_file = tmp_path / "utf16.log"
    content = "Mar 22 10:15:30 server1 process1: utf-16 message\n"
    with open(input_file, 'w', encoding='utf-16') as f:
        f.write(content)
        
    output_file = tmp_path / "output.json"
    
    test_args = [
        "log_parser.py",
        "--input", str(input_file),
        "--format", "linux",
        "--output", str(output_file),
        "--type", "json",
        "--encoding", "utf-16"
    ]
    
    with patch.object(sys, 'argv', test_args):
        main()
    
    # Verify output
    assert output_file.exists()
    with open(output_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    assert len(data) == 1
    assert data[0]['message'] == "utf-16 message"
