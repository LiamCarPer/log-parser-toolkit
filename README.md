# Log Parser Toolkit

![Terminal Demo](demo.gif)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Run Tests](https://github.com/LiamCarPer/log-parser-toolkit/actions/workflows/test.yml/badge.svg)](https://github.com/LiamCarPer/log-parser-toolkit/actions/workflows/test.yml)

A robust, memory-efficient Python command-line utility designed to parse various unstructured log formats into structured JSON or CSV files. 

This toolkit was built to demonstrate clean software architecture, advanced regular expression (regex) parsing, **streaming data processing** (Generator pattern for large files), and user-friendly CLI design using `argparse`. It serves as a flexible ingestion layer for log data analysis.

## Table of Contents
- [Architecture](#architecture)
- [Features](#features)
- [Supported Formats](#supported-formats)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Testing](#testing)
- [Future Enhancements](#future-enhancements)

## Architecture

The system uses a modular design, allowing new parsers to be added dynamically. It utilizes a **generator pattern** to stream lines, avoiding Out-Of-Memory (OOM) issues on massive log files.

```mermaid
graph TD
    A[Raw Log File] -->|CLI Input| B(log_parser.py)
    B -->|Instantiates| C{Parser Factory}
    C -->|Format: linux| D[LinuxSyslogParser]
    C -->|Format: web| E[WebLogParser]
    C -->|Format: windows| F[WindowsLogParser]
    D -->|Yields Dict| G[Security Analyzer]
    E -->|Yields Dict| G
    F -->|Yields Dict| G
    G -->|Enriches Dict| H[Streaming Writer]
    H -->|Export| I(Structured JSON)
    H -->|Export| J(Structured CSV)
    G -->|Alert| K(High-Fidelity Alerts)
```

## Features

- **Memory Efficient (Streaming):** Parses logs line-by-line using Python Generators (`yield`). Can process multi-gigabyte log files without crashing or hogging RAM.
- **Stateful Security Analysis:** Implements a middle-ware processing layer that evaluates logs against security rules (e.g., SSH Brute Force, Web Scanning) using a rolling time window.
- **AbuseIPDB Threat Intelligence:** Seamlessly enriches log data with IP reputation scores from the AbuseIPDB API. Features a local **Threat Intel Cache** to ensure high performance and prevent API rate-limiting.
- **High-Fidelity Alert Routing:** Automatically identifies and routes security-critical events to a dedicated `--alert-file`, allowing analysts to focus on verified threats without sifting through millions of benign logs.
- **Resource Management:** Employs Python Context Managers (`with` magic methods) to strictly secure file handles and prevent I/O leaks on errors.
- **Dead-Letter Queue Support:** Robust error handling gracefully routes malformed or unmatched log lines to a separate `--error-file` without corrupting the primary structured data export.
- **Dynamic Plugin Factory:** New parsers added to the `parsers/` directory are auto-discovered via subclass introspection and immediately available via the CLI.
- **Dependency-Free Core:** Uses only standard library modules (`json`, `csv`, `re`, `urllib`) for parsing, analysis, and network communication. No heavy third-party dependencies required.

## Supported Formats

- **Linux Syslog** (`linux`): Parses standard Linux syslog messages extracting Timestamp, Hostname, Process/PID, and the core Message.
- **Web Logs** (`web`): Parses the industry-standard Apache/Nginx combined log format (IP, Ident, User, Timestamp, Request, Status, Bytes, Referer, User-Agent).
- **Windows Event Logs** (`windows`): Parses Windows Event Logs that have been exported to CSV format, acting as a normalization layer.

## Project Structure

```text
log-parser-toolkit/
├── log_parser.py          # Main CLI entry point
├── pyproject.toml         # Package definition
├── parsers/               # Parser modules
│   ├── base.py            # Abstract BaseParser class
│   ├── linux.py           # Syslog parsing logic (Regex)
│   ├── web.py             # Apache/Nginx parsing logic (Regex)
│   └── windows.py         # Windows CSV ingestion
├── samples/               # Sample log files for testing
├── tests/                 # Pytest unit tests
└── .github/workflows/     # CI/CD pipelines
```

## Installation

1. Ensure you have Python 3.8+ installed.
2. Clone the repository and navigate to the root directory.
3. Install the package in a virtual environment:

```bash
# Create a virtual environment
python -m venv .venv

# Activate the virtual environment
# On macOS/Linux:
source .venv/bin/activate  
# On Windows:
# .venv\Scripts\activate

# Install the toolkit locally (makes `log-parser` available globally in the venv)
pip install -e .
```

## Usage

Once installed, you can use the `log-parser` command anywhere inside your virtual environment.

```bash
log-parser --input <path_to_log> --format <format_name> --output <path_to_output> --type <json|csv> [options]
```

### Arguments:

- `--input`: Path to the input log file.
- `--format`: Format of the log file (e.g., `linux`, `web`, `windows`).
- `--output`: Path to save the parsed output file.
- `--type`: Desired output file type (`json` or `csv`).
- `--alert-file`: (Optional) Path to save security-critical events (alerts).
- `--abuseipdb-key`: (Optional) Your AbuseIPDB API key for automatic threat scoring.
- `--error-file`: (Optional) Path to save unmatched log lines.
- `--strict`: (Optional) Fail immediately on the first unmatched line.
- `--verbose`: (Optional) Enable debug-level logging.

## Examples

### 1. Basic Syslog Parsing to JSON
```bash
log-parser --input samples/sample_syslog.log --format linux --output output.json --type json
```

### 2. Full Security Analysis with Threat Intel
```bash
log-parser --input logs/auth.log --format linux --output full_data.csv --type csv --alert-file critical_alerts.csv --abuseipdb-key YOUR_API_KEY
```

## Testing

The project uses `pytest` for unit testing the regex patterns, parser logic, and the security analyzer middleware.

To run the full test suite:
```bash
pytest tests/
```

## Future Enhancements
- **Database Export:** Add direct insertion to SQLite or PostgreSQL databases using SQLAlchemy.
- **Web UI:** Create a lightweight dashboard for visualizing security alerts and log trends.
