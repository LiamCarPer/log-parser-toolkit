# VHS Tape for Log Parser Toolkit
Output demo.gif

Require python3
Require cat

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 800
Set Padding 30
Set WindowBar Rings
Set Theme "Catppuccin Mocha"

# Setup the environment silently
Hide
Type "source .venv/bin/activate"
Enter
Type "clear"
Enter
Show

# 1. Demonstrate parsing Linux syslog to JSON
Type "python3 log_parser.py --input samples/sample_syslog.log --format linux --output output.json --type json"
Sleep 500ms
Enter
Sleep 3s

# Show a snippet of the JSON output
Type "head -n 8 output.json"
Sleep 500ms
Enter
Sleep 3s

Type "clear"
Enter
Sleep 500ms

# 2. NEW: Demonstrate Windows Event Log parsing to SQLite Database
# This also showcases the new Security Alerts summary table
Type "python3 log_parser.py --input samples/sample_windows.csv --format windows --output toolkit.db --type db"
Sleep 500ms
Enter
Sleep 5s

Type "clear"
Enter
Sleep 500ms

# 3. NEW: Demonstrate Web log parsing with Security Alert detection
Type "python3 log_parser.py --input samples/sample_apache.log --format web --output alerts.csv --type csv --alert-file security_alerts.json"
Sleep 500ms
Enter
Sleep 5s

# Final cleanup
Hide
Type "rm output.json toolkit.db alerts.csv security_alerts.json"
Enter
