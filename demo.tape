# VHS Tape for Log Parser Toolkit
Output demo.gif

Require python3
Require cat

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 600
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

# Demonstrate parsing Linux syslog to JSON
Type "python3 log_parser.py --input samples/sample_syslog.log --format linux --output output.json --type json"
Sleep 1s
Enter
Sleep 2s

Type "cat output.json"
Sleep 1s
Enter
Sleep 4s

Type "clear"
Enter
Sleep 500ms

# Demonstrate parsing Apache Web logs to CSV
Type "python3 log_parser.py --input samples/sample_apache.log --format web --output output.csv --type csv"
Sleep 1s
Enter
Sleep 2s

Type "cat output.csv"
Sleep 1s
Enter
Sleep 4s

# Final cleanup
Hide
Type "rm output.json output.csv"
Enter
