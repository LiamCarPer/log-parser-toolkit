import argparse
import sys
import pandas as pd
from parsers.linux import LinuxSyslogParser
from parsers.web import WebLogParser
from parsers.windows import WindowsLogParser

def main():
    parser = argparse.ArgumentParser(description="Log Parser Toolkit: Parse logs into structured JSON or CSV.")
    parser.add_argument("--input", required=True, help="Path to the input log file.")
    parser.add_argument("--format", required=True, choices=["linux", "web", "windows"], help="Format of the input log file.")
    parser.add_argument("--output", required=True, help="Path to the output file.")
    parser.add_argument("--type", required=True, choices=["json", "csv"], help="Output file type (json or csv).")

    args = parser.parse_args()

    # Select parser
    if args.format == "linux":
        parser_instance = LinuxSyslogParser(args.input)
    elif args.format == "web":
        parser_instance = WebLogParser(args.input)
    elif args.format == "windows":
        parser_instance = WindowsLogParser(args.input)
    else:
        print(f"Error: Unknown format '{args.format}'", file=sys.stderr)
        sys.exit(1)

    try:
        print(f"Parsing {args.format} log file: {args.input}")
        parsed_data = parser_instance.parse()
    except Exception as e:
        print(f"Error during parsing: {e}", file=sys.stderr)
        sys.exit(1)

    if not parsed_data:
        print("Warning: No valid log lines parsed.")
        sys.exit(0)

    # Convert to pandas DataFrame
    df = pd.DataFrame(parsed_data)

    try:
        if args.type == "csv":
            df.to_csv(args.output, index=False)
            print(f"Successfully saved parsed data to CSV: {args.output}")
        elif args.type == "json":
            df.to_json(args.output, orient="records", indent=4)
            print(f"Successfully saved parsed data to JSON: {args.output}")
    except Exception as e:
        print(f"Error saving output file: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
