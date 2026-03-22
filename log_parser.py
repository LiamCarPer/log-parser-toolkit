import argparse
import sys
import json
import csv
import logging
from parsers.linux import LinuxSyslogParser
from parsers.web import WebLogParser
from parsers.windows import WindowsLogParser

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description="Log Parser Toolkit: Parse logs into structured JSON or CSV.")
    parser.add_argument("--input", required=True, help="Path to the input log file.")
    parser.add_argument("--format", required=True, choices=["linux", "web", "windows"], help="Format of the input log file.")
    parser.add_argument("--output", required=True, help="Path to the output file.")
    parser.add_argument("--type", required=True, choices=["json", "csv"], help="Output file type (json or csv).")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logging.")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.format == "linux":
        parser_instance = LinuxSyslogParser(args.input)
    elif args.format == "web":
        parser_instance = WebLogParser(args.input)
    elif args.format == "windows":
        parser_instance = WindowsLogParser(args.input)
    else:
        logger.error(f"Unknown format '{args.format}'")
        sys.exit(1)

    try:
        logger.info(f"Parsing {args.format} log file: {args.input}")
        parsed_iterator = parser_instance.parse()
        
        first_item = next(parsed_iterator, None)
        if not first_item:
            logger.warning("No valid log lines parsed or file is empty.")
            sys.exit(0)

        if args.type == "csv":
            with open(args.output, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=first_item.keys())
                writer.writeheader()
                writer.writerow(first_item)
                count = 1
                for row in parsed_iterator:
                    row_clean = {k: row.get(k) for k in first_item.keys()}
                    writer.writerow(row_clean)
                    count += 1
            logger.info(f"Successfully saved {count} records to CSV: {args.output}")

        elif args.type == "json":
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write('[\n')
                f.write('    ' + json.dumps(first_item))
                count = 1
                for row in parsed_iterator:
                    f.write(',\n    ' + json.dumps(row))
                    count += 1
                f.write('\n]\n')
            logger.info(f"Successfully saved {count} records to JSON: {args.output}")

    except Exception as e:
        logger.error(f"Error during parsing or saving: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
