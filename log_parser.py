import argparse
import sys
import json
import csv
import logging
from parsers import get_parser, get_available_parsers

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
    
    available_formats = list(get_available_parsers().keys())
    parser.add_argument("--format", required=True, choices=available_formats, help="Format of the input log file.")
    parser.add_argument("--output", required=True, help="Path to the output file.")
    parser.add_argument("--type", required=True, choices=["json", "csv"], help="Output file type (json or csv).")
    parser.add_argument("--error-file", help="Path to save unmatched log lines (dead-letter file).")
    parser.add_argument("--strict", action="store_true", help="If enabled, stop execution on first unmatched line.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logging.")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    try:
        parser_instance = get_parser(args.format, args.input)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    try:
        logger.info(f"Parsing {args.format} log file: {args.input}")
        
        with parser_instance as current_parser:
            parsed_iterator = current_parser.parse()
            
            first_item = next(parsed_iterator, None)
            if not first_item:
                logger.warning("No valid log lines parsed or file is empty.")
                sys.exit(0)

            error_f = None
            if args.error_file:
                error_f = open(args.error_file, 'w', encoding='utf-8')

            matched_count = 0
            unmatched_count = 0
            import itertools
            all_rows = itertools.chain([first_item], parsed_iterator)

            if args.type == "csv":
                fields = current_parser.get_fields()
                with open(args.output, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=fields)
                    writer.writeheader()
                    for row in all_rows:
                        if row.get("error"):
                            unmatched_count += 1
                            if args.strict:
                                logger.error(f"Strict mode enabled. Unmatched line: {row.get('raw_line')}")
                                if error_f: error_f.close()
                                sys.exit(1)
                            if error_f:
                                error_f.write(row.get('raw_line', '') + "\n")
                        else:
                            matched_count += 1
                        writer.writerow(row)
                
                logger.info(f"Successfully processed {matched_count + unmatched_count} records.")
                logger.info(f" - Saved to CSV: {args.output}")

            elif args.type == "json":
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write('[\n')
                    is_first = True
                    for row in all_rows:
                        if row.get("error"):
                            unmatched_count += 1
                            if args.strict:
                                logger.error(f"Strict mode enabled. Unmatched line: {row.get('raw_line')}")
                                if error_f: error_f.close()
                                sys.exit(1)
                            if error_f:
                                error_f.write(row.get('raw_line', '') + "\n")
                        else:
                            matched_count += 1
                        
                        if not is_first:
                            f.write(',\n')
                        f.write('    ' + json.dumps(row))
                        is_first = False
                    f.write('\n]\n')
                logger.info(f"Successfully processed {matched_count + unmatched_count} records.")
                logger.info(f" - Saved to JSON: {args.output}")

            if error_f:
                error_f.close()
                if unmatched_count > 0:
                    logger.warning(f" - Found {unmatched_count} unmatched lines. Details saved to: {args.error_file}")
                else:
                    logger.info(" - No unmatched lines found.")

    except Exception as e:
        logger.error(f"Error during parsing or saving: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
