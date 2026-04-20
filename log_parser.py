import argparse
import sys
import json
import csv
import logging
from parsers import get_parser, get_available_parsers
from analyzer import StatefulSecurityAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description="Log Parser Toolkit: Parse logs into structured JSON or CSV.")
    parser.add_argument("--input", default="-", help="Path to the input log file. Use '-' for stdin (default).")
    
    available_formats = list(get_available_parsers().keys())
    parser.add_argument("--format", required=True, choices=available_formats, help="Format of the input log file.")
    parser.add_argument("--output", required=True, help="Path to the output file.")
    parser.add_argument("--type", required=True, choices=["json", "csv"], help="Output file type (json or csv).")
    parser.add_argument("--error-file", help="Path to save unmatched log lines (dead-letter file).")
    parser.add_argument("--alert-file", help="Path to save detected security alerts.")
    parser.add_argument("--abuseipdb-key", help="Optional API key for AbuseIPDB threat intelligence.")
    parser.add_argument("--pattern-file", help="Optional JSON file containing custom regex patterns.")
    parser.add_argument("--pattern-name", help="Name of the pattern to load from the pattern file.")
    parser.add_argument("--encoding", help="Optional encoding for the input log file (e.g., utf-8, latin-1).", default=None)
    parser.add_argument("--strict", action="store_true", help="If enabled, stop execution on first unmatched line.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logging.")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    custom_pattern = None
    if args.pattern_file:
        if not args.pattern_name:
            logger.error("--pattern-name is required when using --pattern-file")
            sys.exit(1)
        try:
            with open(args.pattern_file, 'r') as f:
                patterns = json.load(f)
                custom_pattern = patterns.get(args.pattern_name)
                if not custom_pattern:
                    logger.error(f"Pattern '{args.pattern_name}' not found in {args.pattern_file}")
                    sys.exit(1)
        except Exception as e:
            logger.error(f"Error loading pattern file: {e}")
            sys.exit(1)

    try:
        parser_instance = get_parser(args.format, args.input, encoding=args.encoding, custom_pattern=custom_pattern)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    try:
        input_desc = "Standard Input" if args.input == "-" else args.input
        logger.info(f"Parsing {args.format} logs from {input_desc}")
        
        analyzer = StatefulSecurityAnalyzer(abuseipdb_key=args.abuseipdb_key)

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
            alert_count = 0
            import itertools
            all_rows = itertools.chain([first_item], parsed_iterator)

            fields = current_parser.get_fields()
            extended_fields = fields + ["is_alert", "alert_reason", "details", "threat_score"]

            if args.type == "csv":
                with open(args.output, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=extended_fields)
                    writer.writeheader()
                    
                    alert_f = None
                    alert_writer = None
                    if args.alert_file:
                        alert_f = open(args.alert_file, 'w', newline='', encoding='utf-8')
                        alert_writer = csv.DictWriter(alert_f, fieldnames=extended_fields)
                        alert_writer.writeheader()

                    try:
                        for row in all_rows:
                            if row.get("error"):
                                unmatched_count += 1
                                if args.strict:
                                    logger.error(f"Strict mode enabled. Unmatched line: {row.get('raw_line')}")
                                    if error_f: error_f.close()
                                    if alert_f: alert_f.close()
                                    sys.exit(1)
                                if error_f:
                                    error_f.write(row.get('raw_line', '') + "\n")
                            else:
                                matched_count += 1
                                # Apply security analysis
                                row = analyzer.analyze(row)
                                if row.get("is_alert"):
                                    alert_count += 1
                                    if alert_writer:
                                        alert_writer.writerow(row)
                            
                            writer.writerow(row)
                    finally:
                        if alert_f: alert_f.close()
                
                logger.info(f"Successfully processed {matched_count + unmatched_count} records.")
                logger.info(f" - Saved to CSV: {args.output}")
                if alert_count > 0:
                    logger.warning(f" - Found {alert_count} security alerts! Saved to: {args.alert_file}")

            elif args.type == "json":
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write('[\n')
                    
                    alert_f = None
                    if args.alert_file:
                        alert_f = open(args.alert_file, 'w', encoding='utf-8')
                        alert_f.write('[\n')

                    is_first_out = True
                    is_first_alert = True
                    
                    try:
                        for row in all_rows:
                            if row.get("error"):
                                unmatched_count += 1
                                if args.strict:
                                    logger.error(f"Strict mode enabled. Unmatched line: {row.get('raw_line')}")
                                    if error_f: error_f.close()
                                    if alert_f: alert_f.close()
                                    sys.exit(1)
                                if error_f:
                                    error_f.write(row.get('raw_line', '') + "\n")
                            else:
                                matched_count += 1
                                # Apply security analysis
                                row = analyzer.analyze(row)
                                if row.get("is_alert"):
                                    alert_count += 1
                                    if alert_f:
                                        if not is_first_alert:
                                            alert_f.write(',\n')
                                        alert_f.write('    ' + json.dumps(row))
                                        is_first_alert = False
                            
                            if not is_first_out:
                                f.write(',\n')
                            f.write('    ' + json.dumps(row))
                            is_first_out = False
                    finally:
                        f.write('\n]\n')
                        if alert_f:
                            alert_f.write('\n]\n')
                            alert_f.close()

                logger.info(f"Successfully processed {matched_count + unmatched_count} records.")
                logger.info(f" - Saved to JSON: {args.output}")
                if alert_count > 0:
                    logger.warning(f" - Found {alert_count} security alerts! Saved to: {args.alert_file}")

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
