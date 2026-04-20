import argparse
import sys
import json
import csv
import logging
import sqlite3
from collections import Counter
from typing import List, Dict, Any

from parsers import get_parser, get_available_parsers
from analyzer import StatefulSecurityAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def print_summary(stats: Counter, alert_counter: Counter, top_ips: List, top_status: List):
    """Prints a professional terminal dashboard using rich."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich import box
    except ImportError:
        logger.info("\n--- Processing Summary ---")
        logger.info(f"Total Processed: {stats['total']}")
        logger.info(f"Matched: {stats['matched']}")
        logger.info(f"Unmatched: {stats['unmatched']}")
        logger.info(f"Alerts: {stats['alerts']}")
        return

    console = Console()
    
    # Header
    console.print(Panel("[bold blue]Log Parser Toolkit - Execution Summary[/bold blue]", box=box.DOUBLE))

    # General Stats
    stats_table = Table(title="General Statistics", box=box.SIMPLE)
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="magenta")
    stats_table.add_row("Total Records", str(stats['total']))
    stats_table.add_row("Successfully Parsed", str(stats['matched']))
    stats_table.add_row("Failed Parsing", str(stats['unmatched']))
    stats_table.add_row("Security Alerts", f"[bold red]{stats['alerts']}[/bold red]")
    console.print(stats_table)

    # Top IPs & Status
    col1, col2 = Table.grid(expand=True), Table.grid(expand=True)
    
    ip_table = Table(title="Top 5 Source IPs", box=box.SIMPLE)
    ip_table.add_column("IP Address", style="green")
    ip_table.add_column("Count", justify="right")
    for ip, count in top_ips:
        ip_table.add_row(ip, str(count))
    
    status_table = Table(title="Status Distribution", box=box.SIMPLE)
    status_table.add_column("Status", style="yellow")
    status_table.add_column("Count", justify="right")
    for status, count in top_status:
        status_table.add_row(str(status), str(count))
        
    console.print(ip_table)
    console.print(status_table)

    # Alerts Breakdown
    if alert_counter:
        alert_table = Table(title="Alert Breakdown", box=box.SIMPLE)
        alert_table.add_column("Alert Reason", style="red")
        alert_table.add_column("Count", justify="right")
        for reason, count in alert_counter.most_common():
            alert_table.add_row(reason, str(count))
        console.print(alert_table)

def main():
    parser = argparse.ArgumentParser(description="Log Parser Toolkit: Parse logs into structured JSON or CSV.")
    parser.add_argument("--input", default="-", help="Path to the input log file. Use '-' for stdin (default).")
    
    available_formats = list(get_available_parsers().keys())
    parser.add_argument("--format", required=True, choices=available_formats, help="Format of the input log file.")
    parser.add_argument("--output", required=True, help="Path to the output file.")
    parser.add_argument("--type", required=True, choices=["json", "csv", "db"], help="Output file type (json, csv, db).")
    parser.add_argument("--error-file", help="Path to save unmatched log lines (dead-letter file).")
    parser.add_argument("--alert-file", help="Path to save detected security alerts.")
    parser.add_argument("--abuseipdb-key", help="Optional API key for AbuseIPDB threat intelligence.")
    parser.add_argument("--geoip-db", help="Optional path to MaxMind GeoLite2-City.mmdb for IP enrichment.")
    parser.add_argument("--pattern-file", help="Optional JSON file containing custom regex patterns.")
    parser.add_argument("--pattern-name", help="Name of the pattern to load from the pattern file.")
    parser.add_argument("--encoding", help="Optional encoding for the input log file (e.g., utf-8, latin-1).", default=None)
    parser.add_argument("--strict", action="store_true", help="If enabled, stop execution on first unmatched line.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logging.")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Stats Tracking
    stats = Counter()
    alert_counter = Counter()
    ip_counter = Counter()
    status_counter = Counter()

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
        
        analyzer = StatefulSecurityAnalyzer(
            abuseipdb_key=args.abuseipdb_key,
            geoip_db_path=args.geoip_db
        )

        with parser_instance as current_parser:
            parsed_iterator = current_parser.parse()
            
            first_item = next(parsed_iterator, None)
            if not first_item:
                logger.warning("No valid log lines parsed or file is empty.")
                sys.exit(0)

            error_f = None
            if args.error_file:
                error_f = open(args.error_file, 'w', encoding='utf-8')

            import itertools
            all_rows = itertools.chain([first_item], parsed_iterator)

            fields = current_parser.get_fields()
            # Dynamic fields based on analyzer output (including GeoIP)
            extended_fields = fields + [
                "is_alert", "alert_reason", "details", "threat_score",
                "country", "city", "asn", "isp"
            ]

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
                            stats['total'] += 1
                            if row.get("error"):
                                stats['unmatched'] += 1
                                if args.strict:
                                    logger.error(f"Strict mode enabled. Unmatched line: {row.get('raw_line')}")
                                    if error_f: error_f.close()
                                    if alert_f: alert_f.close()
                                    sys.exit(1)
                                if error_f:
                                    error_f.write(row.get('raw_line', '') + "\n")
                            else:
                                stats['matched'] += 1
                                row = analyzer.analyze(row)
                                # Stats
                                if row.get('ip'): ip_counter[row['ip']] += 1
                                if row.get('status'): status_counter[row['status']] += 1
                                if row.get("is_alert"):
                                    stats['alerts'] += 1
                                    alert_counter[row['alert_reason']] += 1
                                    if alert_writer:
                                        alert_writer.writerow(row)
                            
                            writer.writerow(row)
                    finally:
                        if alert_f: alert_f.close()

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
                            stats['total'] += 1
                            if row.get("error"):
                                stats['unmatched'] += 1
                                if args.strict:
                                    logger.error(f"Strict mode enabled. Unmatched line: {row.get('raw_line')}")
                                    if error_f: error_f.close()
                                    if alert_f: alert_f.close()
                                    sys.exit(1)
                                if error_f:
                                    error_f.write(row.get('raw_line', '') + "\n")
                            else:
                                stats['matched'] += 1
                                row = analyzer.analyze(row)
                                # Stats
                                if row.get('ip'): ip_counter[row['ip']] += 1
                                if row.get('status'): status_counter[row['status']] += 1
                                if row.get("is_alert"):
                                    stats['alerts'] += 1
                                    alert_counter[row['alert_reason']] += 1
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

            elif args.type == "db":
                conn = sqlite3.connect(args.output)
                cursor = conn.cursor()
                
                # Sanitize field names for SQL
                sql_fields = [f.replace("-", "_").replace(" ", "_") for f in extended_fields]
                placeholders = ", ".join(["?" for _ in sql_fields])
                columns_def = ", ".join([f"{f} TEXT" for f in sql_fields])
                
                cursor.execute(f"DROP TABLE IF EXISTS logs")
                cursor.execute(f"CREATE TABLE logs ({columns_def})")
                
                insert_sql = f"INSERT INTO logs ({', '.join(sql_fields)}) VALUES ({placeholders})"
                
                batch = []
                try:
                    for row in all_rows:
                        stats['total'] += 1
                        if row.get("error"):
                            stats['unmatched'] += 1
                            if args.strict:
                                logger.error(f"Strict mode enabled. Unmatched line: {row.get('raw_line')}")
                                if error_f: error_f.close()
                                conn.close()
                                sys.exit(1)
                            if error_f:
                                error_f.write(row.get('raw_line', '') + "\n")
                        else:
                            stats['matched'] += 1
                            row = analyzer.analyze(row)
                            # Stats
                            if row.get('ip'): ip_counter[row['ip']] += 1
                            if row.get('status'): status_counter[row['status']] += 1
                            if row.get("is_alert"):
                                stats['alerts'] += 1
                                alert_counter[row['alert_reason']] += 1
                            
                        # Prepare data for insertion (ensure all fields exist)
                        values = [str(row.get(f, "")) for f in extended_fields]
                        batch.append(values)
                        
                        if len(batch) >= 1000:
                            cursor.executemany(insert_sql, batch)
                            batch = []
                    
                    if batch:
                        cursor.executemany(insert_sql, batch)
                    conn.commit()
                finally:
                    conn.close()

            if error_f:
                error_f.close()

            analyzer.close()
            
            # Print Dashboard
            print_summary(
                stats, 
                alert_counter, 
                ip_counter.most_common(5), 
                status_counter.most_common(5)
            )

    except Exception as e:
        logger.error(f"Error during parsing or saving: {e}")
        import traceback
        logger.debug(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
