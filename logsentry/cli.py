import argparse
import sys
import time

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from . import __version__
from .parser import parse_log_file, count_parseable_lines
from .analyzer import LogAnalyzer
from .reporter import print_full_report, export_json, export_csv

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logsentry",
        description="LogSentry — Security Log Analyzer",
        epilog="Example: logsentry access.log --export json -o report",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("logfile", help="Path to the log file to analyze")

    parser.add_argument(
        "-e", "--export",
        choices=["json", "csv", "both"],
        default=None,
        help="Export format (default: terminal only)",
    )
    parser.add_argument(
        "-o", "--output",
        default="logsentry_report",
        help="Output filename without extension (default: logsentry_report)",
    )
    parser.add_argument(
        "--brute-force-threshold",
        type=int, default=10,
        help="Failed login attempts before flagging brute force (default: 10)",
    )
    parser.add_argument(
        "--rate-limit",
        type=int, default=100,
        help="Requests/min to flag as rate abuse (default: 100)",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Only export, don't print to terminal",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"LogSentry v{__version__}",
    )

    return parser


def run():
    args = build_parser().parse_args()

    # quick check that the file exists and has parseable content
    try:
        n_parseable = count_parseable_lines(args.logfile)
    except FileNotFoundError:
        console.print(f"\n  [bold red]Error:[/] File not found: {args.logfile}")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n  [bold red]Error:[/] {e}")
        sys.exit(1)

    if n_parseable == 0:
        console.print(f"\n  [bold yellow]Warning:[/] No parseable entries in {args.logfile}")
        console.print("  Supported: Apache Combined, Nginx, Common Log Format (CLF)")
        sys.exit(1)

    # parse + show progress
    entries = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30),
        TextColumn("[dim]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Parsing log entries...", total=n_parseable)
        for entry in parse_log_file(args.logfile):
            entries.append(entry)
            progress.advance(task)

        progress.update(task, description="Running analysis...")
        time.sleep(0.2)

    # analyze
    analyzer = LogAnalyzer(
        brute_force_threshold=args.brute_force_threshold,
        rate_limit_threshold=args.rate_limit,
    )
    result = analyzer.analyze(entries)

    # output
    if not args.quiet:
        print_full_report(result)

    if args.export in ("json", "both"):
        export_json(result, f"{args.output}.json")
    if args.export in ("csv", "both"):
        export_csv(result, f"{args.output}.csv")

    # exit codes: 0 = clean, 1 = threats found, 2 = critical threats
    if result.severity_counts.get("CRITICAL", 0) > 0:
        sys.exit(2)
    elif result.total_threats > 0:
        sys.exit(1)
    else:
        sys.exit(0)
