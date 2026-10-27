from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from contextlib import contextmanager
from importlib import resources
from pathlib import Path
from typing import Iterator, TextIO, TypedDict

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import IntPrompt, Prompt
from rich.text import Text

from newbiesaif.analyzer import LogFileError, LogFormat, analyze_log_file

console = Console()
error_console = Console(stderr=True)
ALERT_THRESHOLD = 3
OUTPUT_FORMATS = ("auto", "terminal", "json", "csv")
INPUT_FORMATS = ("auto", "auth", "journald")


class ResultRow(TypedDict):
    ip_address: str
    failed_attempts: int
    alert: bool


class ResultSummary(TypedDict):
    failed_attempts: int
    unique_ips: int
    alerts: int


class ResultDocument(TypedDict):
    source: str
    log_format: LogFormat
    threshold: int
    summary: ResultSummary
    results: list[ResultRow]


@contextmanager
def bundled_sample() -> Iterator[Path]:
    """Yield the bundled sample path, including for non-filesystem packages."""
    sample = resources.files("newbiesaif").joinpath("sample.log")
    with resources.as_file(sample) as sample_path:
        yield sample_path


def show_banner() -> None:
    console.print()
    console.print(
        Panel(
            Text("NewbieSaif", style="bold green"),
            title="[bold white]NewbieSaif[/bold white]",
            subtitle="[orange1]Linux Security Toolkit[/orange1]",
            border_style="green",
            box=box.DOUBLE,
            expand=False,
        )
    )
    console.print("[bold green]  Version:[/bold green] 0.1.0")
    console.print("[bold green]  Author:[/bold green] Saif")
    console.print("[bold green]  Platform:[/bold green] Linux")
    console.print()


def _result_rows(
    failed_attempts: Counter[str], threshold: int
) -> list[ResultRow]:
    return [
        {
            "ip_address": ip_address,
            "failed_attempts": count,
            "alert": count >= threshold,
        }
        for ip_address, count in sorted(failed_attempts.items())
    ]


def _result_document(
    source: Path,
    log_format: LogFormat,
    threshold: int,
    failed_attempts: Counter[str],
) -> ResultDocument:
    rows = _result_rows(failed_attempts, threshold)
    return {
        "source": str(source),
        "log_format": log_format,
        "threshold": threshold,
        "summary": {
            "failed_attempts": sum(failed_attempts.values()),
            "unique_ips": len(failed_attempts),
            "alerts": sum(bool(row["alert"]) for row in rows),
        },
        "results": rows,
    }


def render_report(
    log_file: Path, threshold: int, failed_attempts: Counter[str]
) -> None:
    console.print(
        Panel(
            Text.assemble(
                ("Analyzing: ", "bold"),
                (str(log_file), ""),
                ("\nAlert threshold: ", "bold"),
                (str(threshold), ""),
            ),
            title="[green]Security Log Analysis[/green]",
            border_style="green",
        )
    )

    if not failed_attempts:
        console.print("[yellow]No valid failed login attempts found.[/yellow]")
        return

    for row in _result_rows(failed_attempts, threshold):
        ip_address = str(row["ip_address"])
        count = int(row["failed_attempts"])
        is_alert = bool(row["alert"])
        status = (
            "[bold red]ALERT: Repeated failed logins detected![/bold red]"
            if is_alert
            else "[green]Status: Below alert threshold[/green]"
        )
        console.print(
            Panel(
                f"[bold]IP Address:[/bold] {ip_address}\n"
                f"[bold]Failed Attempts:[/bold] {count}\n{status}",
                border_style="red" if is_alert else "green",
            )
        )


def _output_format(requested: str, output: Path | None) -> str:
    if requested != "auto":
        return requested
    if output is None:
        return "terminal"
    suffix = output.suffix.lower().lstrip(".")
    if suffix in {"json", "csv"}:
        return suffix
    raise ValueError("Use a .json or .csv output filename, or set --output-format")


def _write_export(
    output_format: str,
    destination: Path | None,
    document: ResultDocument,
) -> None:
    if destination is None:
        stream: TextIO = sys.stdout
        close_stream = False
    else:
        stream = destination.open("w", encoding="utf-8", newline="")
        close_stream = True

    try:
        if output_format == "json":
            json.dump(document, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        else:
            writer = csv.DictWriter(
                stream,
                fieldnames=["ip_address", "failed_attempts", "alert"],
            )
            writer.writeheader()
            writer.writerows(document["results"])
    finally:
        if close_stream:
            stream.close()


def analyze_logs(
    log_file: Path,
    threshold: int,
    log_format: LogFormat = "auto",
    output: Path | None = None,
    output_format: str = "terminal",
    quiet: bool = False,
) -> int:
    try:
        failed_attempts = analyze_log_file(log_file, log_format)
    except LogFileError as error:
        error_console.print(Text(f"Error: {error}", style="bold red"))
        return 1

    if output_format in {"json", "csv"}:
        document = _result_document(log_file, log_format, threshold, failed_attempts)
        try:
            _write_export(output_format, output, document)
        except OSError as error:
            error_console.print(Text(f"Error writing output: {error}", style="bold red"))
            return 1
    elif not quiet:
        render_report(log_file, threshold, failed_attempts)
    return 0


def analyze_bundled_sample(threshold: int) -> int:
    with bundled_sample() as sample_path:
        return analyze_logs(sample_path, threshold)


def interactive_menu() -> int:
    show_banner()
    while True:
        console.print("[bold green]  [1][/bold green] Analyze security logs")
        console.print("[bold green]  [2][/bold green] Tool information")
        console.print("[bold green]  [3][/bold green] Help & usage")
        console.print("[bold red]  [0][/bold red] Exit\n")
        choice = Prompt.ask(
            "[bold white]newbiesaif[/bold white]",
            choices=["0", "1", "2", "3"],
            default="1",
        )
        if choice == "0":
            console.print("[green]Stay safe. Goodbye![/green]")
            return 0
        if choice == "1":
            file_name = Prompt.ask(
                "Path to log file (press Enter for bundled sample)", default=""
            )
            threshold = IntPrompt.ask("Alert threshold", default=ALERT_THRESHOLD)
            if threshold < 1:
                console.print("[red]Threshold must be at least 1.[/red]")
            elif file_name:
                analyze_logs(Path(file_name), threshold)
            else:
                analyze_bundled_sample(threshold)
        elif choice == "2":
            console.print(
                Panel(
                    "NewbieSaif 0.1.0\n"
                    "A Linux authentication log analyzer.",
                    title="About",
                    border_style="green",
                )
            )
        elif choice == "3":
            console.print(
                "Usage:\n"
                "  newbiesaif --file /var/log/auth.log --format auth\n"
                "  newbiesaif --file journal.json --format journald\n"
                "  newbiesaif   (interactive menu; Enter selects bundled sample)"
            )
        Prompt.ask("\nPress Enter to return to the menu", default="")


def _add_analysis_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--file", type=Path, help="Path to the log file")
    parser.add_argument(
        "--threshold",
        type=int,
        default=ALERT_THRESHOLD,
        help=f"Alert after this many failures per IP (default: {ALERT_THRESHOLD})",
    )
    parser.add_argument(
        "--format",
        choices=INPUT_FORMATS,
        default="auto",
        help="Input log format: auth, journald JSON, or auto-detect (default)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write JSON or CSV results to this path (inferred from its extension)",
    )
    parser.add_argument(
        "--output-format",
        choices=OUTPUT_FORMATS,
        default="auto",
        help="Output as terminal, json, or csv; auto uses the output filename",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress the terminal report (exports and errors remain visible)",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="newbiesaif",
        description="Analyze Linux authentication logs for repeated failed logins.",
        epilog=(
            "Examples: newbiesaif --file /var/log/auth.log --format auth; "
            "newbiesaif --file journal.json --format journald --output alerts.json"
        ),
    )
    parser.add_argument("--version", action="version", version="NewbieSaif 0.1.0")
    _add_analysis_options(parser)
    subparsers = parser.add_subparsers(dest="command")
    logs_parser = subparsers.add_parser("logs", help="Analyze a security log file")
    _add_analysis_options(logs_parser)

    args = parser.parse_args(argv)
    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    if args.command is None and args.file is None:
        return interactive_menu()
    if args.file is None:
        parser.error("--file is required when using the logs command")

    try:
        resolved_output_format = _output_format(args.output_format, args.output)
    except ValueError as error:
        parser.error(str(error))
    if args.output is not None and resolved_output_format == "terminal":
        parser.error("--output requires JSON or CSV output; choose --output-format")

    if not args.quiet and resolved_output_format == "terminal":
        show_banner()
    return analyze_logs(
        args.file,
        args.threshold,
        args.format,
        args.output,
        resolved_output_format,
        args.quiet,
    )


if __name__ == "__main__":
    raise SystemExit(main())
