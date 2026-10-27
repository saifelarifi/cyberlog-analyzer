from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from importlib import resources
from pathlib import Path
from typing import TextIO, TypedDict

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import IntPrompt, Prompt
from rich.table import Table
from rich.text import Text

from newbiesaif import __version__
from newbiesaif.analyzer import (
    AnalysisResult,
    LogFileError,
    LogFormat,
    analyze_inputs,
)

console = Console()
error_console = Console(stderr=True)
ALERT_THRESHOLD = 3
OUTPUT_FORMATS = ("auto", "terminal", "json", "csv")
INPUT_FORMATS = ("auto", "auth", "journald")
WINDOW_PATTERN = re.compile(r"^(?P<amount>[1-9]\d*)(?P<unit>[smhd])$")


class UserCount(TypedDict):
    username: str
    failed_attempts: int


class ResultRow(TypedDict):
    ip_address: str
    failed_attempts: int
    alert: bool
    spike_alert: bool
    usernames: list[UserCount]
    first_seen: str | None
    last_seen: str | None


class ResultSummary(TypedDict):
    failed_attempts: int
    unique_ips: int
    alerts: int
    unique_usernames: int
    malformed_lines: int
    events_without_timestamp: int
    filtered_events: int


class ResultDocument(TypedDict):
    schema_version: str
    source: str
    sources: list[str]
    log_format: LogFormat
    threshold: int
    since: str | None
    until: str | None
    window_seconds: int | None
    syslog_year: int
    summary: ResultSummary
    username_summary: list[UserCount]
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
    console.print(f"[bold green]  Version:[/bold green] {__version__}")
    console.print("[bold green]  Author:[/bold green] Saif")
    console.print("[bold green]  Platform:[/bold green] Linux")
    console.print()


def _isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    normalized = value.astimezone(timezone.utc)
    return normalized.isoformat().replace("+00:00", "Z")


def _result_rows(
    analysis: AnalysisResult, threshold: int, window: timedelta | None
) -> list[ResultRow]:
    rows: list[ResultRow] = []
    for ip_address, stats in sorted(analysis.by_ip.items()):
        is_alert = stats.spike_alert if window is not None else stats.attempts >= threshold
        usernames = [
            {"username": username, "failed_attempts": count}
            for username, count in sorted(stats.usernames.items())
        ]
        rows.append(
            {
                "ip_address": ip_address,
                "failed_attempts": stats.attempts,
                "alert": is_alert,
                "spike_alert": stats.spike_alert,
                "usernames": usernames,
                "first_seen": _isoformat(stats.first_seen),
                "last_seen": _isoformat(stats.last_seen),
            }
        )
    return rows


def _source_label(sources: Sequence[str]) -> str:
    if len(sources) == 1:
        return sources[0]
    return ", ".join(sources)


def _result_document(
    sources: Sequence[str],
    log_format: LogFormat,
    threshold: int,
    analysis: AnalysisResult,
    since: datetime | None,
    until: datetime | None,
    window: timedelta | None,
    year: int | None,
) -> ResultDocument:
    rows = _result_rows(analysis, threshold, window)
    username_summary = [
        {"username": username, "failed_attempts": count}
        for username, count in sorted(analysis.by_username.items())
    ]
    resolved_year = year or datetime.now(timezone.utc).year
    return {
        "schema_version": "1.1.0",
        "source": _source_label(sources),
        "sources": list(sources),
        "log_format": log_format,
        "threshold": threshold,
        "since": _isoformat(since),
        "until": _isoformat(until),
        "window_seconds": int(window.total_seconds()) if window is not None else None,
        "syslog_year": resolved_year,
        "summary": {
            "failed_attempts": analysis.failed_attempts,
            "unique_ips": len(analysis.by_ip),
            "alerts": sum(bool(row["alert"]) for row in rows),
            "unique_usernames": len(analysis.by_username),
            "malformed_lines": analysis.malformed_lines,
            "events_without_timestamp": analysis.events_without_timestamp,
            "filtered_events": analysis.filtered_events,
        },
        "username_summary": username_summary,
        "results": rows,
    }


def render_report(
    sources: Sequence[str],
    log_format: LogFormat,
    threshold: int,
    analysis: AnalysisResult,
    since: datetime | None,
    until: datetime | None,
    window: timedelta | None,
) -> None:
    details = Text.assemble(
        ("Sources: ", "bold"),
        (_source_label(sources), ""),
        ("\nInput format: ", "bold"),
        (log_format, ""),
        ("\nAlert threshold: ", "bold"),
        (str(threshold), ""),
    )
    if window is not None:
        details.append("\nBurst window: ", style="bold")
        details.append(_format_window(window))
    if since is not None:
        details.append("\nSince: ", style="bold")
        details.append(_isoformat(since) or "")
    if until is not None:
        details.append("\nUntil: ", style="bold")
        details.append(_isoformat(until) or "")
    console.print(
        Panel(details, title="[green]Security Log Analysis[/green]", border_style="green")
    )

    if not analysis.by_ip:
        console.print("[yellow]No valid failed login attempts found.[/yellow]")
        return

    table = Table(show_header=True, header_style="bold cyan")
    for heading in ("IP address", "Attempts", "Alert", "Target users", "First seen", "Last seen"):
        table.add_column(heading)
    for row in _result_rows(analysis, threshold, window):
        usernames = ", ".join(
            f"{user['username']} ({user['failed_attempts']})"
            for user in row["usernames"]
        )
        table.add_row(
            Text(row["ip_address"]),
            str(row["failed_attempts"]),
            "YES" if row["alert"] else "no",
            Text(usernames),
            row["first_seen"] or "—",
            row["last_seen"] or "—",
        )
    console.print(table)
    console.print(
        Text(
            f"{analysis.failed_attempts} failed events, "
            f"{len(analysis.by_ip)} IPs, {len(analysis.by_username)} usernames; "
            f"{analysis.filtered_events} filtered, {analysis.malformed_lines} malformed."
        )
    )
    if analysis.events_without_timestamp:
        console.print(
            f"[yellow]Events without timestamps: "
            f"{analysis.events_without_timestamp}[/yellow]"
        )


def _format_window(window: timedelta) -> str:
    seconds = int(window.total_seconds())
    for unit, divisor in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds % divisor == 0:
            return f"{seconds // divisor}{unit}"
    return f"{seconds}s"


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
        _serialize_report(output_format, sys.stdout, document)
        return

    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = stream.name
            _serialize_report(output_format, stream, document)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, destination)
    except BaseException:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
        raise


def _serialize_report(
    output_format: str, stream: TextIO, document: ResultDocument
) -> None:
    if output_format == "json":
        json.dump(document, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
        return

    writer = csv.DictWriter(
        stream,
        fieldnames=[
            "ip_address",
            "failed_attempts",
            "alert",
            "usernames",
            "first_seen",
            "last_seen",
            "spike_alert",
        ],
    )
    writer.writeheader()
    for row in document["results"]:
        csv_row = dict(row)
        csv_row["usernames"] = json.dumps(row["usernames"], ensure_ascii=False)
        writer.writerow(csv_row)


def analyze_logs(
    files: list[Path],
    threshold: int,
    log_format: LogFormat = "auto",
    output: Path | None = None,
    output_format: str = "terminal",
    quiet: bool = False,
    stdin: TextIO | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    window: timedelta | None = None,
    year: int | None = None,
) -> int:
    try:
        analysis = analyze_inputs(
            files,
            stdin=stdin,
            log_format=log_format,
            threshold=threshold,
            since=since,
            until=until,
            window=window,
            year=year,
        )
    except (LogFileError, ValueError) as error:
        error_console.print(Text(f"Error: {error}", style="bold red"))
        return 1

    sources = [str(path) for path in files]
    if stdin is not None:
        sources.append("stdin")
    if output_format in {"json", "csv"}:
        document = _result_document(
            sources, log_format, threshold, analysis, since, until, window, year
        )
        try:
            _write_export(output_format, output, document)
        except OSError as error:
            error_console.print(Text(f"Error writing output: {error}", style="bold red"))
            return 1
    elif not quiet:
        render_report(sources, log_format, threshold, analysis, since, until, window)
    return 0


def analyze_bundled_sample(threshold: int) -> int:
    with bundled_sample() as sample_path:
        return analyze_logs([sample_path], threshold)


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
                analyze_logs([Path(file_name)], threshold)
            else:
                analyze_bundled_sample(threshold)
        elif choice == "2":
            console.print(
                Panel(
                    f"NewbieSaif {__version__}\nA Linux authentication log analyzer.",
                    title="About",
                    border_style="green",
                )
            )
        elif choice == "3":
            console.print(
                "Usage:\n"
                "  newbiesaif --file /var/log/auth.log --format auth\n"
                "  newbiesaif --file journal.json --format journald\n"
                "  newbiesaif --file auth.log --since 2026-10-01T00:00:00Z "
                "--window 5m\n"
                "  newbiesaif   (interactive menu; Enter selects bundled sample)"
            )
        Prompt.ask("\nPress Enter to return to the menu", default="")


def _parse_datetime(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "use an ISO 8601 timestamp, for example 2026-10-27T12:30:00Z"
        ) from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_window(value: str) -> timedelta:
    match = WINDOW_PATTERN.fullmatch(value.lower())
    if match is None:
        raise argparse.ArgumentTypeError("use a positive duration such as 30s, 5m, 1h, or 1d")
    amount = int(match.group("amount"))
    multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group("unit")]
    return timedelta(seconds=amount * multiplier)


def _add_analysis_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--file",
        dest="files",
        action="append",
        type=Path,
        help="Log file; repeat this option to analyze multiple files",
    )
    parser.add_argument("--stdin", action="store_true", help="Also read log lines from stdin")
    parser.add_argument(
        "--threshold",
        type=int,
        default=ALERT_THRESHOLD,
        help=f"Alert after this many failures (default: {ALERT_THRESHOLD})",
    )
    parser.add_argument(
        "--format",
        choices=INPUT_FORMATS,
        default="auto",
        help="Input log format: auth, journald JSON/text, or auto-detect",
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
        help="Suppress terminal results; exports and errors remain visible",
    )
    parser.add_argument("--since", type=_parse_datetime, help="Include events at or after ISO time")
    parser.add_argument("--until", type=_parse_datetime, help="Include events at or before ISO time")
    parser.add_argument(
        "--window",
        type=_parse_window,
        help="Flag a burst of threshold failures within a duration, e.g. 5m",
    )
    parser.add_argument(
        "--year",
        type=int,
        help="Year for syslog timestamps that omit a year (default: current UTC year)",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="newbiesaif",
        description="Analyze Linux authentication logs for repeated failed logins.",
        epilog=(
            "Examples: newbiesaif --file /var/log/auth.log --format auth; "
            "newbiesaif --file journal.json --format journald --output alerts.json; "
            "newbiesaif --file auth.log --since 2026-10-01T00:00:00Z --window 5m"
        ),
    )
    parser.add_argument("--version", action="version", version=f"NewbieSaif {__version__}")
    _add_analysis_options(parser)
    subparsers = parser.add_subparsers(dest="command")
    logs_parser = subparsers.add_parser("logs", help="Analyze security log files")
    _add_analysis_options(logs_parser)

    args = parser.parse_args(argv)
    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    if args.year is not None and not 1 <= args.year <= 9999:
        parser.error("--year must be between 1 and 9999")
    if args.since is not None and args.until is not None and args.since > args.until:
        parser.error("--since must be earlier than or equal to --until")

    files = args.files or []
    stdin_requested = args.stdin or Path("-") in files
    files = [path for path in files if path != Path("-")]
    if not files and not stdin_requested and args.command is None:
        return interactive_menu()
    if not files and not stdin_requested:
        parser.error("provide --file at least once or pass --stdin")

    try:
        resolved_output_format = _output_format(args.output_format, args.output)
    except ValueError as error:
        parser.error(str(error))
    if args.output is not None and resolved_output_format == "terminal":
        parser.error("--output requires JSON or CSV output; choose --output-format")

    if not args.quiet and resolved_output_format == "terminal":
        show_banner()
    return analyze_logs(
        files,
        args.threshold,
        args.format,
        args.output,
        resolved_output_format,
        args.quiet,
        sys.stdin if stdin_requested else None,
        args.since,
        args.until,
        args.window,
        args.year,
    )


if __name__ == "__main__":
    raise SystemExit(main())
