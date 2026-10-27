"""Read and analyze supported Linux authentication log formats."""

from __future__ import annotations

import bisect
import ipaddress
import json
import re
from collections import Counter
from collections.abc import Iterable, TextIO
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

LogFormat = Literal["auto", "auth", "journald"]
MAX_LOG_LINE_LENGTH = 64 * 1024

FAILED_LOGIN = re.compile(
    r"(?:\bLogin failed\b.*?\bfrom|\bFailed password for "
    r"(?:(?:invalid user)\s+)?\S+\s+from)\s+"
    r"(?P<ip>[^\s,]+)(?:\s+port\s+\d+(?:\s+\S+.*)?)?\s*$"
)
LOGIN_USERNAME = re.compile(r"\bLogin failed\b.*?\buser\s+(?P<username>\S+).*?\bfrom")
SSH_USERNAME = re.compile(
    r"\bFailed password for (?:(?:invalid user)\s+)?(?P<username>\S+)\s+from"
)
ISO_TIMESTAMP = re.compile(
    r"^\s*(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
SYSLOG_TIMESTAMP = re.compile(
    r"^\s*(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)


class LogFileError(Exception):
    """Raised when an input source cannot be read as a UTF-8 text stream."""


@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime | None
    username: str | None
    ip_address: str


@dataclass
class IPStats:
    attempts: int = 0
    usernames: Counter[str] = field(default_factory=Counter)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    spike_alert: bool = False


@dataclass
class AnalysisResult:
    by_ip: dict[str, IPStats] = field(default_factory=dict)
    by_username: Counter[str] = field(default_factory=Counter)
    malformed_lines: int = 0
    events_without_timestamp: int = 0
    filtered_events: int = 0

    @property
    def failed_attempts(self) -> int:
        return sum(stats.attempts for stats in self.by_ip.values())


def _json_record(line: str, log_format: LogFormat) -> dict[str, object] | None:
    if log_format == "auth" or not line.lstrip().startswith("{"):
        return None
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return None
    return record if isinstance(record, dict) else None


def _record_timestamp(record: dict[str, object] | None) -> datetime | None:
    if record is None:
        return None
    raw_timestamp = record.get("__REALTIME_TIMESTAMP")
    if raw_timestamp is None:
        raw_timestamp = record.get("_SOURCE_REALTIME_TIMESTAMP")
    try:
        microseconds = int(str(raw_timestamp))
        seconds, remainder = divmod(microseconds, 1_000_000)
        return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(
            microsecond=remainder
        )
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _parse_timestamp(line: str, year: int) -> datetime | None:
    iso_match = ISO_TIMESTAMP.match(line)
    if iso_match:
        value = iso_match.group("timestamp").replace("Z", "+00:00")
        try:
            timestamp = datetime.fromisoformat(value)
        except ValueError:
            return None
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return timestamp.astimezone(timezone.utc)

    syslog_match = SYSLOG_TIMESTAMP.match(line)
    if not syslog_match:
        return None
    try:
        timestamp = datetime.strptime(
            f"{year} {syslog_match.group('timestamp')}", "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        return None
    return timestamp.replace(tzinfo=timezone.utc)


def _safe_username(value: str | None) -> str | None:
    if not value or len(value) > 128 or not value.isprintable():
        return None
    return value


def parse_failed_login_event(
    line: str, log_format: LogFormat = "auto", year: int | None = None
) -> LogEvent | None:
    """Parse a supported failed-login event without retaining the raw log line."""
    record = _json_record(line, log_format)
    message = record.get("MESSAGE") if record else line
    if not isinstance(message, str):
        return None

    match = FAILED_LOGIN.search(message.rstrip("\r\n"))
    if match is None:
        return None
    try:
        ip_address = str(ipaddress.ip_address(match.group("ip")))
    except ValueError:
        return None

    username_match = LOGIN_USERNAME.search(message) or SSH_USERNAME.search(message)
    username = _safe_username(username_match.group("username")) if username_match else None
    timestamp = _record_timestamp(record)
    if timestamp is None:
        timestamp_year = year or datetime.now(timezone.utc).year
        timestamp = _parse_timestamp(line, timestamp_year)
        if timestamp is None and message != line:
            timestamp = _parse_timestamp(message, timestamp_year)
    return LogEvent(timestamp, username, ip_address)


def parse_failed_login(line: str, log_format: LogFormat = "auto") -> str | None:
    """Compatibility helper returning only the source IP for a log line."""
    event = parse_failed_login_event(line, log_format)
    return event.ip_address if event else None


def _bounded_lines(stream: TextIO) -> Iterable[str | None]:
    """Yield lines, replacing overlong lines with None while draining safely."""
    while True:
        line = stream.readline(MAX_LOG_LINE_LENGTH + 1)
        if not line:
            return
        if len(line) <= MAX_LOG_LINE_LENGTH:
            yield line
            continue
        while line and not line.endswith("\n"):
            line = stream.readline(MAX_LOG_LINE_LENGTH + 1)
        yield None


def _record_event(
    result: AnalysisResult,
    event: LogEvent,
    *,
    threshold: int,
    since: datetime | None,
    until: datetime | None,
    window: timedelta | None,
    windows_by_ip: dict[str, list[datetime]],
) -> None:
    timestamp = event.timestamp
    if timestamp is None:
        result.events_without_timestamp += 1
        if since is not None or until is not None:
            result.filtered_events += 1
            return
    elif (since is not None and timestamp < since) or (
        until is not None and timestamp > until
    ):
        result.filtered_events += 1
        return

    stats = result.by_ip.setdefault(event.ip_address, IPStats())
    stats.attempts += 1
    if event.username:
        stats.usernames[event.username] += 1
        result.by_username[event.username] += 1
    if timestamp is not None:
        if stats.first_seen is None or timestamp < stats.first_seen:
            stats.first_seen = timestamp
        if stats.last_seen is None or timestamp > stats.last_seen:
            stats.last_seen = timestamp

        if window is not None and not stats.spike_alert:
            timestamps = windows_by_ip.setdefault(event.ip_address, [])
            bisect.insort(timestamps, timestamp)
            newest = timestamps[-1]
            cutoff = newest - window
            first_in_window = bisect.bisect_left(timestamps, cutoff)
            if first_in_window:
                del timestamps[:first_in_window]
            if len(timestamps) >= threshold:
                stats.spike_alert = True
                windows_by_ip.pop(event.ip_address, None)


def analyze_stream(
    stream: TextIO,
    *,
    source: str,
    log_format: LogFormat = "auto",
    threshold: int = 3,
    since: datetime | None = None,
    until: datetime | None = None,
    window: timedelta | None = None,
    year: int | None = None,
    result: AnalysisResult | None = None,
    windows_by_ip: dict[str, list[datetime]] | None = None,
) -> AnalysisResult:
    """Analyze a text stream incrementally and aggregate events in bounded state."""
    if threshold < 1:
        raise ValueError("threshold must be greater than zero")
    analysis = result if result is not None else AnalysisResult()
    active_windows = windows_by_ip if windows_by_ip is not None else {}
    inferred_year = year or datetime.now(timezone.utc).year
    try:
        for line in _bounded_lines(stream):
            if line is None:
                analysis.malformed_lines += 1
                continue
            event = parse_failed_login_event(line, log_format, inferred_year)
            if event is None:
                if "Login failed" in line or "Failed password" in line:
                    analysis.malformed_lines += 1
                continue
            _record_event(
                analysis,
                event,
                threshold=threshold,
                since=since,
                until=until,
                window=window,
                windows_by_ip=active_windows,
            )
    except (OSError, UnicodeError) as error:
        raise LogFileError(f"Cannot read log input {source}: {error}") from error
    return analysis


def analyze_inputs(
    log_files: list[Path],
    *,
    stdin: TextIO | None = None,
    log_format: LogFormat = "auto",
    threshold: int = 3,
    since: datetime | None = None,
    until: datetime | None = None,
    window: timedelta | None = None,
    year: int | None = None,
) -> AnalysisResult:
    """Analyze multiple files and optional standard input as one report."""
    if not log_files and stdin is None:
        raise LogFileError("Provide at least one log file or enable --stdin")
    if since is not None and until is not None and since > until:
        raise ValueError("--since must be earlier than or equal to --until")

    result = AnalysisResult()
    windows_by_ip: dict[str, list[datetime]] = {}
    for log_file in log_files:
        try:
            with log_file.open("r", encoding="utf-8") as stream:
                analyze_stream(
                    stream,
                    source=str(log_file),
                    log_format=log_format,
                    threshold=threshold,
                    since=since,
                    until=until,
                    window=window,
                    year=year,
                    result=result,
                    windows_by_ip=windows_by_ip,
                )
        except (OSError, UnicodeError) as error:
            raise LogFileError(f"Cannot read log file {log_file}: {error}") from error
    if stdin is not None:
        analyze_stream(
            stdin,
            source="stdin",
            log_format=log_format,
            threshold=threshold,
            since=since,
            until=until,
            window=window,
            year=year,
            result=result,
            windows_by_ip=windows_by_ip,
        )
    return result


def analyze_log_file(
    log_file: Path,
    log_format: LogFormat = "auto",
    *,
    threshold: int = 3,
    since: datetime | None = None,
    until: datetime | None = None,
    window: timedelta | None = None,
    year: int | None = None,
) -> AnalysisResult:
    """Analyze one file; retained as the simple single-file entry point."""
    return analyze_inputs(
        [log_file],
        log_format=log_format,
        threshold=threshold,
        since=since,
        until=until,
        window=window,
        year=year,
    )
