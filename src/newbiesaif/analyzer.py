"""Read and analyze supported Linux authentication log formats."""

from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from pathlib import Path
from typing import Literal

LogFormat = Literal["auto", "auth", "journald"]

FAILED_LOGIN = re.compile(
    r"(?:Login failed\b.*?\bfrom|Failed password for "
    r"(?:(?:invalid user)\s+)?\S+\s+from)\s+"
    r"(?P<ip>[^\s,]+)(?:\s+port\s+\d+(?:\s+\S+.*)?)?\s*$"
)


class LogFileError(Exception):
    """Raised when a log cannot be read as a UTF-8 text file."""


def _message_for_line(line: str, log_format: LogFormat) -> str:
    """Extract the MESSAGE field from journalctl JSON when applicable."""
    stripped = line.lstrip()
    if log_format != "auth" and stripped.startswith("{"):
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError:
            return line
        if isinstance(record, dict) and isinstance(record.get("MESSAGE"), str):
            return record["MESSAGE"]
    return line


def parse_failed_login(line: str, log_format: LogFormat = "auto") -> str | None:
    """Return a normalized source IP for a supported failed SSH login."""
    message = _message_for_line(line.rstrip("\r\n"), log_format)
    match = FAILED_LOGIN.search(message)
    if match is None:
        return None

    try:
        return str(ipaddress.ip_address(match.group("ip")))
    except ValueError:
        return None


def analyze_log_file(
    log_file: Path, log_format: LogFormat = "auto"
) -> Counter[str]:
    """Count supported failed logins by valid IP, streaming the input file."""
    failed_attempts: Counter[str] = Counter()
    try:
        with log_file.open("r", encoding="utf-8") as stream:
            for line in stream:
                ip_address = parse_failed_login(line, log_format)
                if ip_address is not None:
                    failed_attempts[ip_address] += 1
    except (OSError, UnicodeError) as error:
        raise LogFileError(f"Cannot read log file {log_file}: {error}") from error

    return failed_attempts
