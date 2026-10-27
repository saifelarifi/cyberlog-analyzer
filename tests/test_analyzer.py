import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from io import StringIO

import pytest

from newbiesaif.analyzer import (
    AnalysisResult,
    LogFileError,
    analyze_inputs,
    analyze_log_file,
    analyze_stream,
    parse_failed_login,
    parse_failed_login_event,
)


def test_parse_failed_login_validates_and_normalizes_ip_addresses():
    assert parse_failed_login(
        "FAILED Login failed for user admin from 203.0.113.25\n"
    ) == "203.0.113.25"
    assert parse_failed_login(
        "FAILED Login failed for user admin from 2001:0db8::1\n"
    ) == "2001:db8::1"
    assert parse_failed_login("Login failed for user admin from 999.1.1.1") is None
    assert parse_failed_login("Login successful for user admin from 203.0.113.25") is None
    assert parse_failed_login("Login failed with no source address") is None


def test_auth_log_event_captures_username_and_syslog_timestamp():
    event = parse_failed_login_event(
        "Oct 27 10:30:20 host sshd[123]: Failed password for invalid user guest "
        "from 2001:db8::1 port 22 ssh2",
        "auth",
        year=2026,
    )

    assert event is not None
    assert event.ip_address == "2001:db8::1"
    assert event.username == "guest"
    assert event.timestamp == datetime(2026, 10, 27, 10, 30, 20, tzinfo=timezone.utc)


def test_journald_json_event_uses_realtime_timestamp():
    record = json.dumps(
        {
            "MESSAGE": "sshd[123]: Failed password for admin from 198.51.100.9 "
            "port 22 ssh2",
            "__REALTIME_TIMESTAMP": "1793097000000000",
        }
    )
    event = parse_failed_login_event(record, "journald")

    assert event is not None
    assert event.username == "admin"
    assert event.timestamp == datetime.fromtimestamp(1793097000, tz=timezone.utc)


def test_analyze_log_file_counts_by_ip_and_username(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "2026-10-24 09:01:12 FAILED Login failed for user admin from 203.0.113.25\n"
        "2026-10-24 09:01:18 FAILED Login failed for user root from 203.0.113.25\n"
        "2026-10-24 09:01:24 FAILED Login failed for user root from invalid-ip\n"
        "2026-10-24 09:02:00 INFO Login successful for user root from 198.51.100.4\n",
        encoding="utf-8",
    )

    result = analyze_log_file(log_file)

    assert result.failed_attempts == 2
    assert result.by_ip["203.0.113.25"].attempts == 2
    assert result.by_ip["203.0.113.25"].usernames == Counter({"root": 1, "admin": 1})
    assert result.by_username == Counter({"root": 1, "admin": 1})
    assert result.malformed_lines == 1


def test_since_until_filter_events_inclusive(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "2026-10-27T09:00:00Z host sshd: Failed password for a from 203.0.113.1 port 22\n"
        "2026-10-27T10:00:00Z host sshd: Failed password for b from 203.0.113.2 port 22\n"
        "2026-10-27T11:00:00Z host sshd: Failed password for c from 203.0.113.3 port 22\n",
        encoding="utf-8",
    )

    result = analyze_log_file(
        log_file,
        since=datetime(2026, 10, 27, 10, tzinfo=timezone.utc),
        until=datetime(2026, 10, 27, 10, tzinfo=timezone.utc),
    )

    assert list(result.by_ip) == ["203.0.113.2"]
    assert result.filtered_events == 2


def test_window_flags_bursts_not_slow_retries(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "2026-10-27T10:00:00Z host sshd: Failed password for a from 203.0.113.1 port 22\n"
        "2026-10-27T10:04:00Z host sshd: Failed password for a from 203.0.113.1 port 22\n"
        "2026-10-27T10:20:00Z host sshd: Failed password for a from 203.0.113.2 port 22\n"
        "2026-10-27T10:30:00Z host sshd: Failed password for a from 203.0.113.2 port 22\n",
        encoding="utf-8",
    )

    result = analyze_log_file(log_file, threshold=2, window=timedelta(minutes=5))

    assert result.by_ip["203.0.113.1"].spike_alert is True
    assert result.by_ip["203.0.113.2"].spike_alert is False


def test_multiple_files_and_stdin_are_aggregated(tmp_path):
    first = tmp_path / "first.log"
    second = tmp_path / "second.log"
    first.write_text("Login failed for user admin from 203.0.113.25\n", encoding="utf-8")
    second.write_text("Login failed for user admin from 203.0.113.25\n", encoding="utf-8")

    result = analyze_inputs(
        [first, second], stdin=StringIO("Login failed for user root from 198.51.100.7\n")
    )

    assert result.failed_attempts == 3
    assert result.by_ip["203.0.113.25"].attempts == 2
    assert result.by_ip["198.51.100.7"].attempts == 1


def test_missing_log_file_raises_clear_error(tmp_path):
    with pytest.raises(LogFileError, match="Cannot read log file"):
        analyze_log_file(tmp_path / "missing.log")


def test_invalid_utf8_raises_clear_error(tmp_path):
    log_file = tmp_path / "invalid.log"
    log_file.write_bytes(b"Login failed from 203.0.113.25\n\xff")

    with pytest.raises(LogFileError, match="Cannot read log input"):
        analyze_log_file(log_file)


def test_overlong_line_is_skipped_without_breaking_following_lines():
    long_line = "Login failed " + ("x" * 70_000) + "\n"
    valid_line = "Login failed for user admin from 203.0.113.25\n"
    result = analyze_stream(StringIO(long_line + valid_line), source="stdin")

    assert result.malformed_lines == 1
    assert result.failed_attempts == 1


def test_events_without_timestamp_are_counted_and_filtered_when_needed():
    result = analyze_stream(
        StringIO("Login failed for user admin from 203.0.113.25\n"),
        source="stdin",
        since=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert result.events_without_timestamp == 1
    assert result.filtered_events == 1
    assert result.failed_attempts == 0


def test_invalid_threshold_is_rejected():
    with pytest.raises(ValueError, match="threshold"):
        analyze_inputs([], stdin=StringIO(""), threshold=0)


def test_empty_sources_are_rejected():
    with pytest.raises(LogFileError, match="at least one"):
        analyze_inputs([])


def test_analysis_result_defaults_are_independent():
    first = AnalysisResult()
    second = AnalysisResult()
    first.by_username["alice"] += 1
    assert not second.by_username
