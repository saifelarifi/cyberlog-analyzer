from collections import Counter
import json

import pytest

from newbiesaif.analyzer import LogFileError, analyze_log_file, parse_failed_login


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


def test_auth_log_openssh_format_is_supported():
    assert parse_failed_login(
        "Oct 27 10:30:20 host sshd[123]: Failed password for admin "
        "from 203.0.113.25 port 22 ssh2\n",
        "auth",
    ) == "203.0.113.25"
    assert parse_failed_login(
        "Oct 27 10:30:20 host sshd[123]: Failed password for invalid user guest "
        "from 2001:db8::1 port 22 ssh2\n",
        "auth",
    ) == "2001:db8::1"


def test_journald_json_message_is_supported():
    line = json.dumps(
        {
            "MESSAGE": "sshd[123]: Failed password for admin from 198.51.100.9 "
            "port 22 ssh2",
            "_COMM": "sshd",
        }
    )
    assert parse_failed_login(line, "journald") == "198.51.100.9"
    assert parse_failed_login(line, "auto") == "198.51.100.9"


def test_analyze_log_file_counts_by_valid_ip(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Login failed for user admin from 203.0.113.25\n"
        "Login failed for user root from 203.0.113.25\n"
        "Login failed for user root from invalid-ip\n"
        "Login successful for user root from 198.51.100.4\n",
        encoding="utf-8",
    )

    assert analyze_log_file(log_file) == Counter({"203.0.113.25": 2})


def test_missing_log_file_raises_clear_error(tmp_path):
    with pytest.raises(LogFileError, match="Cannot read log file"):
        analyze_log_file(tmp_path / "missing.log")


def test_directory_is_not_read_as_log_file(tmp_path):
    with pytest.raises(LogFileError, match="Cannot read log file"):
        analyze_log_file(tmp_path)


def test_invalid_utf8_raises_clear_error(tmp_path):
    log_file = tmp_path / "invalid.log"
    log_file.write_bytes(b"Login failed from 203.0.113.25\n\xff")

    with pytest.raises(LogFileError, match="Cannot read log file"):
        analyze_log_file(log_file)
