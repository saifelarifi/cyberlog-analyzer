import csv
import json
from io import StringIO
from pathlib import Path

import jsonschema
import pytest
from rich.console import Console

from newbiesaif import cli


def set_console(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(cli, "console", Console(file=output, force_terminal=False))
    monkeypatch.setattr(cli, "error_console", Console(file=output, force_terminal=False))
    return output


def test_direct_cli_options_analyze_log_and_apply_threshold(tmp_path, monkeypatch):
    output = set_console(monkeypatch)
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Login failed for user admin from 203.0.113.25\n" * 3,
        encoding="utf-8",
    )

    assert cli.main(["--file", str(log_file), "--threshold", "3"]) == 0
    assert "203.0.113.25" in output.getvalue()
    assert "YES" in output.getvalue()


def test_json_export_contains_summary_and_alerts(tmp_path, monkeypatch):
    output = set_console(monkeypatch)
    log_file = tmp_path / "auth.log"
    output_file = tmp_path / "result.json"
    log_file.write_text(
        "Login failed for user admin from 203.0.113.25\n" * 2,
        encoding="utf-8",
    )

    assert cli.main(
        ["--file", str(log_file), "--threshold", "2", "--output", str(output_file)]
    ) == 0
    report = json.loads(output_file.read_text(encoding="utf-8"))
    assert report["schema_version"] == "1.1.0"
    assert report["summary"]["failed_attempts"] == 2
    assert report["summary"]["unique_ips"] == 1
    assert report["summary"]["alerts"] == 1
    assert report["results"][0]["alert"] is True
    assert report["results"][0]["usernames"] == [
        {"username": "admin", "failed_attempts": 2}
    ]
    assert output.getvalue() == ""


def test_json_report_matches_schema_and_schema_accepts_legacy_shape(tmp_path, monkeypatch):
    set_console(monkeypatch)
    log_file = tmp_path / "auth.log"
    output_file = tmp_path / "result.json"
    log_file.write_text(
        "2026-10-27T10:00:00Z host sshd: Failed password for alice from "
        "203.0.113.25 port 22\n",
        encoding="utf-8",
    )
    assert cli.main(
        ["--file", str(log_file), "--output", str(output_file)]
    ) == 0

    schema_path = Path(__file__).parents[1] / "docs" / "report.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    report = json.loads(output_file.read_text(encoding="utf-8"))
    jsonschema.validate(report, schema, format_checker=jsonschema.FormatChecker())

    legacy_report = {
        "source": "auth.log",
        "log_format": "auto",
        "threshold": 3,
        "summary": {"failed_attempts": 1, "unique_ips": 1, "alerts": 0},
        "results": [{"ip_address": "203.0.113.25", "failed_attempts": 1, "alert": False}],
    }
    jsonschema.validate(legacy_report, schema)


def test_csv_export_can_be_written_to_stdout(tmp_path, monkeypatch, capsys):
    output = set_console(monkeypatch)
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Login failed for user admin from 198.51.100.8\n", encoding="utf-8"
    )

    assert cli.main(
        ["--file", str(log_file), "--output-format", "csv", "--quiet"]
    ) == 0
    captured = capsys.readouterr()
    rows = list(csv.DictReader(captured.out.splitlines()))
    assert rows[0]["ip_address"] == "198.51.100.8"
    assert rows[0]["failed_attempts"] == "1"
    assert rows[0]["alert"] == "False"
    assert json.loads(rows[0]["usernames"]) == [
        {"username": "admin", "failed_attempts": 1}
    ]
    assert rows[0]["first_seen"] == ""
    assert output.getvalue() == ""


def test_quiet_suppresses_terminal_report(tmp_path, monkeypatch):
    output = set_console(monkeypatch)
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Login failed for user admin from 198.51.100.8\n", encoding="utf-8"
    )

    assert cli.main(["--file", str(log_file), "--quiet"]) == 0
    assert output.getvalue() == ""


def test_logs_subcommand_remains_supported(tmp_path, monkeypatch):
    output = set_console(monkeypatch)
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Login failed for user admin from 198.51.100.8\n", encoding="utf-8"
    )

    assert cli.main(["logs", "--file", str(log_file), "--threshold", "2"]) == 0
    assert "198.51.100.8" in output.getvalue()
    assert "no" in output.getvalue()


def test_cli_missing_file_returns_nonzero_and_message(tmp_path, monkeypatch):
    output = set_console(monkeypatch)

    assert cli.main(["--file", str(tmp_path / "missing.log")]) == 1
    assert "Cannot read log file" in output.getvalue()


def test_cli_rejects_non_positive_threshold(capsys):
    with pytest.raises(SystemExit) as error:
        cli.main(["--file", "unused.log", "--threshold", "0"])
    assert error.value.code == 2
    assert "--threshold must be at least 1" in capsys.readouterr().err


def test_bundled_sample_is_available_from_any_working_directory(tmp_path, monkeypatch):
    output = set_console(monkeypatch)
    monkeypatch.chdir(tmp_path)

    assert cli.analyze_bundled_sample(threshold=3) == 0
    assert "203.0.113.25" in output.getvalue()


def test_multiple_files_and_stdin_cli_options(tmp_path, monkeypatch):
    set_console(monkeypatch)
    first = tmp_path / "first.log"
    second = tmp_path / "second.log"
    first.write_text(
        "Login failed for user admin from 203.0.113.25\n", encoding="utf-8"
    )
    second.write_text(
        "Login failed for user root from 203.0.113.25\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        cli.sys, "stdin", StringIO("Login failed for user root from 198.51.100.7\n")
    )

    assert cli.main(
        ["--file", str(first), "--file", str(second), "--stdin", "--quiet"]
    ) == 0


def test_since_window_and_csv_include_time_and_user_data(tmp_path, monkeypatch):
    set_console(monkeypatch)
    log_file = tmp_path / "auth.log"
    output_file = tmp_path / "bursts.csv"
    log_file.write_text(
        "2026-10-27T10:00:00Z host sshd: Failed password for alice from "
        "203.0.113.25 port 22\n"
        "2026-10-27T10:04:00Z host sshd: Failed password for alice from "
        "203.0.113.25 port 22\n",
        encoding="utf-8",
    )

    assert cli.main(
        [
            "--file",
            str(log_file),
            "--format",
            "auth",
            "--threshold",
            "2",
            "--since",
            "2026-10-27T09:00:00Z",
            "--window",
            "5m",
            "--output",
            str(output_file),
        ]
    ) == 0
    with output_file.open(encoding="utf-8", newline="") as stream:
        row = next(csv.DictReader(stream))
    assert row["alert"] == "True"
    assert row["spike_alert"] == "True"
    assert row["first_seen"] == "2026-10-27T10:00:00Z"
    assert json.loads(row["usernames"])[0]["username"] == "alice"
