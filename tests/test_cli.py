from io import StringIO
import csv
import json

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
    assert "Failed Attempts: 3" in output.getvalue()
    assert "ALERT: Repeated failed logins detected!" in output.getvalue()


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
    assert report["summary"] == {
        "failed_attempts": 2,
        "unique_ips": 1,
        "alerts": 1,
    }
    assert report["results"][0]["alert"] is True
    assert output.getvalue() == ""


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
    assert rows == [
        {"ip_address": "198.51.100.8", "failed_attempts": "1", "alert": "False"}
    ]
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
    assert "Below alert threshold" in output.getvalue()


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
