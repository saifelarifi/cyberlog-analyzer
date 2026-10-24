import main


def test_detects_failed_login_attempts(tmp_path, monkeypatch, capsys):
    log_file = tmp_path / "sample.log"
    log_file.write_text(
        "FAILED Login failed for user admin from 203.0.113.25\n"
        "FAILED Login failed for user admin from 203.0.113.25\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(main, "LOG_FILE", log_file)
    main.analyze_logs()
    output = capsys.readouterr().out

    assert "203.0.113.25" in output
    assert "Failed Attempts: 2" in output
    assert "Below alert threshold" in output


def test_alerts_at_threshold(tmp_path, monkeypatch, capsys):
    log_file = tmp_path / "sample.log"
    log_file.write_text(
        "FAILED Login failed for user admin from 203.0.113.25\n"
        "FAILED Login failed for user admin from 203.0.113.25\n"
        "FAILED Login failed for user admin from 203.0.113.25\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(main, "LOG_FILE", log_file)
    main.analyze_logs()
    output = capsys.readouterr().out

    assert "Failed Attempts: 3" in output
    assert "ALERT: Repeated failed logins detected!" in output


def test_ignores_successful_logins(tmp_path, monkeypatch, capsys):
    log_file = tmp_path / "sample.log"
    log_file.write_text(
        "2026-10-24 09:00:00 INFO Login successful for user admin from 192.168.1.10\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(main, "LOG_FILE", log_file)
    main.analyze_logs()
    output = capsys.readouterr().out

    assert "No failed login attempts found." in output


def test_handles_missing_log_file(tmp_path, monkeypatch, capsys):
    missing_file = tmp_path / "missing.log"
    monkeypatch.setattr(main, "LOG_FILE", missing_file)

    main.analyze_logs()
    output = capsys.readouterr().out

    assert "Error: Log file not found:" in output
