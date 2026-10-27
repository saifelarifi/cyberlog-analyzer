# CyberLog Analyzer

A Python command-line tool for analyzing failed SSH login attempts by valid source IP and targeted username. It streams text input, supports time filters and burst alerts, and exports terminal, JSON, or CSV reports.

## Requirements and installation

- Python 3.10 or later

Install from a source checkout:

```bash
python3 -m pip install .
```

For a tagged release, use the installer with an exact semantic version:

```bash
./install.sh v0.2.0
```

The installer checks out that tag under `~/.local/share/newbiesaif`; it does not track a moving branch. See [the release process](docs/releasing.md).

## Supported input

- **`auth`**: Linux `/var/log/auth.log` or `/var/log/secure` text with OpenSSH `Failed password ... from IP` entries. The bundled sample's `Login failed ... from IP` lines are also supported.
- **`journald`**: `journalctl -o short-iso` text or JSON lines from `journalctl -o json`. JSON `MESSAGE` and `__REALTIME_TIMESTAMP` fields are used.
- **`auto`**: recognizes the supported text records and journal JSON automatically.

This does not read binary journal files. Use `journalctl -o json` to export them. Successful logins and other authentication mechanisms are not analyzed yet. Invalid IPs, malformed candidate lines, and lines longer than 64 KiB are skipped and reported in the summary. Raw log messages are never included in output.

## Analyze logs

Analyze one or more files; repeat `--file` for additional inputs:

```bash
newbiesaif --file /var/log/auth.log --format auth --threshold 3
newbiesaif --file auth.log --file secure.log --threshold 5
```

Read directly from stdin, including a live `journalctl` pipe:

```bash
journalctl -u ssh -o json | newbiesaif --stdin --format journald
```

Filter events by inclusive ISO 8601 timestamps. Timestamps without an explicit offset are treated as UTC. Traditional syslog timestamps omit a year; they use the current UTC year unless `--year` is supplied.

```bash
newbiesaif --file /var/log/auth.log \
  --since 2026-10-27T00:00:00Z --until 2026-10-27T23:59:59Z --year 2026
```

Use `--window` with `--threshold` to alert when that many failures from one IP fall inside any rolling duration:

```bash
newbiesaif --file auth.log --threshold 5 --window 10m
```

Supported durations are seconds, minutes, hours, and days (for example `30s`, `5m`, `1h`, `1d`). Without `--window`, alerts retain the total-count behavior.

## Export reports

The JSON report is described by [docs/report.schema.json](docs/report.schema.json). It retains the original `source`, `log_format`, `threshold`, `summary.failed_attempts`, `summary.unique_ips`, `summary.alerts`, and per-IP `ip_address`, `failed_attempts`, and `alert` fields. Version 1.1 adds timestamps, targeted usernames, per-source lists, filtering counters, and burst-alert metadata. New fields are additive; the schema accepts legacy reports that contain the original fields only.

```bash
newbiesaif --file auth.log --output alerts.json
newbiesaif --file auth.log --output alerts.csv
newbiesaif --file auth.log --output-format json
newbiesaif --file auth.log --output-format csv
```

`--output` infers JSON or CSV from `.json` or `.csv`; `--output-format` selects a format explicitly and writes to stdout when no path is given. CSV keeps the original first three columns and appends usernames, first/last timestamps, and burst-alert state. `--quiet` or `-q` suppresses terminal results while keeping exports and errors visible. Run `newbiesaif --help` for all options.

Running `newbiesaif` with no arguments opens the interactive menu. Press Enter at the file prompt to analyze the package's bundled sample from any working directory.

## Development and checks

```bash
python3 -m pip install ".[dev]"
python3 -m pytest -v
ruff check .
mypy src/newbiesaif
```

GitHub Actions runs tests, linting, and type checks on Python 3.10 and 3.12. The test suite also exercises large-file streaming and the report schema.

The analyzer reports suspicious patterns for investigation; an alert does not prove that an attack occurred.
