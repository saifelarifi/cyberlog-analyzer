# NewbieSaif CyberLog Analyzer

[![CI](https://github.com/saifelarifi/cyberlog-analyzer/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/saifelarifi/cyberlog-analyzer/actions/workflows/tests.yml)

**A small, practical command-line tool for reviewing failed SSH login attempts in Linux authentication logs.** NewbieSaif groups events by source IP and targeted username, highlights repeated attempts, and exports reports for further analysis.

> This tool helps you investigate log data. It does not block connections or determine on its own whether an event is malicious.

## Features

- Analyze Linux `auth.log` and `/var/log/secure` entries for supported OpenSSH failed-password messages.
- Read supported `journalctl` text or JSON output from files or standard input.
- Analyze multiple files in one run and combine their results.
- Validate and normalize IPv4 and IPv6 addresses before counting them.
- Summarize failed attempts by IP address and username.
- Filter events by time with `--since` and `--until`, and identify bursts with a rolling `--window`.
- Display readable terminal reports with [Rich](https://github.com/Textualize/rich), or export JSON and CSV.
- Include a bundled sample log for a quick first run.

## Supported logs and limitations

The analyzer recognizes these formats:

| Format | Input |
| --- | --- |
| `auth` | Supported Linux authentication log lines, including OpenSSH `Failed password ... from IP` records and the bundled sample format |
| `journald` | `journalctl -o short-iso` text or JSON lines from `journalctl -o json` |
| `auto` | Automatically recognizes supported text records and journald JSON |

The tool reads text logs; it does not read binary journal files. Export journal entries with `journalctl -o json` first. It currently focuses on failed SSH login events; successful logins and other authentication events are outside its scope. Malformed candidate records, invalid IP addresses, and lines longer than 64 KiB are skipped and counted. Raw log messages are not included in reports.

## Requirements

- Python 3.10 or newer
- Git, if installing from a repository checkout or using the release installer

## Installation

### Install from a checkout with pip

```bash
git clone https://github.com/saifelarifi/cyberlog-analyzer.git
cd cyberlog-analyzer
python3 -m pip install .
```

### Install from a checkout with uv

```bash
git clone https://github.com/saifelarifi/cyberlog-analyzer.git
cd cyberlog-analyzer
uv tool install .
```

### Install a published tagged release

Once a release tag is published, the installer can install that exact version. Replace the example tag with a version that exists in the repository:

```bash
./install.sh v0.2.0
```

The installer keeps the tool under `~/.local/share/newbiesaif` and creates a launcher in `~/.local/bin`. If that directory is not on your `PATH`, the installer prints the line to add to your shell configuration. See [the release guide](docs/releasing.md) for the maintainer workflow.

## Quick start

Run the interactive menu:

```bash
newbiesaif
```

Choose the bundled sample when prompted. To run it directly, pass a log file:

```bash
newbiesaif --file /var/log/auth.log --format auth
```

The default alert threshold is three failed attempts from one IP. Set it explicitly with `--threshold`:

```bash
newbiesaif --file /var/log/auth.log --threshold 5
```

## Usage

### Analyze one or more files

Repeat `--file` to combine logs in one report:

```bash
newbiesaif --file /var/log/auth.log --file /var/log/secure --format auth
```

### Read from standard input

For example, pass JSON output from `journalctl` directly to the analyzer:

```bash
journalctl -u ssh -o json | newbiesaif --stdin --format journald
```

You can also use `--file -` as an alias for standard input:

```bash
cat auth.log | newbiesaif --file - --format auth
```

### Filter by time and detect bursts

Use ISO 8601 timestamps for inclusive time boundaries. A timestamp without an explicit timezone is interpreted as UTC. Traditional syslog timestamps omit the year; the analyzer uses the current UTC year unless `--year` is supplied.

```bash
newbiesaif --file /var/log/auth.log \
  --since 2026-10-27T00:00:00Z \
  --until 2026-10-27T23:59:59Z \
  --year 2026
```

Combine `--window` with `--threshold` to flag a burst from one IP within a rolling duration:

```bash
newbiesaif --file /var/log/auth.log --threshold 5 --window 10m
```

Durations use seconds, minutes, hours, or days, such as `30s`, `5m`, `1h`, or `1d`. Without `--window`, an alert is based on the total number of matching events in the selected input.

### Export JSON or CSV

Infer the output format from the file extension:

```bash
newbiesaif --file auth.log --output report.json
newbiesaif --file auth.log --output report.csv
```

Or select a format explicitly and write the report to standard output:

```bash
newbiesaif --file auth.log --output-format json
newbiesaif --file auth.log --output-format csv
```

JSON reports follow [`docs/report.schema.json`](docs/report.schema.json). The report preserves the original summary and per-IP fields and adds timestamp, username, source, filtering, and burst-alert details. The schema accepts older reports containing only the original fields. CSV retains the original first three columns and appends username and time details.

Use `--quiet` or `-q` to suppress the terminal report while still producing a requested export. Use `--help` to see all command options:

```bash
newbiesaif --help
```

## Development

Install the package and development tools in your active Python environment:

```bash
python3 -m pip install -e ".[dev]"
```

Run tests and quality checks:

```bash
python3 -m pytest -v
ruff check .
mypy src/newbiesaif
```

GitHub Actions is configured to run tests, Ruff, and mypy on Python 3.10 and 3.12. The test suite includes CLI, parsing, report-schema, malformed-input, and large-file coverage.

## Contributing

Contributions are welcome. Open an issue to discuss a bug or feature, then submit a pull request with a focused change, tests for changed behavior, and updated documentation when needed. Please run the development checks above before opening a pull request.

## License

NewbieSaif is distributed under the [MIT License](LICENSE).
