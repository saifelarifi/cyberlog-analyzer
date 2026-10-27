# CyberLog Analyzer

A Python command-line tool for counting failed SSH login attempts by valid source IP. The analyzer is separate from the terminal renderer, streams input files, and exports machine-readable reports.

## Requirements and installation

- Python 3.10 or later

Install from a clone:

```bash
python3 -m pip install .
```

The included `install.sh` creates an isolated environment and installs `newbiesaif` under `~/.local/bin`.

## Supported input formats

- **`auth`**: Linux `/var/log/auth.log` or `/var/log/secure` text containing OpenSSH `Failed password ... from IP` records. The project's sample `Login failed ... from IP` format is also accepted.
- **`journald`**: `journalctl -o short-iso` text (same OpenSSH message format), or one JSON record per line from `journalctl -o json`; the JSON `MESSAGE` field is analyzed.
- **`auto`** (default): recognizes both text records and journal JSON records.

Only valid IPv4 and IPv6 addresses are counted. Other lines and malformed addresses are ignored. No raw log message is displayed or included in exported results.

## Command-line use

Analyze a conventional auth log:

```bash
newbiesaif --file /var/log/auth.log --format auth --threshold 3
```

Analyze JSON output from journald and save a JSON report:

```bash
journalctl -u ssh -o json > ssh-journal.json
newbiesaif --file ssh-journal.json --format journald --output alerts.json
```

Save a CSV report or write it to standard output:

```bash
newbiesaif --file /var/log/auth.log --output alerts.csv
newbiesaif --file /var/log/auth.log --output-format csv
```

`--output` infers JSON or CSV from the `.json` or `.csv` extension. Use `--output-format` to choose a format explicitly. `--quiet` (or `-q`) suppresses the terminal report; exports and error messages remain available. `--help` lists all options and examples.

Run `newbiesaif` with no arguments to open the interactive menu. Press Enter at the path prompt to analyze the sample bundled with the installed package; this works from any current directory.

## Development and checks

```bash
python3 -m pip install ".[dev]"
python3 -m pytest -v
ruff check .
mypy src/newbiesaif
```

GitHub Actions installs the package and runs tests, Ruff, and mypy on Python 3.10 and 3.12.

An alert indicates activity for investigation; it does not prove that an attack occurred.
