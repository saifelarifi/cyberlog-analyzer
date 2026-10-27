import json
import subprocess
import sys
import tracemalloc

from newbiesaif.analyzer import analyze_log_file


def test_cli_processes_multiple_files_and_stdin(tmp_path):
    first = tmp_path / "auth-a.log"
    second = tmp_path / "auth-b.log"
    first.write_text("Login failed for user alice from 203.0.113.25\n", encoding="utf-8")
    second.write_text("Login failed for user bob from 203.0.113.25\n", encoding="utf-8")
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "newbiesaif.cli",
            "--file",
            str(first),
            "--file",
            str(second),
            "--stdin",
            "--output-format",
            "json",
        ],
        input="Login failed for user carol from 198.51.100.7\n",
        capture_output=True,
        text=True,
        check=False,
    )

    assert process.returncode == 0, process.stderr
    report = json.loads(process.stdout)
    assert report["summary"]["failed_attempts"] == 3
    assert report["sources"][-1] == "stdin"
    assert report["results"][0]["usernames"] == [
        {"username": "alice", "failed_attempts": 1},
        {"username": "bob", "failed_attempts": 1},
    ]


def test_million_line_log_uses_bounded_working_memory(tmp_path):
    log_file = tmp_path / "million.log"
    line = "Login failed for user bot from 203.0.113.25\n"
    chunk = line * 10_000
    with log_file.open("w", encoding="utf-8") as stream:
        for _ in range(100):
            stream.write(chunk)

    tracemalloc.start()
    try:
        result = analyze_log_file(log_file)
        _, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert result.failed_attempts == 1_000_000
    assert result.by_ip["203.0.113.25"].usernames["bot"] == 1_000_000
    assert peak_bytes < 4 * 1024 * 1024


def test_installer_requires_a_tagged_semver_release():
    process = subprocess.run(
        ["bash", "install.sh"], capture_output=True, text=True, check=False
    )
    assert process.returncode == 2
    assert "vMAJOR.MINOR.PATCH" in process.stderr


def test_installer_rejects_unpinned_branch_names():
    process = subprocess.run(
        ["bash", "install.sh", "main"], capture_output=True, text=True, check=False
    )
    assert process.returncode == 2
    assert "semantic version tag" in process.stderr
