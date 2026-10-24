import argparse
import ipaddress
from collections import Counter
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt
from rich.text import Text

console = Console()

BANNER = r"""
 _   _                 _     _ _____      _
| \ | | _____      __ | |__ (_)___  / __ _(_)
|  \| |/ _ \ \ /\ / / | '_ \| |  / / / _` | |
| |\  |  __/\ V  V /  | |_) | | / /_| (_| | |
|_| \_|\___| \_/\_/   |_.__/|_|/_____|\__,_|_|
"""


def show_banner():
    console.print()
    console.print(
        Panel(
            Text("NewbieSaif", style="bold green"),
            title="[bold white]NewbieSaif[/bold white]",
            subtitle="[orange1]Linux Security Toolkit[/orange1]",
            border_style="green",
            box=box.DOUBLE,
            expand=False,
        )
    )
    console.print("[bold green]  Version:[/bold green] 0.1.0")
    console.print("[bold green]  Author:[/bold green] Saif")
    console.print("[bold green]  Platform:[/bold green] Linux")
    console.print()


def analyze_logs(log_file: Path, threshold: int) -> int:
    if not log_file.is_file():
        console.print(f"[bold red]Error:[/bold red] Log file not found: {log_file}")
        return 1

    failed_attempts = Counter()

    try:
        with log_file.open("r", encoding="utf-8") as file:
            for line in file:
                if "Login failed" not in line:
                    continue

                parts = line.strip().rsplit("from ", 1)
                if len(parts) != 2:
                    continue

                try:
                    ip_address = str(ipaddress.ip_address(parts[1].strip()))
                except ValueError:
                    continue

                failed_attempts[ip_address] += 1

    except (OSError, UnicodeError) as error:
        console.print(f"[bold red]Error reading log file:[/bold red] {error}")
        return 1

    console.print(
        Panel(
            f"[bold]Analyzing:[/bold] {log_file}\n"
            f"[bold]Alert threshold:[/bold] {threshold}",
            title="[green]Security Log Analysis[/green]",
            border_style="green",
        )
    )

    if not failed_attempts:
        console.print("[yellow]No valid failed login attempts found.[/yellow]")
        return 0

    for ip_address, count in sorted(failed_attempts.items()):
        status = (
            "[bold red]ALERT: Repeated failed logins detected![/bold red]"
            if count >= threshold
            else "[green]Status: Below alert threshold[/green]"
        )

        console.print(
            Panel(
                f"[bold]IP Address:[/bold] {ip_address}\n"
                f"[bold]Failed Attempts:[/bold] {count}\n{status}",
                border_style="red" if count >= threshold else "green",
            )
        )

    return 0


def interactive_menu() -> int:
    show_banner()

    while True:
        console.print("[bold green]  [1][/bold green] Analyze security logs")
        console.print("[bold green]  [2][/bold green] Tool information")
        console.print("[bold green]  [3][/bold green] Help & usage")
        console.print("[bold red]  [0][/bold red] Exit")
        console.print()

        choice = Prompt.ask(
            "[bold white]newbiesaif[/bold white]",
            choices=["0", "1", "2", "3"],
            default="1",
        )

        if choice == "0":
            console.print("[green]Stay safe. Goodbye![/green]")
            return 0

        if choice == "1":
            file_name = Prompt.ask("Path to log file", default="sample.log")
            threshold = IntPrompt.ask("Alert threshold", default=3)

            if threshold < 1:
                console.print("[red]Threshold must be at least 1.[/red]")
                continue

            analyze_logs(Path(file_name), threshold)

        elif choice == "2":
            console.print(
                Panel(
                    "NewbieSaif 0.1.0\n"
                    "A lightweight Linux security log analyzer.\n"
                    "Educational tool for analyzing supported sample logs.",
                    title="About",
                    border_style="green",
                )
            )

        elif choice == "3":
            console.print(
                "Usage:\n"
                "  newbiesaif\n"
                "  newbiesaif --help\n"
                "  newbiesaif --version\n"
                "  newbiesaif logs --file sample.log --threshold 3"
            )

        Prompt.ask("\nPress Enter to return to the menu", default="")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="newbiesaif",
        description="Analyze Linux security logs for repeated failed logins.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="NewbieSaif 0.1.0",
    )

    subparsers = parser.add_subparsers(dest="command")
    logs_parser = subparsers.add_parser("logs", help="Analyze a security log file")
    logs_parser.add_argument("--file", type=Path, required=True)
    logs_parser.add_argument("--threshold", type=int, default=3)

    args = parser.parse_args()

    if args.command is None:
        return interactive_menu()

    if args.command == "logs":
        if args.threshold < 1:
            parser.error("--threshold must be at least 1")
        show_banner()
        return analyze_logs(args.file, args.threshold)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
