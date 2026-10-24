from collections import Counter
from pathlib import Path

LOG_FILE = Path(__file__).parent / "sample.log"
ALERT_THRESHOLD = 3


def analyze_logs():
    failed_attempts = Counter()

    if not LOG_FILE.exists():
        print(f"Error: Log file not found: {LOG_FILE}")
        return

    with LOG_FILE.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            if "Login failed" not in line:
                continue

            parts = line.strip().split("from ", 1)
            if len(parts) != 2:
                continue

            ip_address = parts[1].strip()
            failed_attempts[ip_address] += 1

    print("\n" + "=" * 45)
    print("         CYBERLOG ANALYZER")
    print("=" * 45)
    print("Security Log Analysis Report\n")

    if not failed_attempts:
        print("No failed login attempts found.")
        return

    for ip_address, count in sorted(failed_attempts.items()):
        print(f"IP Address:      {ip_address}")
        print(f"Failed Attempts: {count}")

        if count >= ALERT_THRESHOLD:
            print("ALERT: Repeated failed logins detected!")
        else:
            print("Status: Below alert threshold")

        print("-" * 45)

    print("\nAnalysis complete.")


if __name__ == "__main__":
    analyze_logs()
