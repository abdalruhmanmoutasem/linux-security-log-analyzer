
#!/usr/bin/env python3

import argparse
import ipaddress
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


FAILED_PATTERNS = [
    re.compile(
        r"\bFailed password for (?:invalid user )?\S+ from (?P<ip>\S+)"
    ),
    re.compile(r"\bFailed login from (?P<ip>\S+)"),
    re.compile(
        r"\bauthentication failure;.*?\brhost=(?P<ip>\S+)"
    ),
]

SUCCESS_PATTERNS = [
    re.compile(
        r"\bAccepted (?:password|publickey|keyboard-interactive/pam) "
        r"for (?:invalid user )?\S+ from (?P<ip>\S+)"
    ),
    re.compile(r"\bSuccessful login from (?P<ip>\S+)"),
]

ISO_TIMESTAMP = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"
)

SYSLOG_TIMESTAMP = re.compile(
    r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"
)


def extract_ip(line, patterns):
    for pattern in patterns:
        match = pattern.search(line)
        if not match:
            continue

        candidate = match.group("ip")

        # Try the original value first, then common trailing punctuation.
        for value in (candidate, candidate.rstrip(".,;"), candidate.rstrip(".,;:")):
            try:
                return str(ipaddress.ip_address(value))
            except ValueError:
                pass

    return None


def parse_timestamp(line):
    match = ISO_TIMESTAMP.search(line)

    if match:
        value = match.group(0).replace("Z", "+00:00")

        try:
            timestamp = datetime.fromisoformat(value)
            if timestamp.tzinfo is not None:
                timestamp = timestamp.astimezone(timezone.utc).replace(
                    tzinfo=None
                )
            return timestamp
        except ValueError:
            return None

    match = SYSLOG_TIMESTAMP.search(line)

    if match:
        value = f"{datetime.now().year} {match.group(0)}"

        try:
            return datetime.strptime(value, "%Y %b %d %H:%M:%S")
        except ValueError:
            return None

    return None


def find_max_window(events, window):
    """Find the largest number of events inside any time window."""
    events = sorted(events)

    left = 0
    best = 0
    best_start = None
    best_end = None

    for right in range(len(events)):
        while events[right] - events[left] > window:
            left += 1

        count = right - left + 1

        if count > best:
            best = count
            best_start = events[left]
            best_end = events[right]

    return best, best_start, best_end


def analyze_log(log_path, threshold=3, window_minutes=5):
    failed_by_ip = Counter()
    successful_by_ip = Counter()
    failed_events = defaultdict(list)
    successful_events = defaultdict(list)

    results = {
        "file": str(log_path),
        "successful_logins": 0,
        "failed_logins": 0,
        "failed_by_ip": failed_by_ip,
        "successful_by_ip": successful_by_ip,
        "unmatched_failed_lines": 0,
        "threshold": threshold,
        "window_minutes": window_minutes,
        "brute_force_ips": {},
        "success_after_failures": {},
    }

    with log_path.open(
        "r", encoding="utf-8", errors="replace"
    ) as log_file:
        for line in log_file:
            timestamp = parse_timestamp(line)

            failed = any(p.search(line) for p in FAILED_PATTERNS)
            successful = any(p.search(line) for p in SUCCESS_PATTERNS)

            if failed:
                results["failed_logins"] += 1
                ip = extract_ip(line, FAILED_PATTERNS)

                if ip is None:
                    results["unmatched_failed_lines"] += 1
                    continue

                failed_by_ip[ip] += 1

                if timestamp is not None:
                    failed_events[ip].append(timestamp)

            elif successful:
                results["successful_logins"] += 1
                ip = extract_ip(line, SUCCESS_PATTERNS)

                if ip is not None:
                    successful_by_ip[ip] += 1

                    if timestamp is not None:
                        successful_events[ip].append(timestamp)

    window = timedelta(minutes=window_minutes)

    # Detect repeated failed attempts within the selected time window.
    for ip, timestamps in failed_events.items():
        count, start, end = find_max_window(timestamps, window)

        if count >= threshold:
            results["brute_force_ips"][ip] = {
                "attempts_in_window": count,
                "window_start": start.isoformat(sep=" "),
                "window_end": end.isoformat(sep=" "),
            }

    # Detect a successful login after repeated failures from the same IP.
    for ip, success_times in successful_events.items():
        failures = sorted(failed_events.get(ip, []))
        best = None

        for success_time in sorted(success_times):
            recent_failures = [
                t for t in failures
                if success_time - window <= t <= success_time
            ]

            if len(recent_failures) >= threshold:
                candidate = {
                    "failed_attempts_before_success": len(recent_failures),
                    "window_start": recent_failures[0].isoformat(sep=" "),
                    "successful_login_time": success_time.isoformat(sep=" "),
                }

                if (
                    best is None
                    or candidate["failed_attempts_before_success"]
                    > best["failed_attempts_before_success"]
                ):
                    best = candidate

        if best is not None:
            results["success_after_failures"][ip] = best

    results["suspicious_ips"] = {
        ip: count
        for ip, count in failed_by_ip.items()
        if count >= threshold
    }

    return results


def print_report(results):
    print(f"Analyzing: {results['file']}")
    print()
    print(f"Successful login attempts: {results['successful_logins']}")
    print(f"Failed login attempts: {results['failed_logins']}")

    print("\nFailed attempts by IP:")
    if results["failed_by_ip"]:
        for ip, count in sorted(
            results["failed_by_ip"].items(),
            key=lambda item: (-item[1], item[0]),
        ):
            print(f"  {ip}: {count}")
    else:
        print("  No valid IP addresses extracted.")

    print(f"\nRepeated failures (threshold: {results['threshold']}):")
    if results["suspicious_ips"]:
        for ip, count in sorted(results["suspicious_ips"].items()):
            print(f"  {ip}: {count} failed attempts")
    else:
        print("  None detected.")

    print(
        f"\nBrute-force patterns "
        f"(at least {results['threshold']} failures in "
        f"{results['window_minutes']} minutes):"
    )
    if results["brute_force_ips"]:
        for ip, details in sorted(results["brute_force_ips"].items()):
            print(
                f"  {ip}: {details['attempts_in_window']} attempts "
                f"({details['window_start']} to {details['window_end']})"
            )
    else:
        print("  None detected in timestamped events.")

    print("\nSuccessful login after repeated failures:")
    if results["success_after_failures"]:
        for ip, details in sorted(
            results["success_after_failures"].items()
        ):
            print(
                f"  {ip}: {details['failed_attempts_before_success']} "
                f"failures before a successful login"
            )
    else:
        print("  None detected.")

    if results["unmatched_failed_lines"]:
        print(
            "\nWarning: "
            f"{results['unmatched_failed_lines']} failed lines "
            "did not contain a recognized valid IP."
        )


def json_safe_report(results):
    report = dict(results)
    report["failed_by_ip"] = dict(results["failed_by_ip"])
    report["successful_by_ip"] = dict(results["successful_by_ip"])
    return report


def main():
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for suspicious activity."
    )
    parser.add_argument("log_file", type=Path, help="Path to the log file")
    parser.add_argument(
        "-t", "--threshold", type=int, default=3,
        help="Number of failures needed for detection (default: 3)",
    )
    parser.add_argument(
        "-w", "--window-minutes", type=int, default=5,
        help="Time window for repeated-failure detection (default: 5)",
    )
    parser.add_argument(
        "--json", dest="json_file", type=Path,
        help="Optional path for a JSON report",
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("threshold must be at least 1")

    if args.window_minutes < 1:
        parser.error("window-minutes must be at least 1")

    if not args.log_file.is_file():
        print(f"Error: Log file not found: {args.log_file}", file=sys.stderr)
        return 1

    try:
        results = analyze_log(
            args.log_file,
            threshold=args.threshold,
            window_minutes=args.window_minutes,
        )
    except PermissionError:
        print(
            f"Error: Permission denied reading {args.log_file}",
            file=sys.stderr,
        )
        return 1
    except OSError as error:
        print(f"Error reading log file: {error}", file=sys.stderr)
        return 1

    print_report(results)

    if args.json_file:
        try:
            args.json_file.write_text(
                json.dumps(json_safe_report(results), indent=2),
                encoding="utf-8",
            )
            print(f"\nJSON report saved to: {args.json_file}")
        except OSError as error:
            print(f"Error saving JSON report: {error}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

