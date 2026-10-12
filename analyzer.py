
#!/usr/bin/env python3

import argparse
import ipaddress
import json
import re
import sys
from collections import Counter
from pathlib import Path


FAILED_PATTERNS = [
    re.compile(r"\bFailed password for (?:invalid user )?\S+ from (?P<ip>\S+)"),
    re.compile(r"\bFailed login from (?P<ip>\S+)"),
    re.compile(r"\bauthentication failure;.*?\brhost=(?P<ip>\S+)"),
]

SUCCESS_PATTERNS = [
    re.compile(r"\bAccepted (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?\S+ from (?P<ip>\S+)"),
    re.compile(r"\bSuccessful login from (?P<ip>\S+)"),
]


def extract_ip(line, patterns):
    """Return a valid IP address found by one of the supplied patterns."""
    for pattern in patterns:
        match = pattern.search(line)
        if match:
            candidate = match.group("ip").rstrip(".,;:")
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                continue
    return None


def analyze_log(log_path, threshold):
    results = {
        "file": str(log_path),
        "successful_logins": 0,
        "failed_logins": 0,
        "failed_by_ip": Counter(),
        "successful_by_ip": Counter(),
        "unmatched_failed_lines": 0,
    }

    with log_path.open("r", encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            failed = any(pattern.search(line) for pattern in FAILED_PATTERNS)
            successful = any(pattern.search(line) for pattern in SUCCESS_PATTERNS)

            if failed:
                results["failed_logins"] += 1
                ip = extract_ip(line, FAILED_PATTERNS)
                if ip:
                    results["failed_by_ip"][ip] += 1
                else:
                    results["unmatched_failed_lines"] += 1

            elif successful:
                results["successful_logins"] += 1
                ip = extract_ip(line, SUCCESS_PATTERNS)
                if ip:
                    results["successful_by_ip"][ip] += 1

    results["threshold"] = threshold
    results["suspicious_ips"] = {
        ip: count
        for ip, count in results["failed_by_ip"].items()
        if count >= threshold
    }

    return results


def print_report(results):
    print(f"Analyzing: {results['file']}")
    print()
    print(f"Successful login attempts: {results['successful_logins']}")
    print(f"Failed login attempts: {results['failed_logins']}")
    print()

    print("Failed attempts by IP:")
    if results["failed_by_ip"]:
        for ip, count in sorted(
            results["failed_by_ip"].items(),
            key=lambda item: (-item[1], item[0]),
        ):
            print(f"  {ip}: {count}")
    else:
        print("  No IP addresses extracted.")

    print()
    print(f"Suspicious IPs (threshold: {results['threshold']}):")
    if results["suspicious_ips"]:
        for ip, count in sorted(results["suspicious_ips"].items()):
            print(f"  {ip}: {count} failed attempts")
    else:
        print("  None detected.")

    if results["unmatched_failed_lines"]:
        print()
        print(
            "Warning: "
            f"{results['unmatched_failed_lines']} failed lines "
            "did not contain a recognized IP address."
        )


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Linux authentication logs for suspicious login activity."
    )
    parser.add_argument("log_file", type=Path, help="Path to the log file")
    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=3,
        help="Failed attempts needed to flag an IP (default: 3)",
    )
    parser.add_argument(
        "--json",
        dest="json_file",
        type=Path,
        help="Optional path to save the report as JSON",
    )
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("threshold must be at least 1")

    if not args.log_file.is_file():
        print(f"Error: Log file not found: {args.log_file}", file=sys.stderr)
        return 1

    try:
        results = analyze_log(args.log_file, args.threshold)
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
            report = {
                **results,
                "failed_by_ip": dict(results["failed_by_ip"]),
                "successful_by_ip": dict(results["successful_by_ip"]),
                "suspicious_ips": results["suspicious_ips"],
            }
            args.json_file.write_text(
                json.dumps(report, indent=2),
                encoding="utf-8",
            )
            print(f"\nJSON report saved to: {args.json_file}")
        except OSError as error:
            print(f"Error saving JSON report: {error}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
