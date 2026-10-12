# Linux Security Log Analyzer

A simple Bash script that analyzes Linux security logs and detects suspicious IP addresses based on failed login attempts.

## Features

- Count successful login attempts
- Count failed login attempts
- Count failed login attempts by IP address
- Detect suspicious IP addresses
- Configurable failed login threshold
- Validate log file input
- Handle missing files and arguments

## Usage

```bash
chmod +x analyzer.sh
./analyzer.sh sample.log
```

## Example Output

```text
Analyzing: sample.log

Successful login attempts: 1
Failed login attempts: 5

Failed attempts by IP:
      1 192.168.8.20
      3 192.168.8.30
      1 192.168.8.50

Suspicious IPs:
IP: 192.168.8.30 | Failed attempts: 3
```

## How It Works

The script reads a log file and analyzes login activity.

It:

1. Counts successful login attempts.
2. Counts failed login attempts.
3. Extracts IP addresses from failed login attempts.
4. Counts failed attempts for each IP.
5. Flags IP addresses that reach the configured threshold.

## Requirements

- Linux
- Bash
- grep
- awk
- sort
- uniq
- wc

## Project Structure

```text
security-log-analyzer/
├── analyzer.sh
├── sample.log
└── README.md
```

## Configuration

The suspicious IP threshold can be changed inside `analyzer.sh`.

```bash
THRESHOLD=3
```

For example:

```bash
THRESHOLD=5
```

will flag IP addresses with 5 or more failed login attempts.

## Error Handling

The script checks that:

- A log file argument is provided.
- The specified log file exists.

Example:

```text
Usage: ./analyzer.sh <log_file>
```

or:

```text
Error: Log file not found: fake.log
```

## Future Improvements

- Analyze real Linux authentication logs such as `/var/log/auth.log`
- Add timestamps to detected events
- Generate security reports
- Detect multiple types of suspicious activity
- Add more advanced log analysis
