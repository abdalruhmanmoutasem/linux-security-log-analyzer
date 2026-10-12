# Linux Security Log Analyzer

A Python and Bash tool for analyzing Linux authentication logs and identifying suspicious login activity.

## Features

- Count successful and failed login attempts.
- Group login attempts by source IP address.
- Validate extracted IP addresses.
- Flag IP addresses that exceed a configurable failed-login threshold.
- Detect repeated failed logins within a configurable time window.
- Identify successful logins following repeated failures from the same IP.
- Export analysis reports as JSON.
- Handle missing files and permission errors.
- Run automated unit tests.

## Requirements

- Linux or WSL Ubuntu
- Python 3
- Bash (for the Bash version)

## Usage

Analyze the sample log:

```bash
python3 analyzer.py sample.log
```

Set a threshold of five failures:

```bash
python3 analyzer.py sample.log --threshold 5
```

Detect repeated failures within ten minutes:

```bash
python3 analyzer.py /tmp/timed_sample.log --threshold 3 --window-minutes 10
```

Export the results to JSON:

```bash
python3 analyzer.py sample.log --json report.json
```

View all available options:

```bash
python3 analyzer.py --help
```

## Automated Tests

Run the test suite:

```bash
python3 -m unittest discover -s tests -t . -v
```

The tests cover login counts, suspicious IP detection, time-window detection, successful logins after repeated failures, and invalid IP addresses.

## Project Structure

- `analyzer.py` — Python log analysis and detection logic
- `analyzer.sh` — Bash-based log analysis
- `sample.log` — Synthetic sample authentication events
- `tests/test_analyzer.py` — Automated tests
- `README.md` — Project documentation

## Detection Logic

The tool supports selected SSH authentication messages and synthetic sample messages. Time-window detection requires parseable timestamps.

A suspicious IP is an indicator for further investigation, not proof of a successful attack or system compromise.

## Limitations

- Detection depends on the log formats and timestamp formats supported by the current implementation.
- Events without parseable timestamps cannot be used for time-window detection.
- The tool does not block IP addresses or perform automatic incident response.
- It is a learning project, not a replacement for a production SIEM.

## Security Note

Use synthetic logs for public demonstrations. Authentication logs from real systems may contain sensitive information and should not be published without appropriate review and sanitization.
