
# Linux Security Log Analyzer

A Python and Bash project for analyzing Linux authentication logs and identifying suspicious login activity.

## Features

- Analyze sample logs and supported Linux SSH authentication log formats
- Count successful and failed login attempts
- Group failed attempts by validated IP address
- Flag IP addresses that meet a configurable threshold
- Export reports to JSON
- Handle missing files, permission errors, and invalid arguments
- Run automated unit tests

## Requirements

- Linux or WSL
- Python 3
- Bash (for the original Bash version)

No third-party Python packages are required.

## Usage

Analyze the sample log:

```bash
python3 analyzer.py sample.log
```

Set a custom threshold:

```bash
python3 analyzer.py sample.log --threshold 5
```

Save a JSON report:

```bash
python3 analyzer.py sample.log --json report.json
```

View available options:

```bash
python3 analyzer.py --help
```

## Real Linux Logs

On Ubuntu systems where the authentication log exists, you can analyze it locally:

```bash
sudo python3 analyzer.py /var/log/auth.log
```

The script needs read permission for the log file. Do not publish real authentication logs because they may contain sensitive system information.

## Testing

Run the automated tests from the project root:

```bash
python3 -m unittest discover -s tests -t . -v
```

The tests cover login counts, suspicious IP detection, and invalid IP handling.

## Project Structure

```text
security-log-analyzer/
├── analyzer.py
├── analyzer.sh
├── sample.log
├── tests/
│   └── test_analyzer.py
├── .gitignore
└── README.md
```

## Detection Logic

The analyzer recognizes supported login messages using regular expressions, validates extracted IP addresses, and counts events by IP.

An IP is flagged when its failed login count reaches the configured threshold. This is a detection signal, not proof of malicious activity.

## Limitations

- Log formats vary between Linux distributions and authentication services.
- Only the patterns implemented in the analyzer are recognized.
- The tool does not block IP addresses or respond to incidents.
- A failed login or suspicious IP does not by itself prove an attack.

## Future Improvements

- Support more authentication log formats
- Add time-window-based detection
- Add richer reporting and severity levels
- Improve test coverage with additional log samples
