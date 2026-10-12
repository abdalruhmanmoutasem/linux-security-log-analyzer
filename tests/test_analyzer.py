
import tempfile
import unittest
from pathlib import Path

from analyzer import analyze_log


class AnalyzerTests(unittest.TestCase):
    def test_counts_and_suspicious_ip(self):
        sample = """\
Failed login from 192.168.8.20
Failed login from 192.168.8.30
Successful login from 192.168.8.10
Failed login from 192.168.8.30
Failed login from 192.168.8.50
Failed login from 192.168.8.30
"""

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "sample.log"
            log_path.write_text(sample, encoding="utf-8")

            results = analyze_log(log_path, threshold=3)

        self.assertEqual(results["successful_logins"], 1)
        self.assertEqual(results["failed_logins"], 5)
        self.assertEqual(results["failed_by_ip"]["192.168.8.30"], 3)
        self.assertEqual(results["suspicious_ips"], {"192.168.8.30": 3})

    def test_no_suspicious_ip_below_threshold(self):
        sample = "Failed login from 192.168.8.20\n"

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "sample.log"
            log_path.write_text(sample, encoding="utf-8")

            results = analyze_log(log_path, threshold=3)

        self.assertEqual(results["suspicious_ips"], {})

    def test_invalid_ip_is_not_counted(self):
        sample = "Failed login from not-an-ip\n"

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "sample.log"
            log_path.write_text(sample, encoding="utf-8")

            results = analyze_log(log_path, threshold=1)

        self.assertEqual(results["failed_logins"], 1)
        self.assertEqual(results["failed_by_ip"], {})
        self.assertEqual(results["unmatched_failed_lines"], 1)


if __name__ == "__main__":
    unittest.main()
