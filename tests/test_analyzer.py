
import tempfile
import unittest
from pathlib import Path

from analyzer import analyze_log


class AnalyzerTests(unittest.TestCase):
    def analyze_text(self, text, threshold=3, window_minutes=5):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)

        log_path = Path(temp_dir.name) / "sample.log"
        log_path.write_text(text, encoding="utf-8")

        return analyze_log(log_path, threshold, window_minutes)

    def test_counts_and_suspicious_ip(self):
        text = """\
Failed login from 192.168.8.20
Failed login from 192.168.8.30
Successful login from 192.168.8.10
Failed login from 192.168.8.30
Failed login from 192.168.8.50
Failed login from 192.168.8.30
"""
        result = self.analyze_text(text)

        self.assertEqual(result["successful_logins"], 1)
        self.assertEqual(result["failed_logins"], 5)
        self.assertEqual(result["suspicious_ips"], {"192.168.8.30": 3})

    def test_brute_force_inside_time_window(self):
        text = """\
2026-10-12T19:00:00 Failed password for user from 192.168.8.30 port 22 ssh2
2026-10-12T19:01:00 Failed password for user from 192.168.8.30 port 22 ssh2
2026-10-12T19:04:00 Failed password for user from 192.168.8.30 port 22 ssh2
"""
        result = self.analyze_text(text)

        self.assertIn("192.168.8.30", result["brute_force_ips"])
        self.assertEqual(
            result["brute_force_ips"]["192.168.8.30"]["attempts_in_window"],
            3,
        )

    def test_failures_outside_time_window(self):
        text = """\
2026-10-12T19:00:00 Failed password for user from 192.168.8.30 port 22 ssh2
2026-10-12T19:10:00 Failed password for user from 192.168.8.30 port 22 ssh2
2026-10-12T19:20:00 Failed password for user from 192.168.8.30 port 22 ssh2
"""
        result = self.analyze_text(text)

        self.assertNotIn("192.168.8.30", result["brute_force_ips"])

    def test_success_after_repeated_failures(self):
        text = """\
2026-10-12T19:00:00 Failed password for user from 192.168.8.30 port 22 ssh2
2026-10-12T19:01:00 Failed password for user from 192.168.8.30 port 22 ssh2
2026-10-12T19:02:00 Failed password for user from 192.168.8.30 port 22 ssh2
2026-10-12T19:03:00 Accepted password for user from 192.168.8.30 port 22 ssh2
"""
        result = self.analyze_text(text)

        self.assertIn("192.168.8.30", result["success_after_failures"])

    def test_invalid_ip_is_not_counted(self):
        result = self.analyze_text("Failed login from not-an-ip\n", threshold=1)

        self.assertEqual(result["failed_logins"], 1)
        self.assertEqual(result["failed_by_ip"], {})
        self.assertEqual(result["unmatched_failed_lines"], 1)

    def test_below_threshold_is_not_flagged(self):
        result = self.analyze_text(
            "Failed login from 192.168.8.20\n",
            threshold=3,
        )

        self.assertEqual(result["suspicious_ips"], {})


if __name__ == "__main__":
    unittest.main()
