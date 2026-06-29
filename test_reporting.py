import tempfile
import unittest
from pathlib import Path

from reporting import Reporter


class ReportingTests(unittest.TestCase):
    def test_human_log_never_contains_terminal_color_codes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "human.log"
            reporter = Reporter(path, quiet=True, color="always")
            reporter.anomaly(
                kind="ssl-flow",
                host="10.0.0.1",
                timestamp=1,
                score=0.9,
                confidence="high",
                reasons=[{"feature": "new_server", "value": "example.test"}],
            )
            reporter.close()
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\033[", text)
            self.assertIn("ALERT", text)
            self.assertIn("new_server", text)


if __name__ == "__main__":
    unittest.main()
