import tempfile
import unittest
from pathlib import Path

from configuration import load_settings


class ConfigurationTests(unittest.TestCase):
    def test_section_values_override_defaults(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "detector.conf"
            path.write_text(
                "[common]\ntraining_hours = 8\nsensitivity = 1.5\nignore_multicast_broadcast = false\n"
                "[output]\ncolor = never\n"
                "[multi_protocol]\nssl_flow_threshold = 4.2\n",
                encoding="utf-8",
            )
            values = load_settings(
                path,
                "multi_protocol",
                {
                    "training_hours": 3,
                    "sensitivity": 1.0,
                    "ignore_multicast_broadcast": True,
                    "color": "auto",
                    "ssl_flow_threshold": 3.5,
                },
                )
            self.assertEqual(values["training_hours"], 8)
            self.assertEqual(values["sensitivity"], 1.5)
            self.assertFalse(values["ignore_multicast_broadcast"])
            self.assertEqual(values["ssl_flow_threshold"], 4.2)
            self.assertEqual(values["color"], "never")

    def test_unknown_setting_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "detector.conf"
            path.write_text(
                "[multi_protocol]\nunknown = 1\n", encoding="utf-8"
            )
            with self.assertRaises(ValueError):
                load_settings(
                    path,
                    "multi_protocol",
                    {"ssl_flow_threshold": 3.5},
                )


if __name__ == "__main__":
    unittest.main()
