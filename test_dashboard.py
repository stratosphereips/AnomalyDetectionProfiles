import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import dashboard


def write_zeek_log(path: Path, fields: list[str], row: list[str]) -> None:
    path.write_text(
        "#separator \\x09\n"
        + "#fields\t"
        + "\t".join(fields)
        + "\n"
        + "\t".join(row)
        + "\n",
        encoding="utf-8",
    )


class DashboardTests(unittest.TestCase):
    def test_dashboard_html_is_full_view_and_has_required_tabs(self):
        html = dashboard.HTML_PATH.read_text(encoding="utf-8")
        self.assertIn("grid-template-columns: 360px minmax(0,1fr)", html)
        self.assertIn("Global anomalies", html)
        self.assertIn("Protocol-hour anomalies", html)
        self.assertIn("SSL flow alerts", html)
        self.assertIn("Support evidence, not an anomaly", html)
        self.assertIn("Documentation", html)
        self.assertIn("per-protocol benign warmup", html)
        self.assertIn("Responsible flows", html)
        self.assertIn("scopedFeature", html)
        self.assertIn("Timeline graphs", html)
        self.assertIn("Training, drift, and anomaly timeline", html)
        self.assertIn("Minimum level", html)
        self.assertIn("Composite importance", html)
        self.assertIn("ignore_multicast_broadcast", dashboard.SETTING_METADATA)
        self.assertEqual(
            dashboard.SETTING_METADATA["ignore_multicast_broadcast"][0],
            "Ignore multicast/broadcast",
        )

    def test_dashboard_run_uses_submitted_config(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            zeek = root / "zeek"
            zeek.mkdir()
            write_zeek_log(
                zeek / "conn.log",
                [
                    "ts",
                    "uid",
                    "id.orig_h",
                    "id.orig_p",
                    "id.resp_h",
                    "id.resp_p",
                    "orig_bytes",
                    "resp_bytes",
                ],
                ["1", "C1", "10.0.0.1", "50000", "1.1.1.1", "443", "10", "20"],
            )
            write_zeek_log(
                zeek / "ssl.log",
                [
                    "ts",
                    "uid",
                    "id.orig_h",
                    "id.orig_p",
                    "id.resp_h",
                    "id.resp_p",
                    "server_name",
                    "ja3",
                    "ja3s",
                ],
                ["1", "C1", "10.0.0.1", "50000", "1.1.1.1", "443", "new.test", "", "abc"],
            )
            config = dashboard.read_config(dashboard.DEFAULT_CONFIG)
            config["common"]["training_hours"] = 0
            config["common"]["sensitivity"] = 1.0
            with patch.object(dashboard, "RUNS_DIR", root / "runs"):
                result = dashboard.run_detector(
                    {"zeek_dir": str(zeek), "config": config}
                )
            self.assertEqual(result["summary"]["records_processed"], 2)
            self.assertEqual(result["capture"]["duration_seconds"], 0)
            self.assertEqual(result["capture"]["traffic_hour_span"], 1)
            self.assertTrue(result["model_updates"])
            self.assertEqual(
                result["flow_anomalies"],
                sorted(
                    result["flow_anomalies"],
                    key=lambda event: event["total_score"],
                    reverse=True,
                ),
            )
            self.assertEqual(len(result["flow_anomalies"]), 1)
            self.assertEqual(
                result["flow_anomalies"][0]["reasons"][0]["feature"],
                "new_server",
            )

    def test_capture_hours_ignore_non_detected_metadata_logs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_zeek_log(
                root / "conn.log",
                ["ts", "uid"],
                ["1", "C1"],
            )
            write_zeek_log(
                root / "ssl.log",
                ["ts", "uid"],
                ["7201", "C1"],
            )
            write_zeek_log(
                root / "x509.log",
                ["ts", "fingerprint"],
                ["1754365630", "ignored"],
            )
            capture = dashboard.inspect_zeek_folder(str(root))
            self.assertEqual(capture["duration_seconds"], 7200)
            self.assertEqual(capture["duration_hours"], 2.0)
            self.assertEqual(capture["traffic_hour_span"], 3)
            self.assertEqual(capture["active_traffic_hours"], 2)

    def test_docs_endpoint_returns_expected_documents(self):
        self.assertEqual(
            sorted(path.name for path in dashboard.DOC_FILES.values()),
            [
                "COMPUTATION_REFERENCE.md",
                "MULTI_PROTOCOL_ANOMALY_DETECTION.md",
                "README.md",
            ],
        )
        rendered = dashboard.markdown_to_html("# Title\n\n- one\n- two\n")
        self.assertIn("<h1>Title</h1>", rendered)
        self.assertIn("<ul><li>one</li><li>two</li></ul>", rendered)
        self.assertNotIn("# Title", rendered)


if __name__ == "__main__":
    unittest.main()
