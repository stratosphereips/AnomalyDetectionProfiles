import argparse
import json
import tempfile
import unittest
from pathlib import Path

from multi_protocol_anomaly_detector import (
    MultiProtocolDetector,
    Outputs,
    discover_logs,
    importance_metrics,
    is_ignored_multicast_broadcast,
    source_ip,
)


def arguments():
    return argparse.Namespace(
        training_hours=1,
        sensitivity=1.0,
        ignore_multicast_broadcast=True,
        minimum_points=1,
        threshold=2.0,
        threshold_quantile=0.995,
        drift_alpha=0.05,
        suspicious_alpha=0.005,
        adaptation_score=8.0,
        protocol_score_cap=10.0,
        global_threshold=0.65,
        minimum_protocols=2,
        corroboration_bonus=0.15,
        corroboration_bonus_cap=0.30,
        max_responsible_flows=10,
        ssl_hourly_threshold=3.5,
        ssl_flow_threshold=100.0,
        ssl_novelty_threshold=1.5,
        ssl_baseline_alpha=0.1,
        ssl_max_small_anomalies=2,
    )


class MultiProtocolTests(unittest.TestCase):
    def test_importance_rewards_breadth_and_threshold_excess(self):
        narrow = importance_metrics(
            [{"zscore": 4.0, "threshold": 3.5}], 4.0, protocol_count=1
        )
        broad = importance_metrics(
            [
                {"zscore": 8.0, "threshold": 3.5},
                {"zscore": 6.0, "threshold": 3.5},
            ],
            14.0,
            protocol_count=3,
        )
        self.assertGreater(
            broad["importance_score"], narrow["importance_score"]
        )
        self.assertGreater(broad["threshold_excess"], 0)

    def test_source_ip_protocol_fallbacks(self):
        self.assertEqual(
            source_ip({"client_addr": "10.0.0.2"}, "dhcp"), "10.0.0.2"
        )
        self.assertEqual(
            source_ip({"host": "10.0.0.3"}, "software"), "10.0.0.3"
        )
        self.assertEqual(source_ip({"host": "not-an-ip"}, "software"), "")

    def test_discovery_excludes_sensor_logs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "dns.log").touch()
            (root / "stats.log").touch()
            selected, skipped = discover_logs(root)
            self.assertEqual(selected, [("dns", root / "dns.log")])
            self.assertEqual(skipped, ["stats"])

    def test_multicast_and_broadcast_filter_matches_ipv4_and_ipv6(self):
        self.assertTrue(
            is_ignored_multicast_broadcast("10.0.0.1", "224.0.0.1")
        )
        self.assertTrue(
            is_ignored_multicast_broadcast("255.255.255.255", "10.0.0.1")
        )
        self.assertTrue(
            is_ignored_multicast_broadcast("10.0.2.15", "10.0.2.255")
        )
        self.assertTrue(
            is_ignored_multicast_broadcast("10.0.0.1", "ff02::1")
        )
        self.assertFalse(
            is_ignored_multicast_broadcast("10.0.0.1", "1.1.1.1")
        )

    def test_two_protocol_votes_create_global_anomaly(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Outputs(Path(temp), quiet=True)
            detector = MultiProtocolDetector(arguments(), output)
            detector.protocol_anomalies = [
                {
                    "host": "10.0.0.1",
                    "hour_start": 3600,
                    "protocol": "dns",
                    "normalized_score": 0.30,
                    "score": 3.0,
                    "reasons": [{"feature": "flow_count"}],
                    "responsible_flow_count": 0,
                    "responsible_flows": [],
                },
                {
                    "host": "10.0.0.1",
                    "hour_start": 3600,
                    "protocol": "http",
                    "normalized_score": 0.30,
                    "score": 3.0,
                    "reasons": [{"feature": "failure_ratio"}],
                    "responsible_flow_count": 0,
                    "responsible_flows": [],
                },
            ]
            events = detector.ensemble()
            output.close()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["protocols"], ["dns", "http"])
            self.assertEqual(events[0]["global_score"], 0.75)

    def test_low_sensitivity_suppresses_same_protocol_vote(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Outputs(Path(temp), quiet=True)
            args = arguments()
            args.sensitivity = 0.5
            detector = MultiProtocolDetector(args, output)
            detector.protocol_anomalies = [
                {
                    "host": "10.0.0.1",
                    "hour_start": 3600,
                    "protocol": "dns",
                    "normalized_score": 0.70,
                    "score": 7.0,
                    "reasons": [{"feature": "flow_count"}],
                    "responsible_flow_count": 0,
                    "responsible_flows": [],
                }
            ]
            events = detector.ensemble()
            output.close()
            self.assertEqual(events, [])

    def test_protocol_training_then_detection(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Outputs(Path(temp), quiet=True)
            detector = MultiProtocolDetector(arguments(), output)
            detector.observe(
                "dns",
                {
                    "ts": "1",
                    "uid": "C1",
                    "id.orig_h": "10.0.0.1",
                    "id.resp_h": "1.1.1.1",
                    "query": "known.test",
                    "qtype_name": "A",
                    "rcode_name": "NOERROR",
                    "rtt": "0.01",
                },
                "10.0.0.1",
                1.0,
            )
            detector.observe(
                "dns",
                {
                    "ts": "3601",
                    "uid": "C2",
                    "id.orig_h": "10.0.0.1",
                    "id.resp_h": "9.9.9.9",
                    "query": "new.test",
                    "qtype_name": "TXT",
                    "rcode_name": "NXDOMAIN",
                    "rtt": "9.0",
                },
                "10.0.0.1",
                3601.0,
            )
            detector.finalize_all()
            output.close()
            self.assertGreaterEqual(len(detector.protocol_anomalies), 1)
            event = detector.protocol_anomalies[0]
            self.assertGreaterEqual(event["responsible_flow_count"], 1)
            self.assertEqual(
                event["responsible_flows"][0]["log"], "dns"
            )
            self.assertTrue(
                event["responsible_flows"][0]["matched_features"]
            )
            for reason in event["reasons"]:
                self.assertEqual(reason["source_ip"], "10.0.0.1")
                self.assertEqual(reason["protocol"], "dns")
                self.assertEqual(reason["window_seconds"], 3600)

    def test_specialized_ssl_flow_detection_is_unified(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Outputs(Path(temp), quiet=True)
            detector = MultiProtocolDetector(arguments(), output)
            first = {
                "ts": "1",
                "uid": "C1",
                "id.orig_h": "10.0.0.1",
                "id.orig_p": "50000",
                "id.resp_h": "1.1.1.1",
                "id.resp_p": "443",
                "server_name": "known.test",
                "_conn_total_bytes": 30.0,
            }
            detector.observe("ssl", first, "10.0.0.1", 1.0)
            second = {
                "ts": "3601",
                "uid": "C2",
                "id.orig_h": "10.0.0.1",
                "id.orig_p": "50001",
                "id.resp_h": "2.2.2.2",
                "id.resp_p": "443",
                "server_name": "new.test",
                "_conn_total_bytes": 40.0,
            }
            detector.observe("ssl", second, "10.0.0.1", 3601.0)
            detector.finalize_all()
            output.close()
            self.assertEqual(len(detector.flow_anomalies), 1)
            event = detector.flow_anomalies[0]
            self.assertEqual(event["type"], "ssl-flow")
            self.assertEqual(event["responsible_flows"][0]["uid"], "C2")
            self.assertEqual(event["reasons"][0]["feature"], "new_server")
            hourly_rows = [
                json.loads(line)
                for line in (
                    Path(temp) / "protocol_hourly_data.jsonl"
                ).read_text().splitlines()
            ]
            ssl_rows = [
                row for row in hourly_rows if row["protocol"] == "ssl"
            ]
            self.assertTrue(ssl_rows)
            self.assertTrue(
                all(
                    "ssl_flow_anomalies" not in row["features"]
                    for row in ssl_rows
                )
            )


if __name__ == "__main__":
    unittest.main()
