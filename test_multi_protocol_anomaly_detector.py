import argparse
import json
import tempfile
import unittest
from pathlib import Path

from multi_protocol_anomaly_detector import (
    MultiProtocolDetector,
    Outputs,
    bucket_start,
    dns_lexical_metrics,
    discover_logs,
    enrich_cross_log_context,
    importance_metrics,
    is_ignored_multicast_broadcast,
    main,
    source_ip,
)


def arguments():
    return argparse.Namespace(
        training_hours=1,
        window_seconds=3600,
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
        uid_corroboration_bonus=0.10,
        uid_corroboration_bonus_cap=0.20,
        max_responsible_flows=10,
        ssl_hourly_threshold=3.5,
        ssl_flow_threshold=100.0,
        ssl_novelty_threshold=1.5,
        ssl_baseline_alpha=0.1,
        ssl_max_small_anomalies=2,
    )


class MultiProtocolTests(unittest.TestCase):
    def test_off_and_shadow_have_identical_core_outputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            zeek = root / "zeek"
            zeek.mkdir()
            records = [
                {
                    "ts": index * 300 + 1,
                    "uid": f"D{index}",
                    "id.orig_h": "10.0.0.1",
                    "id.resp_h": "1.1.1.1",
                    "query": "example.test" if index < 3 else "unusual.example",
                    "qtype_name": "A",
                    "rcode_name": "NOERROR",
                }
                for index in range(5)
            ]
            (zeek / "dns.log").write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            outputs = {}
            for mode in ("off", "shadow"):
                output = root / mode
                self.assertEqual(
                    main(
                        [
                            str(zeek), "--window-seconds", "300",
                            "--training-hours", "1", "--minimum-points", "1",
                            "--experimental-noop-mode", "off",
                            "--experimental-multivariate-mode", mode, "--quiet",
                            "--no-terminal-data", "-o", str(output),
                        ]
                    ),
                    0,
                )
                outputs[mode] = output
            for filename in (
                "protocol_hourly_data.jsonl", "target_hourly_data.jsonl",
                "flow_anomalies.jsonl", "protocol_anomalies.jsonl",
                "target_anomalies.jsonl", "global_anomalies.jsonl",
            ):
                self.assertEqual(
                    (outputs["off"] / filename).read_bytes(),
                    (outputs["shadow"] / filename).read_bytes(),
                    filename,
                )

    def test_configurable_window_bucketing(self):
        self.assertEqual(bucket_start(599.9, 300), 300)
        self.assertEqual(bucket_start(600.0, 300), 600)
        with tempfile.TemporaryDirectory() as temp:
            args = arguments()
            args.window_seconds = 300
            output = Outputs(Path(temp), quiet=True)
            detector = MultiProtocolDetector(args, output)
            for ts, uid in ((1.0, "D1"), (301.0, "D2")):
                detector.observe(
                    "dns",
                    {
                        "ts": str(ts),
                        "uid": uid,
                        "id.orig_h": "10.0.0.1",
                        "id.resp_h": "1.1.1.1",
                        "query": "example.test",
                        "qtype_name": "A",
                        "rcode_name": "NOERROR",
                    },
                    "10.0.0.1",
                    ts,
                )
            detector.finalize_all()
            output.close()
            rows = [
                json.loads(line)
                for line in (Path(temp) / "protocol_hourly_data.jsonl")
                .read_text()
                .splitlines()
            ]
            self.assertEqual(
                [row["window_start"] for row in rows], [0, 300]
            )
            self.assertTrue(
                all(row["window_seconds"] == 300 for row in rows)
            )

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

    def test_discovery_includes_ssh(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "ssh.log").touch()
            selected, skipped = discover_logs(root)
            self.assertEqual(selected, [("ssh", root / "ssh.log")])
            self.assertEqual(skipped, [])

    def test_dns_lexical_metrics_and_local_exclusion(self):
        suspicious = dns_lexical_metrics("x9q7mz2k4v8p.example")
        local = dns_lexical_metrics("_printer._tcp.local")
        self.assertTrue(suspicious["dga_like"])
        self.assertTrue(local["is_local_tld"])
        self.assertTrue(local["is_service_discovery"])

    def test_uid_and_fuid_cross_log_enrichment(self):
        http = {
            "uid": "C1",
            "resp_fuids": "F1",
        }
        observations = [
            (1.0, "http", http, "10.0.0.1", "1.1.1.1"),
            (
                1.1,
                "files",
                {
                    "uid": "C1",
                    "fuid": "F1",
                    "total_bytes": "120",
                    "seen_bytes": "100",
                    "mime_type": "application/pdf",
                },
                "10.0.0.1",
                "1.1.1.1",
            ),
            (1.2, "weird", {"uid": "C1"}, "10.0.0.1", "1.1.1.1"),
        ]
        enrich_cross_log_context(observations)
        self.assertEqual(http["_uid_protocols"], ["files", "http", "weird"])
        self.assertEqual(http["_linked_fuids"], ["F1"])
        self.assertEqual(http["_linked_file_bytes"], 120.0)
        self.assertEqual(http["_linked_file_mimes"], ["application/pdf"])

    def test_external_normal_directory_is_prefit_and_not_counted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            normal = root / "normal"
            selected = root / "selected"
            output = root / "output"
            normal.mkdir()
            selected.mkdir()
            base = {
                "uid": "C1",
                "id.orig_h": "10.0.0.1",
                "id.resp_h": "1.1.1.1",
                "id.resp_p": 80,
                "conn_state": "SF",
                "orig_bytes": 10,
                "resp_bytes": 20,
            }
            (normal / "conn.log").write_text(
                json.dumps({"ts": 1, **base}) + "\n", encoding="utf-8"
            )
            (selected / "conn.log").write_text(
                json.dumps({"ts": 3601, **base, "uid": "C2"}) + "\n",
                encoding="utf-8",
            )
            self.assertEqual(
                main(
                    [
                        str(selected),
                        "--normal-dir",
                        str(normal),
                        "--training-hours",
                        "0",
                        "--minimum-points",
                        "1",
                        "--quiet",
                        "--no-terminal-data",
                        "-o",
                        str(output),
                    ]
                ),
                0,
            )
            events = [
                json.loads(line)
                for line in (output / "multi_protocol_detector.log.jsonl")
                .read_text()
                .splitlines()
            ]
            baseline = next(
                event
                for event in events
                if event["event"] == "external_baseline_loaded"
            )
            stop = next(
                event for event in events if event["event"] == "detector_stop"
            )
            self.assertEqual(baseline["records"], 1)
            self.assertEqual(stop["records_processed"], 1)
            self.assertEqual(stop["external_baseline_records"], 1)

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

    def test_exact_uid_adds_capped_global_corroboration(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Outputs(Path(temp), quiet=True)
            detector = MultiProtocolDetector(arguments(), output)
            detector.protocol_anomalies = [
                {
                    "event": "protocol_anomaly",
                    "host": "10.0.0.1",
                    "hour_start": 0,
                    "protocol": protocol,
                    "normalized_score": 0.2,
                    "score": 2.0,
                    "reasons": [{"feature": "flow_count"}],
                    "responsible_flow_count": 1,
                    "responsible_flows": [],
                    "responsible_uids": ["C1"],
                    "responsible_fuids": [],
                }
                for protocol in ("dns", "http")
            ]
            event = detector.ensemble()[0]
            output.close()
            self.assertEqual(event["shared_uids"], ["C1"])
            self.assertEqual(event["uid_corroboration_bonus"], 0.1)
            self.assertEqual(event["global_score"], 0.65)

    def test_connection_and_ssh_derived_features(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Outputs(Path(temp), quiet=True)
            detector = MultiProtocolDetector(arguments(), output)
            for port in ("22", "23"):
                detector.observe(
                    "conn",
                    {
                        "uid": f"C{port}",
                        "id.orig_h": "10.0.0.1",
                        "id.resp_h": "1.1.1.1",
                        "id.resp_p": port,
                        "conn_state": "S0",
                        "history": "S",
                        "duration": "0.01",
                        "orig_bytes": "0",
                        "resp_bytes": "0",
                        "orig_pkts": "1",
                    },
                    "10.0.0.1",
                    1.0,
                )
            detector.observe(
                "ssh",
                {
                    "uid": "S1",
                    "id.orig_h": "10.0.0.1",
                    "id.resp_h": "1.1.1.1",
                    "auth_success": "F",
                    "auth_attempts": "7",
                },
                "10.0.0.1",
                1.0,
            )
            detector.finalize_all()
            output.close()
            rows = [
                json.loads(line)
                for line in (Path(temp) / "protocol_hourly_data.jsonl")
                .read_text()
                .splitlines()
            ]
            conn = next(row for row in rows if row["protocol"] == "conn")
            ssh = next(row for row in rows if row["protocol"] == "ssh")
            self.assertEqual(conn["features"]["max_ports_per_destination"], 2)
            self.assertEqual(conn["features"]["failed_scan_ratio"], 1)
            self.assertEqual(ssh["features"]["max_auth_attempts"], 7)

    def test_target_anomalies_contribute_to_global_ensemble(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Outputs(Path(temp), quiet=True)
            detector = MultiProtocolDetector(arguments(), output)
            detector.target_anomalies = [
                {
                    "event": "target_anomaly",
                    "target": "37.48.125.108",
                    "hour_start": 3600,
                    "normalized_score": 0.40,
                    "score": 4.0,
                    "reasons": [{"feature": "incoming_flow_count"}],
                    "responsible_flow_count": 0,
                    "responsible_flows": [],
                }
            ]
            detector.protocol_anomalies = [
                {
                    "event": "protocol_anomaly",
                    "host": "37.48.125.108",
                    "hour_start": 3600,
                    "protocol": "dns",
                    "normalized_score": 0.30,
                    "score": 3.0,
                    "reasons": [{"feature": "flow_count"}],
                    "responsible_flow_count": 0,
                    "responsible_flows": [],
                }
            ]
            events = detector.ensemble()
            output.close()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["host"], "37.48.125.108")
            self.assertEqual(events[0]["protocols"], ["dns", "target:37.48.125.108"])
            self.assertEqual(len(events[0]["target_anomalies"]), 1)

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

    def test_target_ip_hourly_detector_emits_destination_anomaly(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Outputs(Path(temp), quiet=True)
            detector = MultiProtocolDetector(arguments(), output)
            detector.observe(
                "conn",
                {
                    "ts": "1",
                    "uid": "C1",
                    "id.orig_h": "10.0.0.10",
                    "id.resp_h": "37.48.125.108",
                    "id.orig_p": "50000",
                    "id.resp_p": "80",
                    "orig_bytes": "10",
                    "resp_bytes": "20",
                    "conn_state": "SF",
                },
                "10.0.0.10",
                1.0,
            )
            detector.observe_target(
                "conn",
                {
                    "ts": "1",
                    "uid": "C1",
                    "id.orig_h": "10.0.0.10",
                    "id.resp_h": "37.48.125.108",
                    "id.orig_p": "50000",
                    "id.resp_p": "80",
                    "conn_state": "SF",
                },
                "10.0.0.10",
                "37.48.125.108",
                1.0,
            )
            for idx, source in enumerate(
                ["10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14"],
                start=2,
            ):
                ts = float(3600 + idx)
                detector.observe(
                    "conn",
                    {
                        "ts": str(ts),
                        "uid": f"C{idx}",
                        "id.orig_h": source,
                        "id.resp_h": "37.48.125.108",
                        "id.orig_p": str(50000 + idx),
                        "id.resp_p": "443",
                        "orig_bytes": str(20 * idx),
                        "resp_bytes": "0",
                        "conn_state": "S0",
                    },
                    source,
                    ts,
                )
                detector.observe_target(
                    "conn",
                    {
                        "ts": str(ts),
                        "uid": f"C{idx}",
                        "id.orig_h": source,
                        "id.resp_h": "37.48.125.108",
                        "id.orig_p": str(50000 + idx),
                        "id.resp_p": "443",
                        "conn_state": "S0",
                    },
                    source,
                    "37.48.125.108",
                    ts,
                )
            detector.finalize_all()
            detector.finalize_targets()
            output.close()
            self.assertTrue(detector.target_anomalies)
            event = detector.target_anomalies[0]
            self.assertEqual(event["type"], "target-hour")
            self.assertEqual(event["target"], "37.48.125.108")
            self.assertIn("incoming_flow_count", {r["feature"] for r in event["reasons"]})
            self.assertGreaterEqual(event["responsible_flow_count"], 1)
            self.assertTrue(event["responsible_flows"])


if __name__ == "__main__":
    unittest.main()
