import unittest

from experimental_pipeline import (
    ExperimentalModule,
    ExperimentalPipeline,
    ChangePointModule,
    CoreMirrorModule,
    GraphBehaviorModule,
    IsolationForestModule,
    ModuleEvidence,
    NoOpModule,
    PCAModule,
    PipelineContext,
    RarityModule,
    RobustMultivariateModule,
)


def context(with_core: bool = False) -> PipelineContext:
    return PipelineContext(
        records_processed=12,
        window_seconds=300,
        protocols=("conn", "dns"),
        protocol_anomalies=1,
        target_anomalies=0,
        ssl_flow_alerts=0,
        global_anomalies=1,
        core_detections=(
            (
                {
                    "detection_id": "10.0.0.1@300",
                    "host": "10.0.0.1",
                    "window_start": 300,
                    "score": 0.75,
                },
            )
            if with_core
            else ()
        ),
    )


class BrokenModule(ExperimentalModule):
    module_id = "broken_test"
    label = "Broken test module"

    def evaluate(self, run_context: PipelineContext) -> ModuleEvidence:
        del run_context
        raise RuntimeError("deliberate failure")


def numeric_context(include_target: bool = False) -> PipelineContext:
    rows = []
    for index in range(14):
        unusual = index >= 11
        rows.append({
            "host": "10.0.0.8", "protocol": "conn",
            "window_start": index * 300, "phase": "detection",
            "features": {
                "connections": 10 if not unusual else 100,
                "bytes": 20 if not unusual else 5,
                "failures": 1 if not unusual else 30,
            },
            "uids": [f"C{index}"], "fuids": [],
            "responsible_flow_count": 1,
            "responsible_flows": [{
                "log": "conn", "ts": index * 300 + 1,
                "uid": f"C{index}", "fuid": "",
                "src": "10.0.0.8", "src_port": "12345",
                "dst": "192.0.2.20", "dst_port": "443",
                "details": {"service": "ssl"},
            }],
        })
    targets = tuple({
        "target": "192.0.2.20", "window_start": row["window_start"],
        "phase": row["phase"], "features": row["features"],
        "uids": row["uids"], "fuids": [],
    } for row in rows) if include_target else ()
    return PipelineContext(
        records_processed=len(rows), window_seconds=300, protocols=("conn",),
        protocol_anomalies=0, target_anomalies=0, ssl_flow_alerts=0,
        global_anomalies=0, protocol_windows=tuple(rows), target_windows=targets,
    )


class ExperimentalPipelineTests(unittest.TestCase):
    def test_off_does_not_execute_or_contribute(self):
        result = ExperimentalPipeline([(BrokenModule(), "off")]).run(context())[0]
        self.assertEqual(result.status, "disabled")
        self.assertEqual(result.contribution, 0)
        self.assertFalse(result.affects_detection)

    def test_shadow_executes_but_cannot_contribute(self):
        result = ExperimentalPipeline([(NoOpModule(), "shadow")]).run(context())[0]
        self.assertEqual(result.status, "ready")
        self.assertEqual(result.mode, "shadow")
        self.assertEqual(result.contribution, 0)
        self.assertFalse(result.affects_detection)

    def test_active_noop_still_contributes_zero(self):
        result = ExperimentalPipeline([(NoOpModule(), "active")]).run(context())[0]
        self.assertEqual(result.status, "ready")
        self.assertEqual(result.contribution, 0)
        self.assertFalse(result.affects_detection)

    def test_module_failure_is_isolated_and_structured(self):
        result = ExperimentalPipeline([(BrokenModule(), "shadow")]).run(context())[0]
        self.assertEqual(result.status, "error")
        self.assertIn("RuntimeError: deliberate failure", result.error)
        self.assertEqual(result.contribution, 0)
        self.assertFalse(result.affects_detection)
        self.assertEqual(
            set(result.to_dict()),
            {
                "module", "label", "mode", "status", "eligible", "score",
                "candidate_contribution", "contribution", "affects_detection",
                "reasons", "responsible_uids", "responsible_fuids",
                "top_features", "candidate_detections", "comparison", "error",
            },
        )

    def test_core_mirror_has_exact_decision_and_score_agreement(self):
        result = ExperimentalPipeline(
            [(CoreMirrorModule(), "shadow")]
        ).run(context(with_core=True))[0]
        self.assertEqual(result.contribution, 0)
        self.assertEqual(result.comparison["core_count"], 1)
        self.assertEqual(result.comparison["module_count"], 1)
        self.assertEqual(result.comparison["overlap_count"], 1)
        self.assertEqual(result.comparison["decision_agreement"], 1.0)
        self.assertEqual(
            result.comparison["mean_absolute_score_difference"], 0.0
        )

    def test_multivariate_detects_unusual_relationship_with_normal_margins(self):
        rows = tuple(
            {
                "host": "10.0.0.8",
                "protocol": "dns",
                "window_start": index * 300,
                "phase": "training" if index < 10 else "detection",
                "features": {
                    "queries": index + 1 if index < 10 else 4,
                    "responses": index + 1 if index < 10 else 8,
                },
                "uids": [f"D{index}"],
                "fuids": [],
            }
            for index in range(11)
        )
        run_context = PipelineContext(
            records_processed=11,
            window_seconds=300,
            protocols=("dns",),
            protocol_anomalies=0,
            target_anomalies=0,
            ssl_flow_alerts=0,
            global_anomalies=0,
            protocol_windows=rows,
        )
        module = RobustMultivariateModule(
            minimum_points=8,
            threshold=1.2,
            shrinkage=0.1,
            history_limit=64,
        )
        result = ExperimentalPipeline([(module, "shadow")]).run(run_context)[0]
        self.assertTrue(result.eligible)
        self.assertEqual(len(result.candidate_detections), 1)
        candidate = result.candidate_detections[0]
        self.assertEqual(candidate["detection_id"], "10.0.0.8@3000")
        deviations = candidate["reasons"][0]["top_features"]
        self.assertTrue(
            all(abs(item["standardized_deviation"]) < 1 for item in deviations)
        )
        self.assertEqual(result.contribution, 0)
        self.assertFalse(result.affects_detection)

    def test_each_new_numeric_detector_runs_and_finds_the_shift(self):
        modules = [
            PCAModule(minimum_points=8, threshold=0.2, components=1),
            IsolationForestModule(minimum_points=8, threshold=0.45, trees=16),
            RarityModule(minimum_points=8, threshold=0.5),
            ChangePointModule(minimum_points=8, threshold=1.0, recent_windows=3),
        ]
        results = ExperimentalPipeline([(module, "shadow") for module in modules]).run(numeric_context())
        self.assertTrue(all(result.status == "ready" for result in results))
        self.assertTrue(all(result.eligible for result in results))
        self.assertTrue(all(result.candidate_detections for result in results))

    def test_multivariate_also_scores_destination_ip_windows(self):
        result = ExperimentalPipeline([(
            RobustMultivariateModule(minimum_points=8, threshold=0.5), "shadow"
        )]).run(numeric_context(include_target=True))[0]
        self.assertTrue(any(
            candidate["host"] == "192.0.2.20"
            for candidate in result.candidate_detections
        ))

    def test_graph_detector_combines_protocol_peers_per_window(self):
        rows = []
        for index in range(8):
            peers = ["192.0.2.1"] if index < 7 else [f"198.51.100.{n}" for n in range(1, 9)]
            for protocol in ("conn", "dns"):
                rows.append({
                    "host": "10.0.0.9", "protocol": protocol,
                    "window_start": index * 300, "phase": "detection",
                    "features": {"count": len(peers)}, "peer_ips": peers,
                    "uids": [f"G{index}{protocol}"], "fuids": [],
                })
        run_context = PipelineContext(
            records_processed=16, window_seconds=300, protocols=("conn", "dns"),
            protocol_anomalies=0, target_anomalies=0, ssl_flow_alerts=0,
            global_anomalies=0, protocol_windows=tuple(rows),
        )
        result = ExperimentalPipeline([(
            GraphBehaviorModule(minimum_points=6, threshold=0.5), "shadow"
        )]).run(run_context)[0]
        self.assertEqual(len(result.candidate_detections), 1)
        self.assertEqual(result.candidate_detections[0]["detection_id"], "10.0.0.9@2100")

    def test_active_has_effect_but_shadow_has_none_for_same_candidates(self):
        module = RarityModule(minimum_points=8, threshold=0.5)
        shadow, active = ExperimentalPipeline([
            (module, "shadow"), (module, "active")
        ]).run(numeric_context())
        self.assertTrue(shadow.candidate_detections)
        self.assertEqual(shadow.contribution, 0)
        self.assertFalse(shadow.affects_detection)
        self.assertGreater(active.contribution, 0)
        self.assertTrue(active.affects_detection)
        self.assertTrue(active.candidate_detections[0]["responsible_flows"])
        self.assertIn(
            "empirical_feature_rarity",
            active.candidate_detections[0]["responsible_flows"][0]["matched_features"],
        )


if __name__ == "__main__":
    unittest.main()
