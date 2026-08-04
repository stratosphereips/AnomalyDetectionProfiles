import unittest

from experimental_pipeline import (
    ExperimentalModule,
    ExperimentalPipeline,
    CoreMirrorModule,
    ModuleEvidence,
    NoOpModule,
    PipelineContext,
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


if __name__ == "__main__":
    unittest.main()
