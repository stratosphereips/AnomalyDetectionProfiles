"""Failure-isolated experimental detector modules.

The statistical detector is the locked core.  Modules in this file run only
after that core has finished, which makes ``off`` and ``shadow`` observational:
they cannot change the core model, scores, or anomaly decisions.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Mapping


VALID_MODES = ("off", "shadow", "active")


@dataclass(frozen=True)
class PipelineContext:
    """Read-only run facts exposed to an experimental module."""

    records_processed: int
    window_seconds: int
    protocols: tuple[str, ...]
    protocol_anomalies: int
    target_anomalies: int
    ssl_flow_alerts: int
    global_anomalies: int
    core_detections: tuple[Mapping[str, Any], ...] = ()
    protocol_windows: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True)
class ModuleEvidence:
    """Evidence returned by a module before its operating mode is applied."""

    score: float = 0.0
    eligible: bool = True
    candidate_contribution: float = 0.0
    reasons: tuple[Mapping[str, Any], ...] = ()
    responsible_uids: tuple[str, ...] = ()
    responsible_fuids: tuple[str, ...] = ()
    top_features: tuple[Mapping[str, Any], ...] = ()
    candidate_detections: tuple[Mapping[str, Any], ...] = ()


@dataclass
class ModuleResult:
    """Stable result schema shared by every experimental module."""

    module: str
    label: str
    mode: str
    status: str
    eligible: bool = False
    score: float = 0.0
    candidate_contribution: float = 0.0
    contribution: float = 0.0
    affects_detection: bool = False
    reasons: list[Mapping[str, Any]] = field(default_factory=list)
    responsible_uids: list[str] = field(default_factory=list)
    responsible_fuids: list[str] = field(default_factory=list)
    top_features: list[Mapping[str, Any]] = field(default_factory=list)
    candidate_detections: list[Mapping[str, Any]] = field(default_factory=list)
    comparison: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ExperimentalModule:
    """Small interface implemented by each local experimental detector."""

    module_id = "experimental"
    label = "Experimental module"

    def evaluate(self, context: PipelineContext) -> ModuleEvidence:
        raise NotImplementedError


class NoOpModule(ExperimentalModule):
    """Validation module that deliberately emits no anomaly contribution."""

    module_id = "noop_v1"
    label = "No-op pipeline check"

    def evaluate(self, context: PipelineContext) -> ModuleEvidence:
        del context
        return ModuleEvidence()


class CoreMirrorModule(ExperimentalModule):
    """Copies core decisions to validate comparison and display plumbing."""

    module_id = "core_mirror_v1"
    label = "Core mirror comparison check"

    def evaluate(self, context: PipelineContext) -> ModuleEvidence:
        return ModuleEvidence(candidate_detections=context.core_detections)


def _invert_matrix(matrix: list[list[float]]) -> list[list[float]]:
    """Invert a small regularized matrix with Gauss-Jordan elimination."""

    size = len(matrix)
    augmented = [
        row[:] + [1.0 if row_index == column else 0.0 for column in range(size)]
        for row_index, row in enumerate(matrix)
    ]
    for column in range(size):
        pivot = max(range(column, size), key=lambda row: abs(augmented[row][column]))
        if abs(augmented[pivot][column]) < 1e-12:
            raise ValueError("regularized covariance matrix is singular")
        augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
        divisor = augmented[column][column]
        augmented[column] = [value / divisor for value in augmented[column]]
        for row in range(size):
            if row == column:
                continue
            factor = augmented[row][column]
            augmented[row] = [
                current - factor * pivot_value
                for current, pivot_value in zip(
                    augmented[row], augmented[column]
                )
            ]
    return [row[size:] for row in augmented]


class RobustMultivariateModule(ExperimentalModule):
    """Detect unusual joint feature patterns with robust Mahalanobis distance."""

    module_id = "robust_multivariate_v1"
    label = "Robust multivariate feature relationships"

    def __init__(
        self,
        minimum_points: int = 8,
        threshold: float = 3.0,
        shrinkage: float = 0.5,
        history_limit: int = 64,
    ) -> None:
        if minimum_points < 3 or threshold <= 0 or history_limit < minimum_points:
            raise ValueError("invalid multivariate detector parameters")
        if not 0.0 <= shrinkage <= 1.0:
            raise ValueError("multivariate shrinkage must be between 0 and 1")
        self.minimum_points = minimum_points
        self.threshold = threshold
        self.shrinkage = shrinkage
        self.history_limit = history_limit

    @staticmethod
    def _vector(row: Mapping[str, Any], names: tuple[str, ...]) -> list[float]:
        features = row.get("features", {})
        return [math.log1p(max(0.0, float(features[name]))) for name in names]

    def _score(
        self,
        history: list[list[float]],
        current: list[float],
        names: tuple[str, ...],
    ) -> tuple[float, list[dict[str, Any]]]:
        dimensions = len(names)
        centers = [statistics.median(column) for column in zip(*history)]
        scales = []
        for index, center in enumerate(centers):
            deviations = [abs(row[index] - center) for row in history]
            scales.append(max(0.05, 1.4826 * statistics.median(deviations)))
        standardized = [
            [(row[index] - centers[index]) / scales[index] for index in range(dimensions)]
            for row in history
        ]
        means = [statistics.fmean(column) for column in zip(*standardized)]
        denominator = max(1, len(standardized) - 1)
        covariance = [
            [
                sum(
                    (row[left] - means[left]) * (row[right] - means[right])
                    for row in standardized
                )
                / denominator
                for right in range(dimensions)
            ]
            for left in range(dimensions)
        ]
        regularized = []
        for left in range(dimensions):
            regularized_row = []
            for right in range(dimensions):
                if left == right:
                    value = max(covariance[left][left], 0.05) + 0.05
                else:
                    value = (1.0 - self.shrinkage) * covariance[left][right]
                regularized_row.append(value)
            regularized.append(regularized_row)
        inverse = _invert_matrix(regularized)
        delta = [
            (current[index] - centers[index]) / scales[index] - means[index]
            for index in range(dimensions)
        ]
        projected = [
            sum(inverse[row][column] * delta[column] for column in range(dimensions))
            for row in range(dimensions)
        ]
        squared_distance = max(
            0.0, sum(delta[index] * projected[index] for index in range(dimensions))
        )
        score = math.sqrt(squared_distance / max(1, dimensions))
        feature_contributions = sorted(
            (
                {
                    "feature": names[index],
                    "standardized_deviation": round(delta[index], 4),
                    "distance_contribution": round(
                        abs(delta[index] * projected[index]), 4
                    ),
                }
                for index in range(dimensions)
            ),
            key=lambda item: item["distance_contribution"],
            reverse=True,
        )
        return score, feature_contributions[:5]

    def evaluate(self, context: PipelineContext) -> ModuleEvidence:
        streams: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
        for row in context.protocol_windows:
            key = (str(row.get("host", "")), str(row.get("protocol", "")))
            if all(key):
                streams.setdefault(key, []).append(row)

        candidates_by_id: dict[str, dict[str, Any]] = {}
        reasons: list[Mapping[str, Any]] = []
        eligible_windows = 0
        for (host, protocol), rows in streams.items():
            if not rows:
                continue
            feature_names = tuple(sorted(rows[0].get("features", {})))
            if len(feature_names) < 2:
                continue
            history: list[list[float]] = []
            for row in rows:
                current = self._vector(row, feature_names)
                trusted = bool(row.get("external_baseline")) or row.get("phase") == "training"
                if trusted or len(history) < self.minimum_points:
                    history.append(current)
                    history = history[-self.history_limit :]
                    continue
                eligible_windows += 1
                score, top = self._score(history, current, feature_names)
                if score >= self.threshold:
                    window_start = int(row.get("window_start", row.get("hour_start", 0)))
                    detection_id = f"{host}@{window_start}"
                    reason = {
                        "feature": "joint_feature_relationship",
                        "host": host,
                        "protocol": protocol,
                        "window_start": window_start,
                        "window_seconds": context.window_seconds,
                        "score": round(score, 4),
                        "threshold": self.threshold,
                        "top_features": top,
                        "explanation": (
                            "The feature combination is far from this host/protocol's "
                            "regularized multivariate baseline."
                        ),
                    }
                    reasons.append(reason)
                    candidate = candidates_by_id.setdefault(
                        detection_id,
                        {
                            "detection_id": detection_id,
                            "host": host,
                            "window_start": window_start,
                            "score": 0.0,
                            "protocols": [],
                            "reasons": [],
                            "responsible_uids": [],
                            "responsible_fuids": [],
                        },
                    )
                    candidate["score"] = max(
                        float(candidate["score"]),
                        1.0 - math.exp(-score / self.threshold),
                    )
                    candidate["protocols"].append(protocol)
                    candidate["reasons"].append(reason)
                    candidate["responsible_uids"].extend(row.get("uids", ()))
                    candidate["responsible_fuids"].extend(row.get("fuids", ()))
                history.append(current)
                history = history[-self.history_limit :]

        candidates = []
        for candidate in candidates_by_id.values():
            candidate["score"] = round(float(candidate["score"]), 4)
            candidate["protocols"] = sorted(set(candidate["protocols"]))
            candidate["responsible_uids"] = sorted(
                set(candidate["responsible_uids"])
            )
            candidate["responsible_fuids"] = sorted(
                set(candidate["responsible_fuids"])
            )
            candidates.append(candidate)
        candidates.sort(key=lambda item: (item["window_start"], item["host"]))
        all_uids = sorted(
            {uid for candidate in candidates for uid in candidate["responsible_uids"]}
        )
        all_fuids = sorted(
            {fuid for candidate in candidates for fuid in candidate["responsible_fuids"]}
        )
        top_features = [
            feature
            for reason in reasons
            for feature in reason.get("top_features", ())
        ][:10]
        return ModuleEvidence(
            score=max((float(reason["score"]) for reason in reasons), default=0.0),
            eligible=eligible_windows > 0,
            reasons=tuple(reasons),
            responsible_uids=tuple(all_uids),
            responsible_fuids=tuple(all_fuids),
            top_features=tuple(top_features),
            candidate_detections=tuple(candidates),
        )


class ExperimentalPipeline:
    """Runs modules independently and applies Off/Shadow/Active semantics."""

    def __init__(
        self,
        modules: Iterable[tuple[ExperimentalModule, str]],
    ) -> None:
        self.modules = list(modules)
        for _, mode in self.modules:
            if mode not in VALID_MODES:
                raise ValueError(f"invalid experimental module mode: {mode}")

    def run(self, context: PipelineContext) -> list[ModuleResult]:
        return [self._run_one(module, mode, context) for module, mode in self.modules]

    @staticmethod
    def _run_one(
        module: ExperimentalModule,
        mode: str,
        context: PipelineContext,
    ) -> ModuleResult:
        if mode == "off":
            return ModuleResult(
                module=module.module_id,
                label=module.label,
                mode=mode,
                status="disabled",
                comparison=ExperimentalPipeline._compare((), context),
            )
        try:
            evidence = module.evaluate(context)
            candidate = max(0.0, float(evidence.candidate_contribution))
            contribution = candidate if mode == "active" and evidence.eligible else 0.0
            return ModuleResult(
                module=module.module_id,
                label=module.label,
                mode=mode,
                status="ready",
                eligible=evidence.eligible,
                score=float(evidence.score),
                candidate_contribution=candidate,
                contribution=contribution,
                affects_detection=contribution > 0.0,
                reasons=list(evidence.reasons),
                responsible_uids=list(evidence.responsible_uids),
                responsible_fuids=list(evidence.responsible_fuids),
                top_features=list(evidence.top_features),
                candidate_detections=list(evidence.candidate_detections),
                comparison=ExperimentalPipeline._compare(
                    evidence.candidate_detections, context
                ),
            )
        except Exception as error:  # modules must never stop the locked core
            return ModuleResult(
                module=module.module_id,
                label=module.label,
                mode=mode,
                status="error",
                comparison=ExperimentalPipeline._compare((), context),
                error=f"{type(error).__name__}: {error}",
            )

    @staticmethod
    def _compare(
        candidates: Iterable[Mapping[str, Any]],
        context: PipelineContext,
    ) -> dict[str, Any]:
        core = {
            str(item["detection_id"]): item
            for item in context.core_detections
            if item.get("detection_id")
        }
        module = {
            str(item["detection_id"]): item
            for item in candidates
            if item.get("detection_id")
        }
        core_ids = set(core)
        module_ids = set(module)
        overlap = sorted(core_ids & module_ids)
        union = core_ids | module_ids
        score_differences = [
            abs(
                float(core[detection_id].get("score", 0.0))
                - float(module[detection_id].get("score", 0.0))
            )
            for detection_id in overlap
        ]
        return {
            "core_count": len(core_ids),
            "module_count": len(module_ids),
            "overlap_count": len(overlap),
            "core_only_count": len(core_ids - module_ids),
            "module_only_count": len(module_ids - core_ids),
            "decision_agreement": round(
                len(overlap) / len(union) if union else 1.0, 4
            ),
            "mean_absolute_score_difference": round(
                sum(score_differences) / len(score_differences)
                if score_differences
                else 0.0,
                4,
            ),
            "overlap_ids": overlap,
            "core_only_ids": sorted(core_ids - module_ids),
            "module_only_ids": sorted(module_ids - core_ids),
        }


def pipeline_summary(results: Iterable[ModuleResult]) -> dict[str, Any]:
    """Return dashboard-friendly status for the locked core and experiments."""

    return {
        "core": {
            "module": "core_statistical_v1",
            "label": "Adaptive statistical detector",
            "mode": "active",
            "status": "ready",
            "locked": True,
            "affects_detection": True,
        },
        "experimental": [result.to_dict() for result in results],
    }
