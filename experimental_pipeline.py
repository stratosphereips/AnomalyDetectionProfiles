"""Failure-isolated experimental detector modules.

The statistical detector is the locked core.  Modules in this file run only
after that core has finished, which makes ``off`` and ``shadow`` observational:
they cannot change the core model, scores, or anomaly decisions.
"""

from __future__ import annotations

import math
import random
import statistics
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Mapping, Optional


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
    max_responsible_flows: int = 10
    core_detections: tuple[Mapping[str, Any], ...] = ()
    protocol_windows: tuple[Mapping[str, Any], ...] = ()
    target_windows: tuple[Mapping[str, Any], ...] = ()


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
        streams = _window_streams(context)

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
                            "responsible_flow_count": 0,
                            "responsible_flows": [],
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
                    candidate["responsible_flow_count"] += int(
                        row.get("responsible_flow_count", 0)
                    )
                    for original in row.get("responsible_flows", ()):
                        flow = dict(original)
                        flow["matched_features"] = sorted(
                            set(flow.get("matched_features", ()))
                            | {"joint_feature_relationship"}
                        )
                        candidate["responsible_flows"].append(flow)
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
            unique_flows: dict[str, Mapping[str, Any]] = {}
            for flow in candidate["responsible_flows"]:
                key = str(
                    flow.get("uid")
                    or flow.get("fuid")
                    or f'{flow.get("log")}:{flow.get("ts")}:{flow.get("dst")}'
                )
                unique_flows.setdefault(key, flow)
            candidate["responsible_flows"] = list(unique_flows.values())[
                : context.max_responsible_flows
            ]
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
            candidate_contribution=max(
                (float(item["score"]) for item in candidates), default=0.0
            ),
            reasons=tuple(reasons),
            responsible_uids=tuple(all_uids),
            responsible_fuids=tuple(all_fuids),
            top_features=tuple(top_features),
            candidate_detections=tuple(candidates),
        )


def _window_streams(
    context: PipelineContext,
) -> dict[tuple[str, str], list[Mapping[str, Any]]]:
    """Return source/protocol and destination streams in one common shape."""

    streams: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for row in context.protocol_windows:
        key = (str(row.get("host", "")), str(row.get("protocol", "")))
        if all(key):
            streams.setdefault(key, []).append(row)
    for original in context.target_windows:
        target = str(original.get("target", original.get("host", "")))
        if not target:
            continue
        row = dict(original)
        row["host"] = target
        row["protocol"] = "destination"
        row.setdefault("uids", ())
        row.setdefault("fuids", ())
        streams.setdefault((target, "destination"), []).append(row)
    for rows in streams.values():
        rows.sort(key=lambda row: float(row.get("window_start", 0)))
    return streams


def _trusted(row: Mapping[str, Any]) -> bool:
    return bool(row.get("external_baseline")) or row.get("phase") == "training"


def _numeric_feature_names(rows: list[Mapping[str, Any]]) -> tuple[str, ...]:
    if not rows:
        return ()
    common = set(rows[0].get("features", {}))
    for row in rows[1:]:
        common &= set(row.get("features", {}))
    return tuple(sorted(common))


def _vector(row: Mapping[str, Any], names: tuple[str, ...]) -> list[float]:
    return [
        math.log1p(max(0.0, float(row.get("features", {}).get(name, 0.0))))
        for name in names
    ]


def _robust_center_scale(
    history: list[list[float]],
) -> tuple[list[float], list[float]]:
    centers = [statistics.median(column) for column in zip(*history)]
    scales = []
    for index, center in enumerate(centers):
        deviations = [abs(row[index] - center) for row in history]
        scales.append(max(0.05, 1.4826 * statistics.median(deviations)))
    return centers, scales


def _candidate(
    host: str,
    protocol: str,
    row: Mapping[str, Any],
    raw_score: float,
    normalized_score: float,
    threshold: float,
    feature: str,
    explanation: str,
    top_features: list[Mapping[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    window_start = float(row.get("window_start", row.get("hour_start", 0)))
    reason = {
        "feature": feature,
        "host": host,
        "protocol": protocol,
        "window_start": window_start,
        "score": round(raw_score, 4),
        "threshold": threshold,
        "top_features": top_features[:5],
        "explanation": explanation,
    }
    responsible_flows = []
    for original in row.get("responsible_flows", ()):
        flow = dict(original)
        flow["matched_features"] = sorted(
            set(flow.get("matched_features", ())) | {feature}
        )
        responsible_flows.append(flow)
    candidate = {
        "detection_id": f"{host}@{window_start:g}",
        "host": host,
        "window_start": window_start,
        "score": round(max(0.0, min(1.0, normalized_score)), 4),
        "protocols": [protocol],
        "reasons": [reason],
        "responsible_uids": sorted(set(row.get("uids", ()))),
        "responsible_fuids": sorted(set(row.get("fuids", ()))),
        "responsible_flow_count": int(
            row.get("responsible_flow_count", len(responsible_flows))
        ),
        "responsible_flows": responsible_flows,
    }
    return reason, candidate


def _module_evidence(
    reasons: list[Mapping[str, Any]],
    candidates: list[Mapping[str, Any]],
    eligible: bool,
) -> ModuleEvidence:
    return ModuleEvidence(
        score=max((float(reason.get("score", 0.0)) for reason in reasons), default=0.0),
        eligible=eligible,
        candidate_contribution=max(
            (float(candidate.get("score", 0.0)) for candidate in candidates),
            default=0.0,
        ),
        reasons=tuple(reasons),
        responsible_uids=tuple(sorted({uid for item in candidates for uid in item.get("responsible_uids", ())})),
        responsible_fuids=tuple(sorted({uid for item in candidates for uid in item.get("responsible_fuids", ())})),
        top_features=tuple(
            feature
            for reason in reasons
            for feature in reason.get("top_features", ())
        )[:10],
        candidate_detections=tuple(candidates),
    )


def _jacobi_eigenvectors(matrix: list[list[float]]) -> list[tuple[float, list[float]]]:
    """Eigenpairs for a small symmetric matrix without external dependencies."""

    size = len(matrix)
    values = [row[:] for row in matrix]
    vectors = [[1.0 if row == column else 0.0 for column in range(size)] for row in range(size)]
    for _ in range(max(12, size * size * 8)):
        left, right = max(
            ((i, j) for i in range(size) for j in range(i + 1, size)),
            key=lambda pair: abs(values[pair[0]][pair[1]]),
            default=(0, 0),
        )
        if left == right or abs(values[left][right]) < 1e-9:
            break
        angle = 0.5 * math.atan2(
            2.0 * values[left][right], values[right][right] - values[left][left]
        )
        cosine, sine = math.cos(angle), math.sin(angle)
        for index in range(size):
            if index in {left, right}:
                continue
            first, second = values[index][left], values[index][right]
            values[index][left] = values[left][index] = cosine * first - sine * second
            values[index][right] = values[right][index] = sine * first + cosine * second
        a, b, cross = values[left][left], values[right][right], values[left][right]
        values[left][left] = cosine * cosine * a - 2 * sine * cosine * cross + sine * sine * b
        values[right][right] = sine * sine * a + 2 * sine * cosine * cross + cosine * cosine * b
        values[left][right] = values[right][left] = 0.0
        for index in range(size):
            first, second = vectors[index][left], vectors[index][right]
            vectors[index][left] = cosine * first - sine * second
            vectors[index][right] = sine * first + cosine * second
    pairs = [
        (values[index][index], [vectors[row][index] for row in range(size)])
        for index in range(size)
    ]
    return sorted(pairs, key=lambda pair: pair[0], reverse=True)


class PCAModule(ExperimentalModule):
    """Detect vectors that do not fit the main historical feature relationships."""

    module_id = "pca_reconstruction_v1"
    label = "PCA reconstruction error"

    def __init__(self, minimum_points: int = 8, threshold: float = 2.5, components: int = 2, history_limit: int = 64) -> None:
        self.minimum_points, self.threshold = minimum_points, threshold
        self.components, self.history_limit = components, history_limit
        if minimum_points < 3 or threshold <= 0 or components < 1 or history_limit < minimum_points:
            raise ValueError("invalid PCA detector parameters")

    def evaluate(self, context: PipelineContext) -> ModuleEvidence:
        reasons: list[Mapping[str, Any]] = []
        candidates: list[Mapping[str, Any]] = []
        eligible = False
        for (host, protocol), rows in _window_streams(context).items():
            names = _numeric_feature_names(rows)
            if len(names) < 2:
                continue
            history: list[list[float]] = []
            for row in rows:
                current = _vector(row, names)
                if _trusted(row) or len(history) < self.minimum_points:
                    history = (history + [current])[-self.history_limit:]
                    continue
                eligible = True
                centers, scales = _robust_center_scale(history)
                standardized = [[(item[i] - centers[i]) / scales[i] for i in range(len(names))] for item in history]
                means = [statistics.fmean(column) for column in zip(*standardized)]
                covariance = [[sum((item[i] - means[i]) * (item[j] - means[j]) for item in standardized) / max(1, len(history) - 1) for j in range(len(names))] for i in range(len(names))]
                eigenvectors = [pair[1] for pair in _jacobi_eigenvectors(covariance)[: min(self.components, len(names) - 1)]]
                delta = [(current[i] - centers[i]) / scales[i] - means[i] for i in range(len(names))]
                reconstruction = [sum(sum(delta[k] * vector[k] for k in range(len(names))) * vector[i] for vector in eigenvectors) for i in range(len(names))]
                residuals = [delta[i] - reconstruction[i] for i in range(len(names))]
                score = math.sqrt(sum(value * value for value in residuals) / len(names))
                if score >= self.threshold:
                    top = sorted(({"feature": names[i], "reconstruction_residual": round(abs(residuals[i]), 4)} for i in range(len(names))), key=lambda item: item["reconstruction_residual"], reverse=True)
                    reason, candidate = _candidate(host, protocol, row, score, 1.0 - math.exp(-score / self.threshold), self.threshold, "pca_reconstruction_error", "The feature vector cannot be reconstructed well from the main historical feature relationships.", top)
                    reasons.append(reason); candidates.append(candidate)
                history = (history + [current])[-self.history_limit:]
        return _module_evidence(reasons, candidates, eligible)


@dataclass
class _IsolationNode:
    size: int
    feature: int = -1
    split: float = 0.0
    left: Optional["_IsolationNode"] = None
    right: Optional["_IsolationNode"] = None


def _isolation_tree(rows: list[list[float]], rng: random.Random, depth: int, limit: int) -> _IsolationNode:
    node = _IsolationNode(len(rows))
    if len(rows) <= 1 or depth >= limit:
        return node
    choices = [i for i in range(len(rows[0])) if min(row[i] for row in rows) < max(row[i] for row in rows)]
    if not choices:
        return node
    node.feature = rng.choice(choices)
    low, high = min(row[node.feature] for row in rows), max(row[node.feature] for row in rows)
    node.split = rng.uniform(low, high)
    below = [row for row in rows if row[node.feature] < node.split]
    above = [row for row in rows if row[node.feature] >= node.split]
    if not below or not above:
        node.feature = -1
        return node
    node.left = _isolation_tree(below, rng, depth + 1, limit)
    node.right = _isolation_tree(above, rng, depth + 1, limit)
    return node


def _average_path_length(size: int) -> float:
    if size <= 1:
        return 0.0
    if size == 2:
        return 1.0
    return 2.0 * (math.log(size - 1) + 0.5772156649) - 2.0 * (size - 1) / size


def _isolation_path(node: _IsolationNode, row: list[float], depth: int = 0) -> float:
    if node.feature < 0 or node.left is None or node.right is None:
        return depth + _average_path_length(node.size)
    child = node.left if row[node.feature] < node.split else node.right
    return _isolation_path(child, row, depth + 1)


class IsolationForestModule(ExperimentalModule):
    """Detect feature vectors that are easy to isolate from historical vectors."""

    module_id = "isolation_forest_v1"
    label = "Isolation Forest"

    def __init__(self, minimum_points: int = 8, threshold: float = 0.65, trees: int = 32, history_limit: int = 64) -> None:
        self.minimum_points, self.threshold = minimum_points, threshold
        self.trees, self.history_limit = trees, history_limit
        if minimum_points < 4 or not 0 < threshold < 1 or trees < 4 or history_limit < minimum_points:
            raise ValueError("invalid Isolation Forest parameters")

    def evaluate(self, context: PipelineContext) -> ModuleEvidence:
        reasons: list[Mapping[str, Any]] = []; candidates: list[Mapping[str, Any]] = []; eligible = False
        for (host, protocol), rows in _window_streams(context).items():
            names = _numeric_feature_names(rows)
            if len(names) < 2: continue
            history: list[list[float]] = []
            for row in rows:
                current = _vector(row, names)
                if _trusted(row) or len(history) < self.minimum_points:
                    history = (history + [current])[-self.history_limit:]; continue
                eligible = True
                seed = sum(ord(char) for char in host + protocol) + int(float(row.get("window_start", 0)))
                rng = random.Random(seed)
                limit = max(1, math.ceil(math.log2(len(history))))
                forest = [_isolation_tree(history, rng, 0, limit) for _ in range(self.trees)]
                mean_path = statistics.fmean(_isolation_path(tree, current) for tree in forest)
                score = 2.0 ** (-mean_path / max(0.001, _average_path_length(len(history))))
                if score >= self.threshold:
                    centers, scales = _robust_center_scale(history)
                    top = sorted(({"feature": names[i], "standardized_deviation": round(abs(current[i] - centers[i]) / scales[i], 4)} for i in range(len(names))), key=lambda item: item["standardized_deviation"], reverse=True)
                    reason, candidate = _candidate(host, protocol, row, score, score, self.threshold, "isolation_score", "Random partition trees isolated this feature vector unusually quickly.", top)
                    reasons.append(reason); candidates.append(candidate)
                history = (history + [current])[-self.history_limit:]
        return _module_evidence(reasons, candidates, eligible)


class RarityModule(ExperimentalModule):
    """Detect feature values in sparsely observed empirical tails."""

    module_id = "empirical_rarity_v1"
    label = "Empirical rarity and novelty"

    def __init__(self, minimum_points: int = 8, threshold: float = 1.0, history_limit: int = 64) -> None:
        self.minimum_points, self.threshold, self.history_limit = minimum_points, threshold, history_limit
        if minimum_points < 4 or threshold <= 0 or history_limit < minimum_points:
            raise ValueError("invalid rarity detector parameters")

    def evaluate(self, context: PipelineContext) -> ModuleEvidence:
        reasons: list[Mapping[str, Any]] = []; candidates: list[Mapping[str, Any]] = []; eligible = False
        for (host, protocol), rows in _window_streams(context).items():
            names = _numeric_feature_names(rows); history: list[list[float]] = []
            if not names: continue
            for row in rows:
                current = _vector(row, names)
                if _trusted(row) or len(history) < self.minimum_points:
                    history = (history + [current])[-self.history_limit:]; continue
                eligible = True; feature_scores = []
                for i, name in enumerate(names):
                    column = [item[i] for item in history]
                    lower = sum(value <= current[i] for value in column)
                    upper = sum(value >= current[i] for value in column)
                    probability = min(1.0, 2.0 * (1 + min(lower, upper)) / (len(column) + 1))
                    feature_scores.append({"feature": name, "rarity_score": round(-math.log10(max(probability, 1e-9)), 4), "empirical_tail_probability": round(probability, 6)})
                feature_scores.sort(key=lambda item: item["rarity_score"], reverse=True)
                score = float(feature_scores[0]["rarity_score"])
                if score >= self.threshold:
                    reason, candidate = _candidate(host, protocol, row, score, 1.0 - 10.0 ** (-score), self.threshold, "empirical_feature_rarity", "At least one feature value lies in a rarely observed empirical tail for this stream.", feature_scores)
                    reasons.append(reason); candidates.append(candidate)
                history = (history + [current])[-self.history_limit:]
        return _module_evidence(reasons, candidates, eligible)


class ChangePointModule(ExperimentalModule):
    """Detect sustained recent level changes rather than isolated point outliers."""

    module_id = "change_point_v1"
    label = "Rolling time-series change"

    def __init__(self, minimum_points: int = 8, threshold: float = 3.0, recent_windows: int = 3, history_limit: int = 64) -> None:
        self.minimum_points, self.threshold = minimum_points, threshold
        self.recent_windows, self.history_limit = recent_windows, history_limit
        if minimum_points < recent_windows + 3 or threshold <= 0 or recent_windows < 2 or history_limit < minimum_points:
            raise ValueError("invalid change-point detector parameters")

    def evaluate(self, context: PipelineContext) -> ModuleEvidence:
        reasons: list[Mapping[str, Any]] = []; candidates: list[Mapping[str, Any]] = []; eligible = False
        for (host, protocol), rows in _window_streams(context).items():
            names = _numeric_feature_names(rows); history: list[list[float]] = []
            if not names: continue
            for row in rows:
                current = _vector(row, names)
                if _trusted(row) or len(history) < self.minimum_points:
                    history = (history + [current])[-self.history_limit:]; continue
                eligible = True
                reference = history[: -self.recent_windows + 1]
                recent = history[-self.recent_windows + 1 :] + [current]
                feature_scores = []
                for i, name in enumerate(names):
                    old = [item[i] for item in reference]; new = [item[i] for item in recent]
                    center = statistics.median(old)
                    scale = max(0.05, 1.4826 * statistics.median(abs(value - center) for value in old))
                    change = abs(statistics.median(new) - center) / scale
                    feature_scores.append({"feature": name, "change_score": round(change, 4), "old_median": round(center, 4), "recent_median": round(statistics.median(new), 4)})
                feature_scores.sort(key=lambda item: item["change_score"], reverse=True)
                score = float(feature_scores[0]["change_score"])
                if score >= self.threshold:
                    reason, candidate = _candidate(host, protocol, row, score, 1.0 - math.exp(-score / self.threshold), self.threshold, "rolling_level_change", "The recent sequence of feature values shifted away from its earlier level.", feature_scores)
                    reasons.append(reason); candidates.append(candidate)
                history = (history + [current])[-self.history_limit:]
        return _module_evidence(reasons, candidates, eligible)


class GraphBehaviorModule(ExperimentalModule):
    """Detect unusual source-to-destination relationships and fan-out."""

    module_id = "graph_behavior_v1"
    label = "Communication graph behavior"

    def __init__(self, minimum_points: int = 6, threshold: float = 0.65, history_limit: int = 64) -> None:
        self.minimum_points, self.threshold, self.history_limit = minimum_points, threshold, history_limit
        if minimum_points < 3 or not 0 < threshold <= 1 or history_limit < minimum_points:
            raise ValueError("invalid graph detector parameters")

    def evaluate(self, context: PipelineContext) -> ModuleEvidence:
        reasons: list[Mapping[str, Any]] = []; candidates: list[Mapping[str, Any]] = []; eligible = False
        grouped: dict[tuple[str, float], dict[str, Any]] = {}
        for row in context.protocol_windows:
            host = str(row.get("host", ""))
            peers = set(str(peer) for peer in row.get("peer_ips", ()) if peer)
            if not host or not peers:
                continue
            window_start = float(row.get("window_start", 0))
            combined = grouped.setdefault(
                (host, window_start),
                {
                    "host": host,
                    "window_start": window_start,
                    "phase": row.get("phase"),
                    "external_baseline": bool(row.get("external_baseline")),
                    "protocols": set(),
                    "peer_ips": set(),
                    "uids": set(),
                    "fuids": set(),
                    "responsible_flow_count": 0,
                    "responsible_flows": [],
                },
            )
            combined["protocols"].add(str(row.get("protocol", "unknown")))
            combined["peer_ips"].update(peers)
            combined["uids"].update(row.get("uids", ()))
            combined["fuids"].update(row.get("fuids", ()))
            combined["responsible_flow_count"] += int(
                row.get("responsible_flow_count", 0)
            )
            combined["responsible_flows"].extend(
                row.get("responsible_flows", ())
            )
        streams: dict[str, list[Mapping[str, Any]]] = {}
        for combined in grouped.values():
            combined["protocol"] = ",".join(sorted(combined.pop("protocols")))
            combined["peer_ips"] = sorted(combined["peer_ips"])
            combined["uids"] = sorted(combined["uids"])
            combined["fuids"] = sorted(combined["fuids"])
            unique_flows: dict[str, Mapping[str, Any]] = {}
            for flow in combined["responsible_flows"]:
                key = str(
                    flow.get("uid")
                    or flow.get("fuid")
                    or f'{flow.get("log")}:{flow.get("ts")}:{flow.get("dst")}'
                )
                unique_flows.setdefault(key, flow)
            combined["responsible_flows"] = list(unique_flows.values())[
                : context.max_responsible_flows
            ]
            streams.setdefault(str(combined["host"]), []).append(combined)
        for host, rows in streams.items():
            rows.sort(key=lambda row: float(row.get("window_start", 0)))
            history: list[set[str]] = []
            for row in rows:
                peers = set(str(peer) for peer in row.get("peer_ips", ()) if peer)
                if _trusted(row) or len(history) < self.minimum_points:
                    history = (history + [peers])[-self.history_limit:]; continue
                eligible = True
                known = set().union(*history) if history else set()
                new_peers = peers - known
                novelty = len(new_peers) / max(1, len(peers))
                counts = [len(item) for item in history]
                center = statistics.median(counts)
                scale = max(1.0, 1.4826 * statistics.median(abs(value - center) for value in counts))
                degree_change = max(0.0, (len(peers) - center) / scale)
                degree_component = min(1.0, degree_change / 3.0)
                score = 0.6 * novelty + 0.4 * degree_component
                if score >= self.threshold:
                    top = [
                        {"feature": "new_destination_ratio", "value": round(novelty, 4)},
                        {"feature": "destination_fanout_change", "value": round(degree_change, 4)},
                        {"feature": "new_destinations", "value": len(new_peers)},
                    ]
                    protocol = str(row.get("protocol", "multiple"))
                    reason, candidate = _candidate(host, protocol, row, score, score, self.threshold, "communication_graph_change", "This source contacted an unusual set or number of destination nodes compared with its earlier communication graph.", top)
                    candidate["protocols"] = protocol.split(",")
                    reason["new_peer_ips"] = sorted(new_peers)[:20]
                    reasons.append(reason); candidates.append(candidate)
                history = (history + [peers])[-self.history_limit:]
        return _module_evidence(reasons, candidates, eligible)


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
