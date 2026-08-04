"""Failure-isolated experimental detector modules.

The statistical detector is the locked core.  Modules in this file run only
after that core has finished, which makes ``off`` and ``shadow`` observational:
they cannot change the core model, scores, or anomaly decisions.
"""

from __future__ import annotations

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
            )
        except Exception as error:  # modules must never stop the locked core
            return ModuleResult(
                module=module.module_id,
                label=module.label,
                mode=mode,
                status="error",
                error=f"{type(error).__name__}: {error}",
            )


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
