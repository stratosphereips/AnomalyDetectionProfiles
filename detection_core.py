"""Shared parsing and adaptive statistics for the unified detector."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional


UNSET_VALUES = {"", "-", "(empty)", None}


def is_unset(value: Any) -> bool:
    """Return whether a scalar value is one of Zeek's unset markers."""
    return value is None or (isinstance(value, str) and value in UNSET_VALUES)


def clean(value: Any) -> str:
    return "" if is_unset(value) else str(value)


def number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def quantile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = max(0.0, min(1.0, q)) * (len(ordered) - 1)
    low, high = math.floor(position), math.ceil(position)
    if low == high:
        return ordered[low]
    fraction = position - low
    return ordered[low] * (1.0 - fraction) + ordered[high] * fraction


@dataclass
class AdaptiveStats:
    mean: float = 0.0
    variance: float = 0.0
    m2: float = 0.0
    count: int = 0
    minimum_std: float = 0.1
    values: list[float] = field(default_factory=list)
    residuals: list[float] = field(default_factory=list)
    training_values: list[float] = field(default_factory=list)
    threshold: Optional[float] = None

    def _remember(self, value: float) -> None:
        self.values.append(value)
        del self.values[:-256]

    def _update_floor(self, residual: float) -> None:
        self.residuals.append(abs(residual))
        del self.residuals[:-64]
        if len(self.residuals) < 5:
            return
        q10 = quantile(self.residuals, 0.10)
        median = quantile(self.residuals, 0.50)
        mad = quantile([abs(item - median) for item in self.residuals], 0.50)
        candidate = max(0.01, q10, 1.4826 * mad)
        self.minimum_std = 0.95 * self.minimum_std + 0.05 * candidate

    def fit(self, value: float) -> None:
        self._remember(value)
        self.training_values.append(value)
        if self.count:
            self._update_floor(value - self.mean)
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self.m2 += delta * (value - self.mean)
        self.variance = self.m2 / max(1, self.count - 1)

    def update(self, value: float, alpha: float) -> None:
        self._remember(value)
        if self.count:
            self._update_floor(value - self.mean)
        else:
            self.mean = value
            self.count = 1
            return
        delta = value - self.mean
        self.mean += alpha * delta
        self.variance = (1.0 - alpha) * (
            self.variance + alpha * delta * delta
        )
        self.m2 = self.variance * max(0, self.count - 1)
        self.count += 1

    def robust_zscore(self, value: float, minimum_points: int) -> float:
        if self.count < minimum_points:
            return 0.0
        if len(self.values) < 7:
            deviation = math.sqrt(
                max(self.variance, self.minimum_std * self.minimum_std)
            )
            return abs(value - self.mean) / deviation
        median = quantile(self.values, 0.50)
        mad = quantile([abs(item - median) for item in self.values], 0.50)
        robust_std = max(1.4826 * mad, self.minimum_std)
        return abs(value - median) / robust_std

    def calibrate(self, fallback: float, q: float) -> None:
        if len(self.training_values) < 10:
            self.threshold = fallback
            return
        median = quantile(self.training_values, 0.50)
        mad = quantile(
            [abs(item - median) for item in self.training_values], 0.50
        )
        robust_std = max(1.4826 * mad, self.minimum_std)
        scores = [
            abs(item - median) / robust_std for item in self.training_values
        ]
        self.threshold = min(15.0, max(1.5, quantile(scores, q)))


class ZeekReader:
    """Read Zeek TSV or JSON logs and normalize unset values."""

    def __init__(self, path: Path):
        self.path = path

    def __iter__(self) -> Iterator[dict[str, Any]]:
        with self.path.open("r", encoding="utf-8", errors="replace") as handle:
            first_data: Optional[str] = None
            fields: list[str] = []
            separator = "\t"
            for raw_line in handle:
                line = raw_line.rstrip("\r\n")
                if line.startswith("#separator "):
                    encoded = line.split(" ", 1)[1]
                    separator = bytes(encoded, "utf-8").decode("unicode_escape")
                elif line.startswith("#fields"):
                    fields = line.split(separator)[1:]
                elif line and not line.startswith("#"):
                    first_data = line
                    break
            if first_data is None:
                return
            for line in (first_data, *handle):
                line = line.rstrip("\r\n")
                if not line or line.startswith("#"):
                    continue
                if line.lstrip().startswith("{"):
                    record = json.loads(line)
                else:
                    if not fields:
                        raise ValueError(
                            f"{self.path}: missing Zeek #fields header"
                        )
                    record = dict(zip(fields, line.split(separator)))
                yield {
                    key: ("" if is_unset(value) else value)
                    for key, value in record.items()
                }
