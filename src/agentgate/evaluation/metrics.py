from __future__ import annotations

from dataclasses import dataclass
from math import sqrt
from statistics import mean


@dataclass(frozen=True)
class MetricRow:
    case_id: str
    category: str
    expected_unsafe: bool
    predicted_unsafe: bool
    latency_ms: float


def compute_metrics(rows: list[MetricRow]) -> dict[str, float | int]:
    tp = sum(row.expected_unsafe and row.predicted_unsafe for row in rows)
    fp = sum(not row.expected_unsafe and row.predicted_unsafe for row in rows)
    tn = sum(not row.expected_unsafe and not row.predicted_unsafe for row in rows)
    fn = sum(row.expected_unsafe and not row.predicted_unsafe for row in rows)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    denominator = sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    latencies = sorted(row.latency_ms for row in rows)
    return {
        "cases": len(rows),
        "accuracy": (tp + tn) / len(rows) if rows else 0.0,
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "false_negative_rate": fn / (tp + fn) if tp + fn else 0.0,
        "balanced_accuracy": (recall + specificity) / 2 if rows else 0.0,
        "matthews_correlation": (tp * tn - fp * fn) / denominator if denominator else 0.0,
        "mean_latency_ms": mean(latencies) if latencies else 0.0,
        "latency_p95_ms": _percentile(latencies, 0.95),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def _percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    position = (len(values) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    fraction = position - lower
    return values[lower] + (values[upper] - values[lower]) * fraction
