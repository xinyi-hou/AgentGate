from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Literal

from agentgate.content import ContentScanner
from agentgate.evaluation.metrics import MetricRow, compute_metrics

ContentMode = Literal["agentgate", "override_regex", "no_guard"]


def evaluate_injecagent(source: str | Path, mode: ContentMode) -> dict:
    data = Path(source) / "data"
    scanner = ContentScanner()
    rows: list[MetricRow] = []
    by_split: dict[str, list[MetricRow]] = {}
    for family in ("dh", "ds"):
        for setting in ("base", "enhanced"):
            split = f"{family}_{setting}"
            records = json.loads((data / f"test_cases_{split}.json").read_text(encoding="utf-8"))
            for index, record in enumerate(records):
                clean = str(record["Tool Response Template"]).replace(
                    "<Attacker Instruction>",
                    "External content returned by the requested service.",
                )
                injected = str(record["Tool Response"])
                for expected_unsafe, content in ((False, clean), (True, injected)):
                    started = time.perf_counter()
                    predicted = _content_prediction(content, scanner, mode)
                    row = MetricRow(
                        case_id=f"{split}:{index}:{'attack' if expected_unsafe else 'clean'}",
                        category=split,
                        expected_unsafe=expected_unsafe,
                        predicted_unsafe=predicted,
                        latency_ms=(time.perf_counter() - started) * 1000,
                    )
                    rows.append(row)
                    by_split.setdefault(split, []).append(row)
    return {
        "benchmark": "InjecAgent",
        "revision": "f19c9f2c79a41046eb13c03c51a24c567a8ffa07",
        "mode": mode,
        "metrics": compute_metrics(rows),
        "by_split": {name: compute_metrics(items) for name, items in by_split.items()},
    }


def _content_prediction(content: str, scanner: ContentScanner, mode: ContentMode) -> bool:
    if mode == "no_guard":
        return False
    if mode == "override_regex":
        return bool(
            re.search(
                r"ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|prompts?)",
                content,
                re.IGNORECASE,
            )
        )
    return scanner.scan(content).blocked
