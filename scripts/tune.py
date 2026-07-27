from __future__ import annotations

import argparse
import asyncio
import itertools
import json
from pathlib import Path

from agentgate.config import AgentGateSettings
from agentgate.evaluation import evaluate_dataset

DEFAULT_DATASET = Path("benchmarks/agentgatebench/cases.jsonl")
DEFAULT_OUTPUT = Path("artifacts/results/tuning.json")


async def tune(dataset: Path, output: Path) -> None:
    candidates = []
    for integrity_severity, personal_budget, external_budget in itertools.product(
        (7, 8, 9), (2, 10, 20), (1, 2)
    ):
        settings = AgentGateSettings(
            integrity_block_severity=integrity_severity,
            personal_record_budget=personal_budget,
            external_transmission_budget=external_budget,
        )
        report = await evaluate_dataset(dataset, split="dev", settings=settings)
        metrics = report.metrics
        objective = float(metrics["f1"]) - float(metrics["false_positive_rate"])
        candidates.append(
            {
                "objective": objective,
                "integrity_block_severity": integrity_severity,
                "personal_record_budget": personal_budget,
                "external_transmission_budget": external_budget,
                "metrics": metrics,
            }
        )
    candidates.sort(key=lambda item: item["objective"], reverse=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(candidates, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(candidates[:5], indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tune AgentGate thresholds on a dev split")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    asyncio.run(tune(args.dataset, args.output))
