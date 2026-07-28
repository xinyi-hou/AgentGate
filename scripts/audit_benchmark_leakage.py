from __future__ import annotations

import argparse
import ast
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BENCHMARKS = (
    ROOT / "benchmarks" / "agentgatebench",
    ROOT / "benchmarks" / "external" / "toolsafe" / "TS-Bench",
)
TASK_FIELDS = {
    "content",
    "goal",
    "instruction",
    "prompt",
    "request",
    "task",
    "user_task",
}
MIN_TOKENS = 5
MIN_CHARACTERS = 24


@dataclass(frozen=True)
class ProductionPhrase:
    path: Path
    line: int
    phrase: str
    normalized: str


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Detect benchmark task phrases copied into production Python strings."
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=ROOT / "src" / "agentgate",
        help="production Python tree to inspect",
    )
    parser.add_argument(
        "--benchmark",
        action="append",
        type=Path,
        help="benchmark file or directory; may be repeated",
    )
    return parser


def main() -> None:
    args = _parser().parse_args()
    benchmark_paths = tuple(args.benchmark or DEFAULT_BENCHMARKS)
    phrases = list(_production_phrases(args.source))
    task_texts = set(_benchmark_task_texts(benchmark_paths))
    matches = [
        (phrase, task)
        for phrase in phrases
        for task in task_texts
        if _contains_phrase(task, phrase.normalized)
    ]
    if matches:
        for phrase, task in matches[:50]:
            relative = phrase.path.relative_to(ROOT)
            print(f"{relative}:{phrase.line}: {phrase.phrase!r}")
            print(f"  benchmark text: {task[:240]!r}")
        raise SystemExit(
            f"Found {len(matches)} production phrase(s) copied from benchmark task text."
        )
    print(
        f"No copied task phrases found across {len(phrases)} production strings "
        f"and {len(task_texts)} unique benchmark texts."
    )


def _production_phrases(source: Path) -> Iterator[ProductionPhrase]:
    for path in sorted(source.rglob("*.py")):
        if "evaluation" in path.relative_to(source).parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        docstrings = _docstring_nodes(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            if id(node) in docstrings:
                continue
            for fragment in re.split(r"[|\n]", node.value):
                normalized = _normalize(fragment)
                if _eligible(normalized):
                    yield ProductionPhrase(path, node.lineno, fragment.strip(), normalized)


def _docstring_nodes(tree: ast.AST) -> set[int]:
    nodes: set[int] = set()
    for owner in ast.walk(tree):
        if not isinstance(owner, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not owner.body or not isinstance(owner.body[0], ast.Expr):
            continue
        value = owner.body[0].value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            nodes.add(id(value))
    return nodes


def _benchmark_task_texts(paths: tuple[Path, ...]) -> Iterator[str]:
    for path in _data_files(paths):
        try:
            if path.suffix == ".jsonl":
                records = (json.loads(line) for line in path.read_text().splitlines() if line)
                for record in records:
                    yield from _task_values(record)
            else:
                yield from _task_values(json.loads(path.read_text()))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Cannot parse benchmark data {path}: {exc}") from exc


def _data_files(paths: tuple[Path, ...]) -> Iterator[Path]:
    for path in paths:
        if not path.exists():
            continue
        if path.is_file() and path.suffix in {".json", ".jsonl"}:
            yield path
        elif path.is_dir():
            yield from sorted(
                candidate
                for candidate in path.rglob("*")
                if candidate.is_file()
                and candidate.suffix in {".json", ".jsonl"}
                and ".git" not in candidate.parts
            )


def _task_values(value: object, key: str | None = None) -> Iterator[str]:
    if isinstance(value, dict):
        for child_key, child in value.items():
            yield from _task_values(child, str(child_key).lower())
    elif isinstance(value, list):
        for child in value:
            yield from _task_values(child, key)
    elif isinstance(value, str) and key in TASK_FIELDS:
        normalized = _normalize(value)
        if _eligible(normalized):
            yield normalized


def _normalize(value: str) -> str:
    value = re.sub(r"\\[AbBdDsSwWZ]", " ", value)
    return " ".join(re.findall(r"[a-z0-9]+", value.lower()))


def _eligible(value: str) -> bool:
    return len(value) >= MIN_CHARACTERS and len(value.split()) >= MIN_TOKENS


def _contains_phrase(task: str, phrase: str) -> bool:
    return f" {phrase} " in f" {task} "


if __name__ == "__main__":
    main()
