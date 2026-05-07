from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from adapter.inventory import write_inventory_payload


BLOCKED_REASON = "requires comparison benchmark mapping support not yet mapped"


@dataclass(frozen=True, slots=True)
class ComparisonMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: str


@dataclass(frozen=True, slots=True)
class AutoComparisonInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str


def generate_upstream_comparison_templates(
    *,
    repo_root: str | Path,
    source_path: str | Path | None = None,
    output_path: str | Path | None = None,
    inventory_path: str | Path | None = None,
) -> dict[str, Any]:
    if output_path is None and inventory_path is None:
        raise ValueError("at least one of output_path or inventory_path is required")
    repo_root_path = Path(repo_root).resolve()
    source = (
        Path(source_path).resolve()
        if source_path is not None
        else repo_root_path / "third_party" / "execution-specs" / "tests" / "benchmark" / "compute" / "instruction" / "test_comparison.py"
    )
    templates, inventory = scan_comparison_cases(source)
    payload = {
        "name": "upstream-comparison-mapping-templates",
        "version": "1",
        "source": str(source.relative_to(repo_root_path)) if source.is_relative_to(repo_root_path) else str(source),
        "cases": [asdict(template) for template in templates],
    }
    if output_path is not None:
        output = Path(output_path).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2) + "\n")
    if inventory_path is not None:
        write_inventory_payload(
            inventory_path,
            family="comparison",
            name="upstream-comparison-auto-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload


def scan_comparison_cases(
    source_path: str | Path,
) -> tuple[tuple[ComparisonMappingTemplate, ...], tuple[AutoComparisonInventoryEntry, ...]]:
    source = Path(source_path)
    text = source.read_text()
    inventory = sorted(
        _scan_test_comparison_cases(text) + _scan_standalone_cases(text),
        key=lambda item: item.upstream_ref,
    )
    return (), tuple(inventory)


def _scan_test_comparison_cases(text: str) -> list[AutoComparisonInventoryEntry]:
    block = _extract_param_block(text, function_name="test_comparison")
    opcodes = [
        match.group("opcode")
        for match in re.finditer(r"^\s*Op\.(?P<opcode>[A-Z0-9_]+),", block, re.MULTILINE)
    ]
    if len(opcodes) != 5:
        raise ValueError(f"expected 5 comparison benchmark cases, found {len(opcodes)}")
    entries: list[AutoComparisonInventoryEntry] = []
    for opcode in opcodes:
        upstream_ref = (
            "tests/benchmark/compute/instruction/test_comparison.py::"
            f"test_comparison[opcode={opcode}]"
        )
        case_id = f"upstream.benchmark.comparison.test_comparison.{opcode.lower()}"
        entries.append(
            AutoComparisonInventoryEntry(
                upstream_ref=upstream_ref,
                case_id=case_id,
                admitted=False,
                mode=None,
                reasons=[BLOCKED_REASON],
                source="test_comparison",
            )
        )
    return entries


def _scan_standalone_cases(text: str) -> list[AutoComparisonInventoryEntry]:
    function_name = "test_iszero"
    if f"def {function_name}(" not in text:
        raise ValueError(f"could not find benchmark function {function_name}")
    return [
        AutoComparisonInventoryEntry(
            upstream_ref=f"tests/benchmark/compute/instruction/test_comparison.py::{function_name}",
            case_id=f"upstream.benchmark.comparison.{function_name}",
            admitted=False,
            mode=None,
            reasons=[BLOCKED_REASON],
            source=function_name,
        )
    ]


def _extract_param_block(text: str, *, function_name: str) -> str:
    func_marker = f"def {function_name}("
    func = text.find(func_marker)
    if func == -1:
        raise ValueError(f"could not find benchmark function {function_name}")
    param_start = text.rfind("@pytest.mark.parametrize(", 0, func)
    if param_start == -1:
        raise ValueError(f"could not find parameter block for {function_name}")
    return text[param_start:func]
