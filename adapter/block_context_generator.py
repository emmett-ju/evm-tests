from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from adapter.inventory import write_inventory_payload


BLOCKHASH_BLOCKED_REASON = "requires block environment control"
BLOCK_CONTEXT_BLOCKED_REASON = "requires block-context benchmark mapping support not yet mapped"


@dataclass(frozen=True, slots=True)
class BlockContextMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: str


@dataclass(frozen=True, slots=True)
class AutoBlockContextInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str


def generate_upstream_block_context_templates(
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
        else repo_root_path
        / "third_party"
        / "execution-specs"
        / "tests"
        / "benchmark"
        / "compute"
        / "instruction"
        / "test_block_context.py"
    )
    templates, inventory = scan_block_context_cases(source)
    payload = {
        "name": "upstream-block-context-mapping-templates",
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
            family="block-context",
            name="upstream-block-context-auto-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload


def scan_block_context_cases(
    source_path: str | Path,
) -> tuple[tuple[BlockContextMappingTemplate, ...], tuple[AutoBlockContextInventoryEntry, ...]]:
    source = Path(source_path)
    text = source.read_text()
    inventory = sorted(
        _scan_zero_param_cases(text) + _scan_blockhash_cases(text),
        key=lambda item: item.upstream_ref,
    )
    if len(inventory) != 13:
        raise ValueError(f"expected 13 block-context benchmark cases, found {len(inventory)}")
    return (), tuple(inventory)


def _scan_zero_param_cases(text: str) -> list[AutoBlockContextInventoryEntry]:
    values = _extract_param_values(
        text,
        r'@pytest\.mark\.parametrize\(\s*"opcode",\s*\[(?P<values>[^\]]+)\]\s*,?\s*\)\s*def test_block_context_ops',
    )
    results: list[AutoBlockContextInventoryEntry] = []
    for opcode in [value.split(".")[-1] for value in values]:
        results.append(
            AutoBlockContextInventoryEntry(
                upstream_ref=f"tests/benchmark/compute/instruction/test_block_context.py::test_block_context_ops[opcode={opcode}]",
                case_id=f"upstream.benchmark.block_context.test_block_context_ops.{opcode.lower()}",
                admitted=False,
                mode=None,
                reasons=[BLOCK_CONTEXT_BLOCKED_REASON],
                source="test_block_context_ops",
            )
        )
    return results


def _scan_blockhash_cases(text: str) -> list[AutoBlockContextInventoryEntry]:
    block = _extract_param_block(text, function_name="test_blockhash")
    labels = [match.group("label") for match in re.finditer(r'id="(?P<label>[^"]+)"', block)]
    if len(labels) != 5:
        raise ValueError(f"expected 5 blockhash benchmark cases, found {len(labels)}")
    return [
        AutoBlockContextInventoryEntry(
            upstream_ref=f"tests/benchmark/compute/instruction/test_block_context.py::test_blockhash[index={label}]",
            case_id=f"upstream.benchmark.block_context.test_blockhash.{label}",
            admitted=False,
            mode=None,
            reasons=[BLOCKHASH_BLOCKED_REASON],
            source="test_blockhash",
        )
        for label in labels
    ]


def _extract_param_block(text: str, *, function_name: str) -> str:
    func_marker = f"def {function_name}("
    func = text.find(func_marker)
    if func == -1:
        raise ValueError(f"could not find benchmark function {function_name}")
    start = text.rfind("\n\n", 0, func)
    if start == -1:
        start = 0
    else:
        start += 2
    block = text[start:func]
    if "@pytest.mark.parametrize(" not in block:
        raise ValueError(f"could not find parameter block for {function_name}")
    return block


def _extract_param_values(text: str, pattern: str) -> list[str]:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise ValueError(f"could not match pattern: {pattern}")
    return [value.strip() for value in match.group("values").split(",") if value.strip()]
