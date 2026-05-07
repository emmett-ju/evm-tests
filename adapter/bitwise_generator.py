from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from adapter.inventory import write_inventory_payload


BLOCKED_REASON = "requires bitwise benchmark mapping support not yet mapped"


@dataclass(frozen=True, slots=True)
class BitwiseMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: str


@dataclass(frozen=True, slots=True)
class AutoBitwiseInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str


def generate_upstream_bitwise_templates(
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
        else repo_root_path / "third_party" / "execution-specs" / "tests" / "benchmark" / "compute" / "instruction" / "test_bitwise.py"
    )
    templates, inventory = scan_bitwise_cases(source)
    payload = {
        "name": "upstream-bitwise-mapping-templates",
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
            family="bitwise",
            name="upstream-bitwise-auto-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload


def scan_bitwise_cases(
    source_path: str | Path,
) -> tuple[tuple[BitwiseMappingTemplate, ...], tuple[AutoBitwiseInventoryEntry, ...]]:
    source = Path(source_path)
    text = source.read_text()
    inventory = sorted(
        _scan_test_bitwise_cases(text)
        + _scan_test_shifts_cases(text)
        + _scan_standalone_cases(text),
        key=lambda item: item.upstream_ref,
    )
    return (), tuple(inventory)


def _scan_test_bitwise_cases(text: str) -> list[AutoBitwiseInventoryEntry]:
    block = _extract_param_block(text, function_name="test_bitwise")
    opcodes = [
        match.group("opcode")
        for match in re.finditer(r"^\s*Op\.(?P<opcode>[A-Z0-9_]+),", block, re.MULTILINE)
    ]
    if len(opcodes) != 7:
        raise ValueError(f"expected 7 bitwise benchmark cases, found {len(opcodes)}")
    entries: list[AutoBitwiseInventoryEntry] = []
    for opcode in opcodes:
        upstream_ref = (
            "tests/benchmark/compute/instruction/test_bitwise.py::"
            f"test_bitwise[opcode={opcode}]"
        )
        case_id = f"upstream.benchmark.bitwise.test_bitwise.{opcode.lower()}"
        entries.append(
            AutoBitwiseInventoryEntry(
                upstream_ref=upstream_ref,
                case_id=case_id,
                admitted=False,
                mode=None,
                reasons=[BLOCKED_REASON],
                source="test_bitwise",
            )
        )
    return entries


def _scan_test_shifts_cases(text: str) -> list[AutoBitwiseInventoryEntry]:
    opcodes = _extract_param_values(
        text,
        r'@pytest\.mark\.parametrize\("opcode", \[(?P<values>[^\]]+)\]\)\ndef test_shifts',
    )
    entries: list[AutoBitwiseInventoryEntry] = []
    for opcode in [value.split(".")[-1] for value in opcodes]:
        upstream_ref = (
            "tests/benchmark/compute/instruction/test_bitwise.py::"
            f"test_shifts[opcode={opcode}]"
        )
        case_id = f"upstream.benchmark.bitwise.test_shifts.{opcode.lower()}"
        entries.append(
            AutoBitwiseInventoryEntry(
                upstream_ref=upstream_ref,
                case_id=case_id,
                admitted=False,
                mode=None,
                reasons=[BLOCKED_REASON],
                source="test_shifts",
            )
        )
    if len(entries) != 2:
        raise ValueError(f"expected 2 shift benchmark cases, found {len(entries)}")
    return entries


def _scan_standalone_cases(text: str) -> list[AutoBitwiseInventoryEntry]:
    function_names = ["test_not_op", "test_clz_same", "test_clz_diff"]
    entries: list[AutoBitwiseInventoryEntry] = []
    for function_name in function_names:
        if f"def {function_name}(" not in text:
            raise ValueError(f"could not find benchmark function {function_name}")
        upstream_ref = f"tests/benchmark/compute/instruction/test_bitwise.py::{function_name}"
        case_id = f"upstream.benchmark.bitwise.{function_name}"
        entries.append(
            AutoBitwiseInventoryEntry(
                upstream_ref=upstream_ref,
                case_id=case_id,
                admitted=False,
                mode=None,
                reasons=[BLOCKED_REASON],
                source=function_name,
            )
        )
    return entries


def _extract_param_block(text: str, *, function_name: str) -> str:
    func_marker = f"def {function_name}("
    func = text.find(func_marker)
    if func == -1:
        raise ValueError(f"could not find benchmark function {function_name}")
    param_start = text.rfind("@pytest.mark.parametrize(", 0, func)
    if param_start == -1:
        raise ValueError(f"could not find parameter block for {function_name}")
    return text[param_start:func]


def _extract_param_values(text: str, pattern: str) -> list[str]:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise ValueError(f"could not match pattern: {pattern}")
    return [value.strip() for value in match.group("values").split(",") if value.strip()]
