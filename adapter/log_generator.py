from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from adapter.inventory import write_inventory_payload


BLOCKED_REASON = "requires log benchmark mapping support not yet mapped"


@dataclass(frozen=True, slots=True)
class LogMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: str


@dataclass(frozen=True, slots=True)
class AutoLogInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str


def generate_upstream_log_templates(
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
        / "test_log.py"
    )
    templates, inventory = scan_log_cases(source)
    payload = {
        "name": "upstream-log-mapping-templates",
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
            family="log",
            name="upstream-log-auto-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload


def scan_log_cases(
    source_path: str | Path,
) -> tuple[tuple[LogMappingTemplate, ...], tuple[AutoLogInventoryEntry, ...]]:
    source = Path(source_path)
    text = source.read_text()
    inventory = sorted(
        _scan_test_log_cases(text) + _scan_test_log_benchmark_cases(text),
        key=lambda item: item.upstream_ref,
    )
    if len(inventory) != 140:
        raise ValueError(f"expected 140 log benchmark cases, found {len(inventory)}")
    return (), tuple(inventory)


def _scan_test_log_cases(text: str) -> list[AutoLogInventoryEntry]:
    block = _extract_param_block(text, function_name="test_log")
    opcodes = [
        match.group("opcode")
        for match in re.finditer(r"Op\.(?P<opcode>[A-Z0-9_]+)", block)
    ]
    size_entries = _extract_pytest_param_entries(block, "size,non_zero_data", function_name="test_log")
    zeros_topic_entries = _extract_pytest_param_entries(block, "zeros_topic", function_name="test_log")
    fixed_offset_values = [
        _parse_bool_literal(value)
        for value in _extract_param_values_from_block(block, "fixed_offset", function_name="test_log")
    ]
    results: list[AutoLogInventoryEntry] = []
    for opcode in opcodes:
        for _size_value, size_label in size_entries:
            size_slug = _slugify_label(size_label)
            for _zeros_topic_value, zeros_topic_label in zeros_topic_entries:
                zeros_topic_slug = _slugify_label(zeros_topic_label)
                for fixed_offset in fixed_offset_values:
                    fixed_slug = "true" if fixed_offset else "false"
                    upstream_ref = (
                        "tests/benchmark/compute/instruction/test_log.py::"
                        f"test_log[opcode={opcode}-size={size_label}-zeros_topic={zeros_topic_label}-fixed_offset={fixed_offset}]"
                    )
                    case_id = (
                        "upstream.benchmark.log.test_log."
                        f"{opcode.lower()}.size_{size_slug}.topic_{zeros_topic_slug}.fixed_offset_{fixed_slug}"
                    )
                    results.append(
                        AutoLogInventoryEntry(
                            upstream_ref=upstream_ref,
                            case_id=case_id,
                            admitted=False,
                            mode=None,
                            reasons=[BLOCKED_REASON],
                            source="test_log",
                        )
                    )
    if len(results) != 60:
        raise ValueError(f"expected 60 log test cases, found {len(results)}")
    return results


def _scan_test_log_benchmark_cases(text: str) -> list[AutoLogInventoryEntry]:
    block = _extract_param_block(text, function_name="test_log_benchmark")
    opcodes = [
        match.group("opcode")
        for match in re.finditer(r"Op\.(?P<opcode>[A-Z0-9_]+)", block)
    ]
    mem_sizes = [
        _parse_int_literal(value)
        for value in _extract_param_values_from_block(block, "mem_size", function_name="test_log_benchmark")
    ]
    log_sizes = [
        _parse_int_literal(value)
        for value in _extract_param_values_from_block(block, "log_size", function_name="test_log_benchmark")
    ]
    results: list[AutoLogInventoryEntry] = []
    for opcode in opcodes:
        for mem_size in mem_sizes:
            for log_size in log_sizes:
                upstream_ref = (
                    "tests/benchmark/compute/instruction/test_log.py::"
                    f"test_log_benchmark[opcode={opcode}-mem_size={mem_size}-log_size={log_size}]"
                )
                case_id = (
                    "upstream.benchmark.log.test_log_benchmark."
                    f"{opcode.lower()}.mem_size_{mem_size}.log_size_{log_size}"
                )
                results.append(
                    AutoLogInventoryEntry(
                        upstream_ref=upstream_ref,
                        case_id=case_id,
                        admitted=False,
                        mode=None,
                        reasons=[BLOCKED_REASON],
                        source="test_log_benchmark",
                    )
                )
    if len(results) != 80:
        raise ValueError(f"expected 80 log benchmark cases, found {len(results)}")
    return results


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


def _extract_pytest_param_entries(block: str, param_name: str, *, function_name: str) -> list[tuple[str, str]]:
    pattern = re.compile(
        rf'@pytest\.mark\.parametrize\(\s*"{re.escape(param_name)}",\s*\[(?P<values>.*?)\]\s*\)',
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(block)
    if not match:
        raise ValueError(f"could not find parameter block for {function_name} field {param_name}")
    values_block = match.group("values")
    entries: list[tuple[str, str]] = []
    if param_name == "size,non_zero_data":
        for param_match in re.finditer(
            r'pytest\.param\((?P<size>[^,]+),\s*(?P<non_zero_data>True|False),\s*id="(?P<label>[^"]+)"\)',
            values_block,
        ):
            entries.append((param_match.group("size").strip(), param_match.group("label")))
    elif param_name == "zeros_topic":
        for param_match in re.finditer(
            r'pytest\.param\((?P<value>True|False),\s*id="(?P<label>[^"]+)"\)',
            values_block,
        ):
            entries.append((param_match.group("value").strip(), param_match.group("label")))
    else:
        raise ValueError(f"unsupported pytest.param field for {function_name}: {param_name}")
    if not entries:
        raise ValueError(f"could not parse parameter entries for {function_name} field {param_name}")
    return entries


def _extract_param_values_from_block(block: str, param_name: str, *, function_name: str) -> list[str]:
    pattern = re.compile(
        rf'@pytest\.mark\.parametrize\(\s*"{re.escape(param_name)}",\s*\[(?P<values>.*?)\]\s*\)',
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(block)
    if not match:
        raise ValueError(f"could not find parameter block for {function_name} field {param_name}")
    values = match.group("values")
    return [value.strip() for value in values.split(",") if value.strip()]


def _parse_int_literal(value: str) -> int:
    normalized = value.replace("_", "").strip()
    if "*" in normalized:
        left, right = [part.strip() for part in normalized.split("*", 1)]
        return int(left) * int(right)
    return int(normalized)


def _parse_bool_literal(value: str) -> bool:
    normalized = value.strip()
    if normalized == "True":
        return True
    if normalized == "False":
        return False
    raise ValueError(f"unsupported bool literal: {value}")


def _slugify_label(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")
