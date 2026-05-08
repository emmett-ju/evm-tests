from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from adapter.inventory import write_inventory_payload


BLOCKED_REASON = "requires system benchmark mapping support not yet mapped"


@dataclass(frozen=True, slots=True)
class SystemMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: str


@dataclass(frozen=True, slots=True)
class AutoSystemInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str


def generate_upstream_system_templates(
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
        / "test_system.py"
    )
    templates, inventory = scan_system_cases(source)
    payload = {
        "name": "upstream-system-mapping-templates",
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
            family="system",
            name="upstream-system-auto-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload


def scan_system_cases(
    source_path: str | Path,
) -> tuple[tuple[SystemMappingTemplate, ...], tuple[AutoSystemInventoryEntry, ...]]:
    source = Path(source_path)
    text = source.read_text()
    inventory = sorted(
        _scan_contract_calling_many_addresses(text)
        + _scan_create(text)
        + _scan_creates_collisions(text)
        + _scan_return_revert(text)
        + _scan_selfdestruct_existing(text)
        + _scan_selfdestruct_created(text)
        + _scan_selfdestruct_initcode(text),
        key=lambda item: item.upstream_ref,
    )
    if len(inventory) != 46:
        raise ValueError(f"expected 46 system benchmark cases, found {len(inventory)}")
    return (), tuple(inventory)


def _scan_contract_calling_many_addresses(text: str) -> list[AutoSystemInventoryEntry]:
    block = _extract_param_block(text, function_name="test_contract_calling_many_addresses")
    transfer_amounts = [_parse_int_literal(value) for value in _extract_param_values_from_block(block, "transfer_amount", function_name="test_contract_calling_many_addresses")]
    opcodes = [value.split(".")[-1] for value in _extract_param_values_from_block(block, "opcode", function_name="test_contract_calling_many_addresses")]
    access_warm_values = [_parse_bool_literal(value) for value in _extract_param_values_from_block(block, "access_warm", function_name="test_contract_calling_many_addresses")]
    results: list[AutoSystemInventoryEntry] = []
    for transfer_amount in transfer_amounts:
        for opcode in opcodes:
            for access_warm in access_warm_values:
                access_slug = "warm" if access_warm else "cold"
                upstream_ref = (
                    "tests/benchmark/compute/instruction/test_system.py::"
                    f"test_contract_calling_many_addresses[transfer_amount={transfer_amount}-opcode={opcode}-access_warm={access_warm}]"
                )
                case_id = (
                    "upstream.benchmark.system.test_contract_calling_many_addresses."
                    f"{opcode.lower()}.transfer_amount_{transfer_amount}.{access_slug}"
                )
                results.append(
                    AutoSystemInventoryEntry(
                        upstream_ref=upstream_ref,
                        case_id=case_id,
                        admitted=False,
                        mode=None,
                        reasons=[BLOCKED_REASON],
                        source="test_contract_calling_many_addresses",
                    )
                )
    return results


def _scan_create(text: str) -> list[AutoSystemInventoryEntry]:
    block = _extract_param_block(text, function_name="test_create")
    opcodes = [value.split(".")[-1] for value in _extract_param_values_from_block(block, "opcode", function_name="test_create")]
    combo_labels = [match.group("label") for match in re.finditer(r'id="(?P<label>[^"]+)"', block)]
    if len(combo_labels) != 10:
        raise ValueError(f"expected 10 create benchmark combinations, found {len(combo_labels)}")
    results: list[AutoSystemInventoryEntry] = []
    for opcode in opcodes:
        for combo_label in combo_labels:
            combo_slug = _slugify_label(combo_label)
            upstream_ref = (
                "tests/benchmark/compute/instruction/test_system.py::"
                f"test_create[opcode={opcode}-variant={combo_label}]"
            )
            case_id = f"upstream.benchmark.system.test_create.{opcode.lower()}.{combo_slug}"
            results.append(
                AutoSystemInventoryEntry(
                    upstream_ref=upstream_ref,
                    case_id=case_id,
                    admitted=False,
                    mode=None,
                    reasons=[BLOCKED_REASON],
                    source="test_create",
                )
            )
    return results


def _scan_creates_collisions(text: str) -> list[AutoSystemInventoryEntry]:
    block = _extract_param_block(text, function_name="test_creates_collisions")
    opcodes = [value.split(".")[-1] for value in _extract_param_values_from_block(block, "opcode", function_name="test_creates_collisions")]
    return [
        AutoSystemInventoryEntry(
            upstream_ref=f"tests/benchmark/compute/instruction/test_system.py::test_creates_collisions[opcode={opcode}]",
            case_id=f"upstream.benchmark.system.test_creates_collisions.{opcode.lower()}",
            admitted=False,
            mode=None,
            reasons=[BLOCKED_REASON],
            source="test_creates_collisions",
        )
        for opcode in opcodes
    ]


def _scan_return_revert(text: str) -> list[AutoSystemInventoryEntry]:
    block = _extract_param_block(text, function_name="test_return_revert")
    opcodes = [value.split(".")[-1] for value in _extract_param_values_from_block(block, "opcode", function_name="test_return_revert")]
    combo_labels = [match.group("label") for match in re.finditer(r'id="(?P<label>[^"]+)"', block)]
    if len(combo_labels) != 5:
        raise ValueError(f"expected 5 return/revert benchmark combinations, found {len(combo_labels)}")
    results: list[AutoSystemInventoryEntry] = []
    for opcode in opcodes:
        for combo_label in combo_labels:
            combo_slug = _slugify_label(combo_label)
            upstream_ref = (
                "tests/benchmark/compute/instruction/test_system.py::"
                f"test_return_revert[opcode={opcode}-variant={combo_label}]"
            )
            case_id = f"upstream.benchmark.system.test_return_revert.{opcode.lower()}.{combo_slug}"
            results.append(
                AutoSystemInventoryEntry(
                    upstream_ref=upstream_ref,
                    case_id=case_id,
                    admitted=False,
                    mode=None,
                    reasons=[BLOCKED_REASON],
                    source="test_return_revert",
                )
            )
    return results


def _scan_selfdestruct_existing(text: str) -> list[AutoSystemInventoryEntry]:
    return _scan_value_bearing_cases(text, function_name="test_selfdestruct_existing")


def _scan_selfdestruct_created(text: str) -> list[AutoSystemInventoryEntry]:
    return _scan_value_bearing_cases(text, function_name="test_selfdestruct_created")


def _scan_selfdestruct_initcode(text: str) -> list[AutoSystemInventoryEntry]:
    return _scan_value_bearing_cases(text, function_name="test_selfdestruct_initcode")


def _scan_value_bearing_cases(text: str, *, function_name: str) -> list[AutoSystemInventoryEntry]:
    block = _extract_param_block(text, function_name=function_name)
    values = [_parse_bool_literal(value) for value in _extract_param_values_from_block(block, "value_bearing", function_name=function_name)]
    return [
        AutoSystemInventoryEntry(
            upstream_ref=f"tests/benchmark/compute/instruction/test_system.py::{function_name}[value_bearing={value}]",
            case_id=f"upstream.benchmark.system.{function_name}.value_bearing_{str(value).lower()}",
            admitted=False,
            mode=None,
            reasons=[BLOCKED_REASON],
            source=function_name,
        )
        for value in values
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


def _extract_param_values_from_block(block: str, param_name: str, *, function_name: str) -> list[str]:
    pattern = re.compile(
        rf'@pytest\.mark\.parametrize\(\s*"{re.escape(param_name)}",\s*\[(?P<values>.*?)\]\s*(?:,?\s*)\)',
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
    return int(float(normalized))


def _parse_bool_literal(value: str) -> bool:
    normalized = value.strip()
    if normalized == "True":
        return True
    if normalized == "False":
        return False
    raise ValueError(f"unsupported bool literal: {value}")


def _slugify_label(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")
