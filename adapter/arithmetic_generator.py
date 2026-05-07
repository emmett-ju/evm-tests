from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from adapter.inventory import write_inventory_payload


BLOCKED_REASON = "requires arithmetic benchmark mapping support not yet mapped"


@dataclass(frozen=True, slots=True)
class ArithmeticMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: str


@dataclass(frozen=True, slots=True)
class AutoArithmeticInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str


def generate_upstream_arithmetic_templates(
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
        else repo_root_path / "third_party" / "execution-specs" / "tests" / "benchmark" / "compute" / "instruction" / "test_arithmetic.py"
    )
    templates, inventory = scan_arithmetic_cases(source)
    payload = {
        "name": "upstream-arithmetic-mapping-templates",
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
            family="arithmetic",
            name="upstream-arithmetic-auto-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload


def scan_arithmetic_cases(
    source_path: str | Path,
) -> tuple[tuple[ArithmeticMappingTemplate, ...], tuple[AutoArithmeticInventoryEntry, ...]]:
    source = Path(source_path)
    text = source.read_text()
    inventory = sorted(
        _scan_test_arithmetic_cases(text)
        + _scan_test_mod_cases(text)
        + _scan_test_mod_arithmetic_cases(text)
        + _scan_test_exp_bench_cases(text),
        key=lambda item: item.upstream_ref,
    )
    return (), tuple(inventory)


def _scan_test_arithmetic_cases(text: str) -> list[AutoArithmeticInventoryEntry]:
    block = _extract_param_block(text, function_name="test_arithmetic")
    opcodes = [
        match.group("opcode")
        for match in re.finditer(r"^\s*Op\.(?P<opcode>[A-Z0-9_]+),", block, re.MULTILINE)
    ]
    if len(opcodes) != 13:
        raise ValueError(f"expected 13 arithmetic benchmark cases, found {len(opcodes)}")
    entries: list[AutoArithmeticInventoryEntry] = []
    ordinal_by_opcode: dict[str, int] = {}
    for opcode in opcodes:
        arg_arity = 3 if opcode in {"ADDMOD", "MULMOD"} else 2
        ordinal = ordinal_by_opcode.get(opcode, 0)
        ordinal_by_opcode[opcode] = ordinal + 1
        suffix = f"variant_{ordinal}" if ordinal else "base"
        upstream_ref = (
            "tests/benchmark/compute/instruction/test_arithmetic.py::"
            f"test_arithmetic[opcode={opcode}-variant={suffix}]"
        )
        case_id = f"upstream.benchmark.arithmetic.test_arithmetic.{opcode.lower()}.{suffix}.arity_{arg_arity}"
        entries.append(
            AutoArithmeticInventoryEntry(
                upstream_ref=upstream_ref,
                case_id=case_id,
                admitted=False,
                mode=None,
                reasons=[BLOCKED_REASON],
                source="test_arithmetic",
            )
        )
    return entries


def _scan_test_mod_cases(text: str) -> list[AutoArithmeticInventoryEntry]:
    mod_bits = _extract_param_values(
        text,
        r'@pytest\.mark\.parametrize\("mod_bits", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("opcode", \[(?P<values2>[^\]]+)\]\)\n@pytest\.mark\.repricing\ndef test_mod',
        group="values",
    )
    opcodes = _extract_param_values(
        text,
        r'@pytest\.mark\.parametrize\("mod_bits", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("opcode", \[(?P<values2>[^\]]+)\]\)\n@pytest\.mark\.repricing\ndef test_mod',
        group="values2",
    )
    entries: list[AutoArithmeticInventoryEntry] = []
    for opcode in [value.split(".")[-1] for value in opcodes]:
        for mod_bit in [_parse_int_literal(value) for value in mod_bits]:
            upstream_ref = (
                "tests/benchmark/compute/instruction/test_arithmetic.py::"
                f"test_mod[opcode={opcode}-mod_bits={mod_bit}]"
            )
            case_id = f"upstream.benchmark.arithmetic.test_mod.{opcode.lower()}.mod_bits_{mod_bit}"
            entries.append(
                AutoArithmeticInventoryEntry(
                    upstream_ref=upstream_ref,
                    case_id=case_id,
                    admitted=False,
                    mode=None,
                    reasons=[BLOCKED_REASON],
                    source="test_mod",
                )
            )
    if len(entries) != 8:
        raise ValueError(f"expected 8 mod benchmark cases, found {len(entries)}")
    return entries


def _scan_test_mod_arithmetic_cases(text: str) -> list[AutoArithmeticInventoryEntry]:
    mod_bits = _extract_param_values(
        text,
        r'@pytest\.mark\.repricing\(mod_bits=191\)\n@pytest\.mark\.parametrize\("mod_bits", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("opcode", \[(?P<values2>[^\]]+)\]\)\ndef test_mod_arithmetic',
        group="values",
    )
    opcodes = _extract_param_values(
        text,
        r'@pytest\.mark\.repricing\(mod_bits=191\)\n@pytest\.mark\.parametrize\("mod_bits", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("opcode", \[(?P<values2>[^\]]+)\]\)\ndef test_mod_arithmetic',
        group="values2",
    )
    entries: list[AutoArithmeticInventoryEntry] = []
    for opcode in [value.split(".")[-1] for value in opcodes]:
        for mod_bit in [_parse_int_literal(value) for value in mod_bits]:
            upstream_ref = (
                "tests/benchmark/compute/instruction/test_arithmetic.py::"
                f"test_mod_arithmetic[opcode={opcode}-mod_bits={mod_bit}]"
            )
            case_id = f"upstream.benchmark.arithmetic.test_mod_arithmetic.{opcode.lower()}.mod_bits_{mod_bit}"
            entries.append(
                AutoArithmeticInventoryEntry(
                    upstream_ref=upstream_ref,
                    case_id=case_id,
                    admitted=False,
                    mode=None,
                    reasons=[BLOCKED_REASON],
                    source="test_mod_arithmetic",
                )
            )
    if len(entries) != 8:
        raise ValueError(f"expected 8 mod_arithmetic benchmark cases, found {len(entries)}")
    return entries


def _scan_test_exp_bench_cases(text: str) -> list[AutoArithmeticInventoryEntry]:
    bases = _extract_param_values(
        text,
        r'@pytest\.mark\.parametrize\("base", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("exp", \[(?P<values2>[^\]]+)\]\)\ndef test_exp_bench_arithmetic',
        group="values",
    )
    exponents = _extract_param_values(
        text,
        r'@pytest\.mark\.parametrize\("base", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("exp", \[(?P<values2>[^\]]+)\]\)\ndef test_exp_bench_arithmetic',
        group="values2",
    )
    entries: list[AutoArithmeticInventoryEntry] = []
    for exp in [_parse_int_literal(value) for value in exponents]:
        for base in [_parse_int_literal(value) for value in bases]:
            upstream_ref = (
                "tests/benchmark/compute/instruction/test_arithmetic.py::"
                f"test_exp_bench_arithmetic[exp={exp}-base={base}]"
            )
            case_id = f"upstream.benchmark.arithmetic.test_exp_bench_arithmetic.exp_{exp}.base_{base}"
            entries.append(
                AutoArithmeticInventoryEntry(
                    upstream_ref=upstream_ref,
                    case_id=case_id,
                    admitted=False,
                    mode=None,
                    reasons=[BLOCKED_REASON],
                    source="test_exp_bench_arithmetic",
                )
            )
    if len(entries) != 36:
        raise ValueError(f"expected 36 exp benchmark cases, found {len(entries)}")
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


def _extract_param_values(text: str, pattern: str, *, group: str = "values") -> list[str]:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise ValueError(f"could not match pattern: {pattern}")
    values = match.group(group)
    return [value.strip() for value in values.split(",") if value.strip()]


def _parse_int_literal(value: str) -> int:
    normalized = value.replace("_", "").strip()
    if "*" in normalized:
        left, right = [part.strip() for part in normalized.split("*", 1)]
        return int(left) * int(right)
    return int(normalized)
