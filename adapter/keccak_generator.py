from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from adapter.inventory import write_inventory_payload


BLOCKED_REASON = "requires keccak benchmark mapping support not yet mapped"


@dataclass(frozen=True, slots=True)
class KeccakMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: str


@dataclass(frozen=True, slots=True)
class AutoKeccakInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str


def generate_upstream_keccak_templates(
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
        / "test_keccak.py"
    )
    templates, inventory = scan_keccak_cases(source)
    payload = {
        "name": "upstream-keccak-mapping-templates",
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
            family="keccak",
            name="upstream-keccak-auto-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload


def scan_keccak_cases(
    source_path: str | Path,
) -> tuple[tuple[KeccakMappingTemplate, ...], tuple[AutoKeccakInventoryEntry, ...]]:
    source = Path(source_path)
    text = source.read_text()
    inventory = sorted(
        _scan_max_permutations_case(text)
        + _scan_test_keccak_cases(text)
        + _scan_diff_mem_msg_sizes_cases(text),
        key=lambda item: item.upstream_ref,
    )
    if len(inventory) != 35:
        raise ValueError(f"expected 35 keccak benchmark cases, found {len(inventory)}")
    return (), tuple(inventory)


def _scan_max_permutations_case(text: str) -> list[AutoKeccakInventoryEntry]:
    _require_function(text, "test_keccak_max_permutations")
    return [
        AutoKeccakInventoryEntry(
            upstream_ref="tests/benchmark/compute/instruction/test_keccak.py::test_keccak_max_permutations",
            case_id="upstream.benchmark.keccak.test_keccak_max_permutations",
            admitted=False,
            mode=None,
            reasons=[BLOCKED_REASON],
            source="test_keccak_max_permutations",
        )
    ]


def _scan_test_keccak_cases(text: str) -> list[AutoKeccakInventoryEntry]:
    mem_alloc_entries = _extract_pytest_param_entries(text, function_name="test_keccak", param_name="mem_alloc")
    offsets = [
        _parse_int_literal(value)
        for value in _extract_param_values(
            text,
            r'@pytest\.mark\.parametrize\("offset", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("mem_update", \[(?P<values2>[^\]]+)\]\)\ndef test_keccak',
            group="values",
        )
    ]
    mem_updates = [
        _parse_bool_literal(value)
        for value in _extract_param_values(
            text,
            r'@pytest\.mark\.parametrize\("offset", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("mem_update", \[(?P<values2>[^\]]+)\]\)\ndef test_keccak',
            group="values2",
        )
    ]
    results: list[AutoKeccakInventoryEntry] = []
    for mem_alloc_value, mem_alloc_label in mem_alloc_entries:
        mem_alloc_slug = _slugify_label(mem_alloc_label)
        for offset in offsets:
            for mem_update in mem_updates:
                mem_update_slug = "true" if mem_update else "false"
                upstream_ref = (
                    "tests/benchmark/compute/instruction/test_keccak.py::"
                    f"test_keccak[mem_alloc={mem_alloc_label}-offset={offset}-mem_update={mem_update}]"
                )
                case_id = (
                    "upstream.benchmark.keccak.test_keccak."
                    f"mem_alloc_{mem_alloc_slug}.offset_{offset}.mem_update_{mem_update_slug}"
                )
                results.append(
                    AutoKeccakInventoryEntry(
                        upstream_ref=upstream_ref,
                        case_id=case_id,
                        admitted=False,
                        mode=None,
                        reasons=[BLOCKED_REASON],
                        source="test_keccak",
                    )
                )
    if len(results) != 18:
        raise ValueError(f"expected 18 keccak parameterized cases, found {len(results)}")
    return results


def _scan_diff_mem_msg_sizes_cases(text: str) -> list[AutoKeccakInventoryEntry]:
    _require_function(text, "test_keccak_diff_mem_msg_sizes")
    mem_sizes = [
        _parse_int_literal(value)
        for value in _extract_param_values(
            text,
            r'@pytest\.mark\.parametrize\("mem_size", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("msg_size", \[(?P<values2>[^\]]+)\]\)\ndef test_keccak_diff_mem_msg_sizes',
            group="values",
        )
    ]
    msg_sizes = [
        _parse_int_literal(value)
        for value in _extract_param_values(
            text,
            r'@pytest\.mark\.parametrize\("mem_size", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("msg_size", \[(?P<values2>[^\]]+)\]\)\ndef test_keccak_diff_mem_msg_sizes',
            group="values2",
        )
    ]
    results: list[AutoKeccakInventoryEntry] = []
    for mem_size in mem_sizes:
        for msg_size in msg_sizes:
            results.append(
                AutoKeccakInventoryEntry(
                    upstream_ref=(
                        "tests/benchmark/compute/instruction/test_keccak.py::"
                        f"test_keccak_diff_mem_msg_sizes[mem_size={mem_size}-msg_size={msg_size}]"
                    ),
                    case_id=(
                        "upstream.benchmark.keccak.test_keccak_diff_mem_msg_sizes."
                        f"mem_size_{mem_size}.msg_size_{msg_size}"
                    ),
                    admitted=False,
                    mode=None,
                    reasons=[BLOCKED_REASON],
                    source="test_keccak_diff_mem_msg_sizes",
                )
            )
    if len(results) != 16:
        raise ValueError(f"expected 16 keccak diff mem/msg cases, found {len(results)}")
    return results


def _require_function(text: str, function_name: str) -> None:
    if f"def {function_name}(" not in text:
        raise ValueError(f"could not find benchmark function {function_name}")


def _extract_param_values(text: str, pattern: str, *, group: str = "values") -> list[str]:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise ValueError(f"could not match pattern: {pattern}")
    return [value.strip() for value in match.group(group).split(",") if value.strip()]


def _extract_pytest_param_entries(text: str, *, function_name: str, param_name: str) -> list[tuple[str, str]]:
    func_marker = f"def {function_name}("
    func = text.find(func_marker)
    if func == -1:
        raise ValueError(f"could not find benchmark function {function_name}")
    prefix = text[:func]
    pattern = re.compile(
        rf'@pytest\.mark\.parametrize\(\s*"{re.escape(param_name)}",\s*\[(?P<values>.*?)\]\s*\)',
        re.MULTILINE | re.DOTALL,
    )
    matches = list(pattern.finditer(prefix))
    if not matches:
        raise ValueError(f"could not find parameter block for {function_name} field {param_name}")
    values_block = matches[-1].group("values")
    entries: list[tuple[str, str]] = []
    if "pytest.param" in values_block:
        for param_match in re.finditer(
            r'pytest\.param\((?P<value>b"[^"]*"),\s*id="(?P<label>[^"]+)"\)',
            values_block,
        ):
            entries.append((param_match.group("value"), param_match.group("label")))
    else:
        raw_values = [value.strip() for value in values_block.split(",") if value.strip()]
        for raw in raw_values:
            label = raw.removeprefix('b"').removesuffix('"') or "empty"
            entries.append((raw, label))
    if not entries:
        raise ValueError(f"could not parse pytest.param entries for {function_name} field {param_name}")
    return entries


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
