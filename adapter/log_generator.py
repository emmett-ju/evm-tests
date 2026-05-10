from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from adapter.assembler import _build_init_code
from adapter.generator import deploy_contract_step, invoke_contract_step, wait_receipt_step
from adapter.inventory import write_inventory_payload
from adapter.manifest import resolve_execution_specs_ref


BLOCKED_REASON = "outside minimal admitted receipt-log subset"
ZERO_TOPIC_WORD = "0x0000000000000000000000000000000000000000000000000000000000000000"
NON_ZERO_TOPIC_WORD = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
LOG0_EMPTY_RUNTIME = "0x5f5fa000"
LOG1_EMPTY_ZERO_TOPIC_RUNTIME = "0x5f5f5fa100"
LOG1_EMPTY_NON_ZERO_TOPIC_RUNTIME = (
    "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5f5fa100"
)

LogTemplateMode = Literal[
    "log0_empty_topics0",
    "log1_empty_zero_topic",
    "log1_empty_non_zero_topic",
]


@dataclass(frozen=True, slots=True)
class LogMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: LogTemplateMode


@dataclass(frozen=True, slots=True)
class AutoLogInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str


LOG_MODE_SPECS: dict[LogTemplateMode, dict[str, Any]] = {
    "log0_empty_topics0": {
        "description": "Mapped from execution-specs LOG0 with fixed offset and empty payload onto a minimal receipt-log witness case.",
        "namespace_seed": "upstream-log-log0-empty-topics0",
        "notes": [
            "Upstream intent: benchmark LOG0 with a fixed offset and zero-length data payload.",
            "RPC mapping: deploy a tiny runtime that emits exactly one LOG0 record with empty data, then prove it later through receipt-log observation rather than storage side effects.",
            "Admitted as part of the minimal receipt-log seam because it proves zero-topic receipt shape without claiming the wider log benchmark family is closed.",
        ],
        "runtime_code": LOG0_EMPTY_RUNTIME,
        "topics": [],
        "data": "0x",
    },
    "log1_empty_zero_topic": {
        "description": "Mapped from execution-specs LOG1 with a zero topic, fixed offset, and empty payload onto a minimal receipt-log witness case.",
        "namespace_seed": "upstream-log-log1-empty-zero-topic",
        "notes": [
            "Upstream intent: benchmark LOG1 with a single zero topic, fixed offset, and zero-length data payload.",
            "RPC mapping: deploy a tiny runtime that emits exactly one LOG1 record with topic0=0x00..00 and empty data, then prove it later through receipt-log observation rather than storage side effects.",
            "Admitted as part of the minimal receipt-log seam because it proves topic-count and concrete zero-topic value handling without admitting the broader log matrix yet.",
        ],
        "runtime_code": LOG1_EMPTY_ZERO_TOPIC_RUNTIME,
        "topics": [ZERO_TOPIC_WORD],
        "data": "0x",
    },
    "log1_empty_non_zero_topic": {
        "description": "Mapped from execution-specs LOG1 with a non-zero topic, fixed offset, and empty payload onto a minimal receipt-log witness case.",
        "namespace_seed": "upstream-log-log1-empty-non-zero-topic",
        "notes": [
            "Upstream intent: benchmark LOG1 with a single non-zero topic, fixed offset, and zero-length data payload.",
            "RPC mapping: deploy a tiny runtime that emits exactly one LOG1 record with topic0=0xff..ff and empty data, then prove it later through receipt-log observation rather than storage side effects.",
            "Admitted as part of the minimal receipt-log seam because it proves topic-count and concrete non-zero topic value handling without admitting the broader log matrix yet.",
        ],
        "runtime_code": LOG1_EMPTY_NON_ZERO_TOPIC_RUNTIME,
        "topics": [NON_ZERO_TOPIC_WORD],
        "data": "0x",
    },
}


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


def generate_upstream_log_manifest(
    *,
    repo_root: str | Path,
    output_path: str | Path,
    template_path: str | Path | None = None,
    suite_version: str = "0.1.0",
    chain_profile_version: str = "1",
) -> dict[str, Any]:
    repo_root_path = Path(repo_root).resolve()
    output = Path(output_path).resolve()
    template_file = (
        Path(template_path).resolve()
        if template_path is not None
        else repo_root_path / "suites" / "templates" / "upstream_log_templates.json"
    )
    templates = load_log_templates(template_file)
    execution_specs_ref = resolve_execution_specs_ref(
        repo_root_path / "suites" / "manifests" / "upstream_log_mapped.json",
        "submodule-pending",
    )
    manifest = {
        "name": "upstream-log-mapped",
        "version": "1",
        "execution_specs_ref": execution_specs_ref,
        "suite_version": suite_version,
        "chain_profile_version": chain_profile_version,
        "cases": [render_log_case(template) for template in templates],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def load_log_templates(path: str | Path) -> tuple[LogMappingTemplate, ...]:
    template_path = Path(path)
    data = json.loads(template_path.read_text())
    entries = data.get("cases")
    if not isinstance(entries, list):
        raise ValueError("log template payload must contain a list 'cases'")
    return tuple(_load_log_template_entry(entry, index=index) for index, entry in enumerate(entries))


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
    templates = tuple(
        _inventory_entry_to_template(entry)
        for entry in inventory
        if entry.admitted and entry.mode is not None
    )
    return templates, tuple(inventory)


def render_log_case(template: LogMappingTemplate) -> dict[str, Any]:
    spec = LOG_MODE_SPECS[template.mode]
    return {
        "kind": "upstream_mapped",
        "case_id": template.case_id,
        "family": "state/log",
        "description": template.description,
        "namespace_seed": template.namespace_seed,
        "upstream_ref": template.upstream_ref,
        "notes": template.notes,
        "observe": {
            "log_probe": {
                "mode": template.mode,
                "topics": spec["topics"],
                "data": spec["data"],
            }
        },
        "filters": {},
        "steps": [
            deploy_contract_step(
                init_code=_build_init_code(spec["runtime_code"]),
                runtime_code=spec["runtime_code"],
            ),
            wait_receipt_step(),
            invoke_contract_step(data_hex="0x"),
            wait_receipt_step(),
        ],
        "expected": {
            "receipt_logs": [
                {
                    "topics": spec["topics"],
                    "data": spec["data"],
                }
            ]
        },
    }


def _load_log_template_entry(entry: object, *, index: int) -> LogMappingTemplate:
    if not isinstance(entry, dict):
        raise ValueError(f"log template entry {index} must be an object")
    required_fields = (
        "case_id",
        "description",
        "namespace_seed",
        "upstream_ref",
        "notes",
        "mode",
    )
    for field in required_fields:
        if field not in entry:
            raise ValueError(f"log template entry {index} missing required field: {field}")
    mode = entry["mode"]
    if mode not in LOG_MODE_SPECS:
        raise ValueError(f"unsupported log template mode: {mode}")
    notes = entry["notes"]
    if not isinstance(notes, list) or not all(isinstance(note, str) for note in notes):
        raise ValueError(f"log template entry {index} field 'notes' must be a list of strings")
    return LogMappingTemplate(
        case_id=str(entry["case_id"]),
        description=str(entry["description"]),
        namespace_seed=str(entry["namespace_seed"]),
        upstream_ref=str(entry["upstream_ref"]),
        notes=list(notes),
        mode=mode,
    )


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
        for size_value, non_zero_data, size_label in size_entries:
            size_slug = _slugify_label(size_label)
            for zeros_topic, zeros_topic_label in zeros_topic_entries:
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
                    admitted_mode = _resolve_test_log_mode(
                        opcode=opcode,
                        size_value=size_value,
                        zeros_topic=zeros_topic,
                        fixed_offset=fixed_offset,
                        non_zero_data=non_zero_data,
                    )
                    results.append(
                        AutoLogInventoryEntry(
                            upstream_ref=upstream_ref,
                            case_id=case_id,
                            admitted=admitted_mode is not None,
                            mode=admitted_mode,
                            reasons=[] if admitted_mode is not None else [BLOCKED_REASON],
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


def _resolve_test_log_mode(
    *,
    opcode: str,
    size_value: int,
    zeros_topic: bool,
    fixed_offset: bool,
    non_zero_data: bool,
) -> LogTemplateMode | None:
    if size_value != 0:
        return None
    if non_zero_data:
        return None
    if not fixed_offset:
        return None
    if opcode == "LOG0" and zeros_topic:
        return "log0_empty_topics0"
    if opcode == "LOG1" and zeros_topic:
        return "log1_empty_zero_topic"
    if opcode == "LOG1" and not zeros_topic:
        return "log1_empty_non_zero_topic"
    return None


def _inventory_entry_to_template(entry: AutoLogInventoryEntry) -> LogMappingTemplate:
    assert entry.mode is not None
    spec = LOG_MODE_SPECS[entry.mode]
    return LogMappingTemplate(
        case_id=entry.case_id,
        description=spec["description"],
        namespace_seed=spec["namespace_seed"],
        upstream_ref=entry.upstream_ref,
        notes=list(spec["notes"]),
        mode=entry.mode,
    )


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


def _extract_pytest_param_entries(block: str, param_name: str, *, function_name: str) -> list[Any]:
    pattern = re.compile(
        rf'@pytest\.mark\.parametrize\(\s*"{re.escape(param_name)}",\s*\[(?P<values>.*?)\]\s*\)',
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(block)
    if not match:
        raise ValueError(f"could not find parameter block for {function_name} field {param_name}")
    values_block = match.group("values")
    entries: list[Any] = []
    if param_name == "size,non_zero_data":
        for param_match in re.finditer(
            r'pytest\.param\((?P<size>[^,]+),\s*(?P<non_zero_data>True|False),\s*id="(?P<label>[^"]+)"\)',
            values_block,
        ):
            entries.append(
                (
                    _parse_int_literal(param_match.group("size")),
                    _parse_bool_literal(param_match.group("non_zero_data")),
                    param_match.group("label"),
                )
            )
    elif param_name == "zeros_topic":
        for param_match in re.finditer(
            r'pytest\.param\((?P<value>True|False),\s*id="(?P<label>[^"]+)"\)',
            values_block,
        ):
            entries.append(
                (
                    _parse_bool_literal(param_match.group("value")),
                    param_match.group("label"),
                )
            )
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
