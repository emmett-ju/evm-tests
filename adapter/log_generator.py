from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from adapter.assembler import _build_init_code, _push_int
from adapter.generator import deploy_contract_step, invoke_contract_step, wait_receipt_step
from adapter.inventory import write_inventory_payload
from adapter.log_probe import opcode_topic_count, validate_log_probe_declaration
from adapter.manifest import resolve_execution_specs_ref
from adapter.signer import keccak256


DYNAMIC_OFFSET_BLOCKED_REASON = "requires gas-derived dynamic log offset observation not yet mapped"
ZERO_TOPIC_WORD = "0x0000000000000000000000000000000000000000000000000000000000000000"
NON_ZERO_TOPIC_WORD = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
EXACT_LOG_DATA_MAX_BYTES = 256

LogTemplateMode = Literal[
    "test_log_fixed_offset",
    "test_log_benchmark",
]
LogWitnessMode = Literal["exact", "digest"]
LogMemorySeedKind = Literal["zero", "ff"]


@dataclass(frozen=True, slots=True)
class LogMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: LogTemplateMode
    opcode: str
    topic_count: int
    topic_word: str | None
    log_size: int
    memory_seed_kind: LogMemorySeedKind
    memory_seed_size: int
    witness_mode: LogWitnessMode


@dataclass(frozen=True, slots=True)
class AutoLogInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str
    opcode: str | None = None
    topic_count: int | None = None
    topic_word: str | None = None
    log_size: int | None = None
    memory_seed_kind: str | None = None
    memory_seed_size: int | None = None
    witness_mode: str | None = None


class _BytecodeBuilder:
    def __init__(self) -> None:
        self.code = bytearray()
        self.labels: dict[str, int] = {}
        self.fixups: list[tuple[int, str]] = []

    def op(self, opcode: int) -> None:
        self.code.append(opcode)

    def extend(self, payload: bytes) -> None:
        self.code.extend(payload)

    def push_int(self, value: int) -> None:
        self.extend(_push_int(value))

    def push_label(self, name: str) -> None:
        self.code.extend((0x60, 0x00))
        self.fixups.append((len(self.code) - 1, name))

    def mark(self, name: str) -> None:
        self.labels[name] = len(self.code)
        self.op(0x5B)  # JUMPDEST

    def finish(self) -> bytes:
        for position, name in self.fixups:
            if name not in self.labels:
                raise ValueError(f"unknown bytecode label: {name}")
            target = self.labels[name]
            if target > 0xFF:
                raise ValueError(f"bytecode label {name} out of PUSH1 range: {target}")
            self.code[position] = target
        return bytes(self.code)


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
    runtime_code = _build_log_runtime(template)
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
                "mode": "parametric_log",
                "opcode": template.opcode,
                "topic_count": template.topic_count,
                "topic_word": template.topic_word,
                "log_size": template.log_size,
                "memory_seed_kind": template.memory_seed_kind,
                "memory_seed_size": template.memory_seed_size,
                "witness_mode": template.witness_mode,
            }
        },
        "filters": {},
        "steps": [
            deploy_contract_step(
                init_code=_build_init_code(runtime_code),
                runtime_code=runtime_code,
            ),
            wait_receipt_step(),
            invoke_contract_step(data_hex="0x", gas=_invoke_gas(template)),
            wait_receipt_step(),
        ],
        "expected": {"receipt_logs": [_expected_receipt_log(template)]},
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
        "opcode",
        "topic_count",
        "log_size",
        "memory_seed_kind",
        "memory_seed_size",
        "witness_mode",
    )
    for field in required_fields:
        if field not in entry:
            raise ValueError(f"log template entry {index} missing required field: {field}")
    mode = entry["mode"]
    if mode not in ("test_log_fixed_offset", "test_log_benchmark"):
        raise ValueError(f"unsupported log template mode: {mode}")
    witness_mode = entry["witness_mode"]
    if witness_mode not in ("exact", "digest"):
        raise ValueError(f"unsupported log witness mode: {witness_mode}")
    memory_seed_kind = entry["memory_seed_kind"]
    if memory_seed_kind not in ("zero", "ff"):
        raise ValueError(f"unsupported log memory seed kind: {memory_seed_kind}")
    notes = entry["notes"]
    if not isinstance(notes, list) or not all(isinstance(note, str) for note in notes):
        raise ValueError(f"log template entry {index} field 'notes' must be a list of strings")
    topic_word = entry.get("topic_word")
    if topic_word is not None and not isinstance(topic_word, str):
        raise ValueError(f"log template entry {index} field 'topic_word' must be a string when present")
    return LogMappingTemplate(
        case_id=str(entry["case_id"]),
        description=str(entry["description"]),
        namespace_seed=str(entry["namespace_seed"]),
        upstream_ref=str(entry["upstream_ref"]),
        notes=list(notes),
        mode=mode,
        opcode=str(entry["opcode"]),
        topic_count=int(entry["topic_count"]),
        topic_word=topic_word,
        log_size=int(entry["log_size"]),
        memory_seed_kind=memory_seed_kind,
        memory_seed_size=int(entry["memory_seed_size"]),
        witness_mode=witness_mode,
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
        topic_count = _opcode_topic_count(opcode)
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
                    topic_word = _resolve_topic_word(topic_count=topic_count, zeros_topic=zeros_topic)
                    witness_mode = _resolve_witness_mode(size_value)
                    memory_seed_kind: LogMemorySeedKind = "ff" if non_zero_data else "zero"
                    results.append(
                        AutoLogInventoryEntry(
                            upstream_ref=upstream_ref,
                            case_id=case_id,
                            admitted=fixed_offset,
                            mode="test_log_fixed_offset" if fixed_offset else None,
                            reasons=[] if fixed_offset else [DYNAMIC_OFFSET_BLOCKED_REASON],
                            source="test_log",
                            opcode=opcode,
                            topic_count=topic_count,
                            topic_word=topic_word,
                            log_size=size_value,
                            memory_seed_kind=memory_seed_kind,
                            memory_seed_size=size_value if non_zero_data else 0,
                            witness_mode=witness_mode,
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
        topic_count = _opcode_topic_count(opcode)
        topic_word = _resolve_topic_word(topic_count=topic_count, zeros_topic=False)
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
                        admitted=True,
                        mode="test_log_benchmark",
                        reasons=[],
                        source="test_log_benchmark",
                        opcode=opcode,
                        topic_count=topic_count,
                        topic_word=topic_word,
                        log_size=log_size,
                        memory_seed_kind="ff" if mem_size > 0 else "zero",
                        memory_seed_size=mem_size,
                        witness_mode=_resolve_witness_mode(log_size),
                    )
                )
    if len(results) != 80:
        raise ValueError(f"expected 80 log benchmark cases, found {len(results)}")
    return results


def _inventory_entry_to_template(entry: AutoLogInventoryEntry) -> LogMappingTemplate:
    assert entry.mode is not None
    return LogMappingTemplate(
        case_id=entry.case_id,
        description=_build_description(entry),
        namespace_seed=_build_namespace_seed(entry.case_id),
        upstream_ref=entry.upstream_ref,
        notes=_build_notes(entry),
        mode=entry.mode,
        opcode=_require_inventory_field(entry.opcode, field="opcode"),
        topic_count=_require_inventory_field(entry.topic_count, field="topic_count"),
        topic_word=entry.topic_word,
        log_size=_require_inventory_field(entry.log_size, field="log_size"),
        memory_seed_kind=_require_inventory_field(entry.memory_seed_kind, field="memory_seed_kind"),
        memory_seed_size=_require_inventory_field(entry.memory_seed_size, field="memory_seed_size"),
        witness_mode=_require_inventory_field(entry.witness_mode, field="witness_mode"),
    )


def _build_description(entry: AutoLogInventoryEntry) -> str:
    opcode = _require_inventory_field(entry.opcode, field="opcode")
    topic_count = _require_inventory_field(entry.topic_count, field="topic_count")
    log_size = _require_inventory_field(entry.log_size, field="log_size")
    witness_mode = _require_inventory_field(entry.witness_mode, field="witness_mode")
    if entry.mode == "test_log_fixed_offset":
        return (
            f"Mapped from execution-specs {opcode} fixed-offset log benchmark onto a receipt-log witness "
            f"with {topic_count} topic(s), {log_size} payload bytes, and {witness_mode} payload proof."
        )
    return (
        f"Mapped from execution-specs {opcode} log benchmark mem/log-size matrix onto a receipt-log witness "
        f"with {topic_count} topic(s), log_size={log_size}, and {witness_mode} payload proof."
    )


def _build_notes(entry: AutoLogInventoryEntry) -> list[str]:
    opcode = _require_inventory_field(entry.opcode, field="opcode")
    topic_count = _require_inventory_field(entry.topic_count, field="topic_count")
    log_size = _require_inventory_field(entry.log_size, field="log_size")
    memory_seed_kind = _require_inventory_field(entry.memory_seed_kind, field="memory_seed_kind")
    memory_seed_size = _require_inventory_field(entry.memory_seed_size, field="memory_seed_size")
    witness_mode = _require_inventory_field(entry.witness_mode, field="witness_mode")
    topic_word = entry.topic_word
    topic_note = (
        "no topics"
        if topic_count == 0
        else f"{topic_count} repeated {'zero' if topic_word == ZERO_TOPIC_WORD else 'non-zero'} topic word(s)"
    )
    witness_note = (
        "Witness keeps full `data` equality because the payload is small enough for stable diffs."
        if witness_mode == "exact"
        else "Witness records `data_digest` plus `data_length_bytes` so large payload variants stay truthful without noisy full-byte diffs."
    )
    if entry.mode == "test_log_fixed_offset":
        notes = [
            f"Upstream intent: benchmark {opcode} with a fixed memory offset, {topic_note}, and log_size={log_size}.",
            (
                "RPC mapping: deploy a small runtime that emits exactly one receipt log at offset 0. "
                f"The runtime seeds the first {memory_seed_size} memory byte(s) with 0xff before logging."
                if memory_seed_kind == "ff"
                else "RPC mapping: deploy a small runtime that emits exactly one receipt log at offset 0 from zero-initialized memory."
            ),
            witness_note,
            "Admitted because fixed offset removes the gas-sensitive dynamic-addressing branch and the remaining topic/payload semantics are fully observable in the receipt.",
        ]
        if topic_count == 0:
            notes.append(
                "For LOG0 the upstream zeros_topic branch does not affect the receipt because the opcode consumes no topics; both branch labels are still tracked as distinct upstream cases."
            )
        return notes
    return [
        f"Upstream intent: benchmark {opcode} over a fixed offset with mem_size={memory_seed_size}, log_size={log_size}, and {topic_note}.",
        (
            f"RPC mapping: seed the first {memory_seed_size} memory byte(s) with deterministic 0xff bytes, leave the remaining log window zero-filled, and emit exactly one receipt log from offset 0."
            if memory_seed_kind == "ff"
            else "RPC mapping: emit exactly one receipt log from offset 0 without pre-seeding memory, preserving the all-zero payload case."
        ),
        witness_note,
        "Admitted because the benchmark varies fixed-offset topic count and payload coverage only; those outputs are directly observable without tracing gas-sensitive intermediates.",
    ]


def _build_namespace_seed(case_id: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", case_id.removeprefix("upstream.benchmark.log.").lower()).strip("-")
    return f"upstream-log-{slug}"


def _build_log_runtime(template: LogMappingTemplate) -> str:
    builder = _BytecodeBuilder()
    if template.memory_seed_kind == "ff" and template.memory_seed_size > 0:
        builder.extend(_build_fill_ff_prefix(template.memory_seed_size))
    if template.topic_word is not None:
        topic_value = int(template.topic_word, 16)
        for _ in range(template.topic_count):
            builder.push_int(topic_value)
    builder.push_int(template.log_size)
    builder.push_int(0)
    builder.op(0xA0 + template.topic_count)
    builder.op(0x00)
    return "0x" + builder.finish().hex()


def _build_fill_ff_prefix(size: int) -> bytes:
    builder = _BytecodeBuilder()
    full_word_bytes = (size // 32) * 32
    tail_bytes = size - full_word_bytes
    if full_word_bytes > 0:
        builder.push_int(full_word_bytes)
        builder.mark("fill_words_loop")
        builder.op(0x80)  # DUP1
        builder.push_int(0)
        builder.op(0x14)  # EQ
        builder.push_label("fill_words_done")
        builder.op(0x57)  # JUMPI
        builder.push_int((1 << 256) - 1)
        builder.op(0x81)  # DUP2
        builder.push_int(32)
        builder.op(0x03)  # SUB
        builder.op(0x52)  # MSTORE
        builder.push_int(32)
        builder.op(0x03)  # SUB
        builder.push_label("fill_words_loop")
        builder.op(0x56)  # JUMP
        builder.mark("fill_words_done")
        builder.op(0x50)  # POP
    for offset in range(full_word_bytes, full_word_bytes + tail_bytes):
        builder.push_int(0xFF)
        builder.push_int(offset)
        builder.op(0x53)  # MSTORE8
    return builder.finish()


def build_validated_log_probe_template(log_probe: dict[str, Any]) -> LogMappingTemplate:
    normalized = validate_log_probe_declaration(log_probe)
    return LogMappingTemplate(
        case_id="observe.log_probe",
        description="Derived receipt-log expectation from runtime contract",
        namespace_seed="observe-log-probe",
        upstream_ref="observe.log_probe",
        notes=[],
        mode="test_log_fixed_offset",
        opcode=str(normalized["opcode"]),
        topic_count=int(normalized["topic_count"]),
        topic_word=normalized["topic_word"],
        log_size=int(normalized["log_size"]),
        memory_seed_kind=str(normalized["memory_seed_kind"]),
        memory_seed_size=int(normalized["memory_seed_size"]),
        witness_mode=str(normalized["witness_mode"]),
    )



def derive_receipt_log_expectation(log_probe: dict[str, Any]) -> dict[str, Any]:
    return _expected_receipt_log(build_validated_log_probe_template(log_probe))



def _expected_receipt_log(template: LogMappingTemplate) -> dict[str, Any]:
    topics = [] if template.topic_word is None else [template.topic_word] * template.topic_count
    payload = _payload_bytes(template)
    if template.witness_mode == "exact":
        return {"topics": topics, "data": "0x" + payload.hex()}
    return {
        "topics": topics,
        "data_digest": "0x" + keccak256(payload).hex(),
        "data_length_bytes": len(payload),
    }


def _payload_bytes(template: LogMappingTemplate) -> bytes:
    if template.log_size == 0:
        return b""
    if template.memory_seed_kind == "zero" or template.memory_seed_size == 0:
        return b"\x00" * template.log_size
    filled = min(template.log_size, template.memory_seed_size)
    return (b"\xff" * filled) + (b"\x00" * (template.log_size - filled))


def _invoke_gas(template: LogMappingTemplate) -> str:
    if template.log_size >= 1024 * 1024:
        return "0x2000000"
    if template.memory_seed_size >= 1024 or template.log_size >= 1024:
        return "0x200000"
    return "0xc350"


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


def _opcode_topic_count(opcode: str) -> int:
    return opcode_topic_count(opcode)


def _resolve_topic_word(*, topic_count: int, zeros_topic: bool) -> str | None:
    if topic_count == 0:
        return None
    return ZERO_TOPIC_WORD if zeros_topic else NON_ZERO_TOPIC_WORD


def _resolve_witness_mode(log_size: int) -> LogWitnessMode:
    return "exact" if log_size <= EXACT_LOG_DATA_MAX_BYTES else "digest"


def _require_inventory_field(value: Any, *, field: str) -> Any:
    if value is None:
        raise ValueError(f"missing log inventory field: {field}")
    return value


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
