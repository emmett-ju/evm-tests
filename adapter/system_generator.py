from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from adapter.assembler import _build_init_code, _push_int, _word_hex
from adapter.generator import deploy_contract_step, invoke_contract_step, wait_receipt_step
from adapter.inventory import write_inventory_payload
from adapter.manifest import resolve_execution_specs_ref
from adapter.signer import keccak256


BLOCKED_EXTERNAL_CALL_REASON = "requires multi-address external-call orchestration not yet mapped"
BLOCKED_CREATE_REASON = "requires create/create2 deployed-address witness not yet mapped"
BLOCKED_CREATE_COLLISION_REASON = "requires gas-capped create collision orchestration not yet mapped"
BLOCKED_SELFDESTRUCT_REASON = "requires selfdestruct lifecycle witness not yet mapped"

SystemTemplateMode = Literal["return_revert_self_call"]


@dataclass(frozen=True, slots=True)
class SystemMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: SystemTemplateMode
    opcode: str
    return_size: int
    return_non_zero_data: bool


@dataclass(frozen=True, slots=True)
class AutoSystemInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str
    opcode: str | None = None
    return_size: int | None = None
    return_non_zero_data: bool | None = None


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


def generate_upstream_system_manifest(
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
        else repo_root_path / "suites" / "templates" / "upstream_system_templates.json"
    )
    templates = load_system_templates(template_file)
    execution_specs_ref = resolve_execution_specs_ref(
        repo_root_path / "suites" / "manifests" / "upstream_system_mapped.json",
        "submodule-pending",
    )
    manifest = {
        "name": "upstream-system-mapped",
        "version": "1",
        "execution_specs_ref": execution_specs_ref,
        "suite_version": suite_version,
        "chain_profile_version": chain_profile_version,
        "cases": [render_system_case(template) for template in templates],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def load_system_templates(path: str | Path) -> tuple[SystemMappingTemplate, ...]:
    template_path = Path(path)
    data = json.loads(template_path.read_text())
    entries = data.get("cases")
    if not isinstance(entries, list):
        raise ValueError("system template payload must contain a list 'cases'")
    return tuple(_load_system_template_entry(entry, index=index) for index, entry in enumerate(entries))


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
    templates = tuple(
        _inventory_entry_to_template(entry)
        for entry in inventory
        if entry.admitted and entry.mode is not None
    )
    return templates, tuple(inventory)


def render_system_case(template: SystemMappingTemplate) -> dict[str, Any]:
    payload = _payload_bytes(template.return_size, template.return_non_zero_data)
    runtime_code = _build_return_revert_wrapper_runtime(template)
    return {
        "kind": "upstream_mapped",
        "case_id": template.case_id,
        "family": "state/system",
        "description": template.description,
        "namespace_seed": template.namespace_seed,
        "upstream_ref": template.upstream_ref,
        "notes": template.notes,
        "observe": {"storage_address": "$last_contract"},
        "filters": {},
        "steps": [
            deploy_contract_step(
                init_code=_build_init_code(runtime_code),
                runtime_code=runtime_code,
            ),
            wait_receipt_step(),
            invoke_contract_step(data_hex="0x", gas=_invoke_gas(template.return_size)),
            wait_receipt_step(),
        ],
        "expected": {
            "receipt_status": "0x1",
            "storage": {
                "0x00": _word_hex(1 if template.opcode == "RETURN" else 0),
                "0x01": _word_hex(template.return_size),
                "0x02": "0x" + keccak256(payload).hex(),
            },
        },
    }


def _scan_contract_calling_many_addresses(text: str) -> list[AutoSystemInventoryEntry]:
    block = _extract_param_block(text, function_name="test_contract_calling_many_addresses")
    transfer_amounts = [
        _parse_int_literal(value)
        for value in _extract_param_values_from_block(
            block,
            "transfer_amount",
            function_name="test_contract_calling_many_addresses",
        )
    ]
    opcodes = [
        value.split(".")[-1]
        for value in _extract_param_values_from_block(
            block,
            "opcode",
            function_name="test_contract_calling_many_addresses",
        )
    ]
    access_warm_values = [
        _parse_bool_literal(value)
        for value in _extract_param_values_from_block(
            block,
            "access_warm",
            function_name="test_contract_calling_many_addresses",
        )
    ]
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
                        reasons=[BLOCKED_EXTERNAL_CALL_REASON],
                        source="test_contract_calling_many_addresses",
                    )
                )
    return results


def _scan_create(text: str) -> list[AutoSystemInventoryEntry]:
    block = _extract_param_block(text, function_name="test_create")
    opcodes = [
        value.split(".")[-1]
        for value in _extract_param_values_from_block(block, "opcode", function_name="test_create")
    ]
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
                    reasons=[BLOCKED_CREATE_REASON],
                    source="test_create",
                )
            )
    return results


def _scan_creates_collisions(text: str) -> list[AutoSystemInventoryEntry]:
    block = _extract_param_block(text, function_name="test_creates_collisions")
    opcodes = [
        value.split(".")[-1]
        for value in _extract_param_values_from_block(
            block,
            "opcode",
            function_name="test_creates_collisions",
        )
    ]
    return [
        AutoSystemInventoryEntry(
            upstream_ref=f"tests/benchmark/compute/instruction/test_system.py::test_creates_collisions[opcode={opcode}]",
            case_id=f"upstream.benchmark.system.test_creates_collisions.{opcode.lower()}",
            admitted=False,
            mode=None,
            reasons=[BLOCKED_CREATE_COLLISION_REASON],
            source="test_creates_collisions",
        )
        for opcode in opcodes
    ]


def _scan_return_revert(text: str) -> list[AutoSystemInventoryEntry]:
    block = _extract_param_block(text, function_name="test_return_revert")
    opcodes = [
        value.split(".")[-1]
        for value in _extract_param_values_from_block(block, "opcode", function_name="test_return_revert")
    ]
    variants = _extract_return_revert_variants(block)
    if len(variants) != 5:
        raise ValueError(f"expected 5 return/revert benchmark combinations, found {len(variants)}")
    results: list[AutoSystemInventoryEntry] = []
    for opcode in opcodes:
        for return_size, return_non_zero_data, combo_label in variants:
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
                    admitted=True,
                    mode="return_revert_self_call",
                    reasons=[],
                    source="test_return_revert",
                    opcode=opcode,
                    return_size=return_size,
                    return_non_zero_data=return_non_zero_data,
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
    values = [
        _parse_bool_literal(value)
        for value in _extract_param_values_from_block(block, "value_bearing", function_name=function_name)
    ]
    return [
        AutoSystemInventoryEntry(
            upstream_ref=f"tests/benchmark/compute/instruction/test_system.py::{function_name}[value_bearing={value}]",
            case_id=f"upstream.benchmark.system.{function_name}.value_bearing_{str(value).lower()}",
            admitted=False,
            mode=None,
            reasons=[BLOCKED_SELFDESTRUCT_REASON],
            source=function_name,
        )
        for value in values
    ]


def _inventory_entry_to_template(entry: AutoSystemInventoryEntry) -> SystemMappingTemplate:
    if entry.mode != "return_revert_self_call":
        raise ValueError(f"unsupported admitted system mode: {entry.mode}")
    opcode = _require_inventory_field(entry.opcode, field="opcode")
    return_size = _require_inventory_field(entry.return_size, field="return_size")
    return_non_zero_data = _require_inventory_field(
        entry.return_non_zero_data,
        field="return_non_zero_data",
    )
    payload_kind = "non-zero" if return_non_zero_data else "zero"
    return SystemMappingTemplate(
        case_id=entry.case_id,
        description=(
            f"Mapped from execution-specs {opcode} benchmark onto a self-call wrapper that stores "
            f"inner-call success, returndata size, and returndata digest for the {return_size}-byte {payload_kind} variant."
        ),
        namespace_seed=_build_namespace_seed(entry.case_id),
        upstream_ref=entry.upstream_ref,
        notes=_build_notes(opcode=opcode, return_size=return_size, return_non_zero_data=return_non_zero_data),
        mode="return_revert_self_call",
        opcode=opcode,
        return_size=return_size,
        return_non_zero_data=return_non_zero_data,
    )


def _load_system_template_entry(entry: object, *, index: int) -> SystemMappingTemplate:
    if not isinstance(entry, dict):
        raise ValueError(f"system template entry {index} must be an object")
    required_fields = (
        "case_id",
        "description",
        "namespace_seed",
        "upstream_ref",
        "notes",
        "mode",
        "opcode",
        "return_size",
        "return_non_zero_data",
    )
    for field in required_fields:
        if field not in entry:
            raise ValueError(f"system template entry {index} missing required field: {field}")
    notes = entry["notes"]
    if not isinstance(notes, list) or not all(isinstance(note, str) for note in notes):
        raise ValueError(f"system template entry {index} field 'notes' must be a list of strings")
    mode = entry["mode"]
    if mode != "return_revert_self_call":
        raise ValueError(f"unsupported system template mode: {mode}")
    opcode = str(entry["opcode"])
    if opcode not in {"RETURN", "REVERT"}:
        raise ValueError(f"unsupported system template opcode: {opcode}")
    return SystemMappingTemplate(
        case_id=str(entry["case_id"]),
        description=str(entry["description"]),
        namespace_seed=str(entry["namespace_seed"]),
        upstream_ref=str(entry["upstream_ref"]),
        notes=list(notes),
        mode="return_revert_self_call",
        opcode=opcode,
        return_size=int(entry["return_size"]),
        return_non_zero_data=bool(entry["return_non_zero_data"]),
    )


def _build_namespace_seed(case_id: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", case_id.removeprefix("upstream.benchmark.system.").lower()).strip("-")
    return f"upstream-system-{slug}"


def _build_notes(*, opcode: str, return_size: int, return_non_zero_data: bool) -> list[str]:
    payload_kind = "non-zero" if return_non_zero_data else "zero"
    child_verdict = "success" if opcode == "RETURN" else "revert"
    payload_note = (
        f"The child path fills the first {return_size} memory byte(s) with 0xff before {opcode}."
        if return_non_zero_data and return_size > 0
        else f"The child path {opcode}s {return_size} byte(s) from zero-initialized memory."
    )
    return [
        f"Upstream intent: benchmark {opcode} with a {return_size}-byte {payload_kind} returndata payload.",
        "RPC mapping: a single deployed contract self-CALLs into its child path so the outer wrapper can observe the inner result without requiring multi-contract orchestration in the manifest.",
        payload_note,
        (
            "Wrapper witness contract stores the inner-call success bit in slot0, RETURNDATASIZE in slot1, and KECCAK256(returndata) in slot2; the outer transaction receipt remains successful so receipt_status stays directly observable."
        ),
        f"Admitted because final receipt status plus wrapper-exposed returndata digest/size are deterministic final observables for the {child_verdict} path.",
    ]


def _build_return_revert_wrapper_runtime(template: SystemMappingTemplate) -> str:
    builder = _BytecodeBuilder()

    builder.op(0x36)  # CALLDATASIZE
    builder.push_int(0)
    builder.op(0x14)  # EQ
    builder.push_label("wrapper")
    builder.op(0x57)  # JUMPI

    if template.return_non_zero_data and template.return_size > 0:
        builder.extend(_build_fill_ff_prefix(template.return_size))
    builder.push_int(template.return_size)
    builder.push_int(0)
    builder.op(0xF3 if template.opcode == "RETURN" else 0xFD)

    builder.mark("wrapper")
    builder.push_int(0)  # out_size
    builder.push_int(0)  # out_offset
    builder.push_int(1)  # in_size
    builder.push_int(0)  # in_offset
    builder.push_int(0)  # value
    builder.op(0x30)  # ADDRESS
    builder.op(0x5A)  # GAS
    builder.op(0xF1)  # CALL

    builder.push_int(0)
    builder.op(0x55)  # SSTORE slot0 <- success

    builder.op(0x3D)  # RETURNDATASIZE
    builder.op(0x80)  # DUP1
    builder.push_int(1)
    builder.op(0x55)  # SSTORE slot1 <- returndata size

    builder.op(0x80)  # DUP1
    builder.push_int(0)
    builder.push_int(0)
    builder.op(0x3E)  # RETURNDATACOPY(0, 0, size)

    builder.push_int(0)
    builder.op(0x20)  # KECCAK256(0, size)
    builder.push_int(2)
    builder.op(0x55)  # SSTORE slot2 <- digest
    builder.op(0x00)  # STOP

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


def _payload_bytes(return_size: int, return_non_zero_data: bool) -> bytes:
    if return_size == 0:
        return b""
    fill_byte = b"\xff" if return_non_zero_data else b"\x00"
    return fill_byte * return_size


def _invoke_gas(return_size: int) -> str:
    if return_size >= 1024 * 1024:
        return "0x2000000"
    if return_size >= 1024:
        return "0x200000"
    return "0x1e8480"


def _extract_return_revert_variants(block: str) -> list[tuple[int, bool, str]]:
    pattern = re.compile(
        r'pytest\.param\((?P<return_size>[^,]+),\s*(?P<return_non_zero_data>True|False),\s*id="(?P<label>[^"]+)"\)',
        re.MULTILINE,
    )
    return [
        (
            _parse_int_literal(match.group("return_size")),
            _parse_bool_literal(match.group("return_non_zero_data")),
            match.group("label"),
        )
        for match in pattern.finditer(block)
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


def _require_inventory_field(value: Any, *, field: str) -> Any:
    if value is None:
        raise ValueError(f"missing system inventory field: {field}")
    return value


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
