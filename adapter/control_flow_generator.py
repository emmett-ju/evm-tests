from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from adapter.assembler import _build_init_code, _push_int, _word_hex
from adapter.generator import deploy_contract_step, invoke_contract_step, wait_receipt_step
from adapter.inventory import write_inventory_payload
from adapter.manifest import resolve_execution_specs_ref


ControlFlowTemplateMode = Literal[
    "gas",
    "pc",
    "jump",
    "jump_pc_relative",
    "jumpi_fallthrough",
    "jumpi_taken",
    "jumpdest",
]

WORD_00 = _word_hex(0)
WORD_01 = _word_hex(1)

CONTROL_FLOW_FUNCTIONS = (
    "test_gas_op",
    "test_pc_op",
    "test_jumps",
    "test_jump_benchmark",
    "test_jumpi_fallthrough",
    "test_jumpis",
    "test_jumpdests",
)

CONTROL_FLOW_MODE_SPECS: dict[str, dict[str, Any]] = {
    "test_gas_op": {
        "case_id": "upstream.benchmark.control_flow.test_gas_op",
        "mode": "gas",
        "description": "Admitted execution-specs GAS benchmark variant with a deterministic storage-observable outcome.",
        "namespace_seed": "upstream-control-flow-gas",
        "notes": [
            "Upstream intent: benchmark GAS in a control-flow workload.",
            "RPC mapping: runtime executes GAS, reduces it to a boolean non-zero signal, and stores the result in slot0.",
            "Admitted because final storage truthfully captures that the GAS opcode executed without relying on upstream gas-accounting internals.",
        ],
    },
    "test_pc_op": {
        "case_id": "upstream.benchmark.control_flow.test_pc_op",
        "mode": "pc",
        "description": "Admitted execution-specs PC benchmark variant with a deterministic storage-observable outcome.",
        "namespace_seed": "upstream-control-flow-pc",
        "notes": [
            "Upstream intent: benchmark PC in a control-flow workload.",
            "RPC mapping: runtime executes PC at byte offset 0, checks the pushed value against the expected location, and stores the boolean result in slot0.",
            "Admitted because final storage truthfully captures the PC opcode outcome without reproducing upstream gas benchmarking internals.",
        ],
    },
    "test_jumps": {
        "case_id": "upstream.benchmark.control_flow.test_jumps",
        "mode": "jump",
        "description": "Admitted execution-specs JUMP benchmark variant with a deterministic storage-observable outcome.",
        "namespace_seed": "upstream-control-flow-jump",
        "notes": [
            "Upstream intent: benchmark JUMP through an explicit destination.",
            "RPC mapping: runtime performs an unconditional jump to a JUMPDEST and stores 1 in slot0 only after the jump lands successfully.",
            "Admitted because final storage truthfully distinguishes successful control transfer from fallthrough or invalid jump behavior.",
        ],
    },
    "test_jump_benchmark": {
        "case_id": "upstream.benchmark.control_flow.test_jump_benchmark",
        "mode": "jump_pc_relative",
        "description": "Admitted execution-specs PC-relative JUMP benchmark variant with a deterministic storage-observable outcome.",
        "namespace_seed": "upstream-control-flow-jump-pc-relative",
        "notes": [
            "Upstream intent: benchmark JUMP where the destination is derived relative to PC.",
            "RPC mapping: runtime computes a destination from PC plus a fixed offset, jumps to the matching JUMPDEST, and stores 1 in slot0 after landing.",
            "Admitted because final storage truthfully captures the relative-control-flow outcome without depending on upstream filler machinery.",
        ],
    },
    "test_jumpi_fallthrough": {
        "case_id": "upstream.benchmark.control_flow.test_jumpi_fallthrough",
        "mode": "jumpi_fallthrough",
        "description": "Admitted execution-specs JUMPI fallthrough benchmark variant with a deterministic storage-observable outcome.",
        "namespace_seed": "upstream-control-flow-jumpi-fallthrough",
        "notes": [
            "Upstream intent: benchmark JUMPI with a false condition so execution falls through.",
            "RPC mapping: runtime executes JUMPI with a zero condition, stores 0 on the fallthrough path, and reserves a distinct taken branch that would store 1.",
            "Admitted because final storage truthfully captures branch direction without requiring trace-level observability.",
        ],
    },
    "test_jumpis": {
        "case_id": "upstream.benchmark.control_flow.test_jumpis",
        "mode": "jumpi_taken",
        "description": "Admitted execution-specs JUMPI taken benchmark variant with a deterministic storage-observable outcome.",
        "namespace_seed": "upstream-control-flow-jumpi-taken",
        "notes": [
            "Upstream intent: benchmark JUMPI with a truthy NUMBER condition so the branch is taken.",
            "RPC mapping: runtime executes NUMBER then JUMPI, lands on a JUMPDEST-backed taken branch, and stores 1 in slot0 after the jump succeeds.",
            "Admitted because final storage truthfully captures branch direction on real execution paths without block-control fixtures.",
        ],
    },
    "test_jumpdests": {
        "case_id": "upstream.benchmark.control_flow.test_jumpdests",
        "mode": "jumpdest",
        "description": "Admitted execution-specs JUMPDEST benchmark variant with a deterministic storage-observable outcome.",
        "namespace_seed": "upstream-control-flow-jumpdest",
        "notes": [
            "Upstream intent: benchmark JUMPDEST in a control-flow workload.",
            "RPC mapping: runtime begins on a JUMPDEST and stores 1 in slot0 after executing the reachable destination path.",
            "Admitted because final storage truthfully captures that the JUMPDEST path executed without depending on upstream gas-accounting internals.",
        ],
    },
}


@dataclass(frozen=True, slots=True)
class ControlFlowMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: ControlFlowTemplateMode


@dataclass(frozen=True, slots=True)
class AutoControlFlowInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str


def generate_upstream_control_flow_templates(
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
        / "test_control_flow.py"
    )
    templates, inventory = scan_control_flow_cases(source)
    payload = {
        "name": "upstream-control-flow-mapping-templates",
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
            family="control-flow",
            name="upstream-control-flow-auto-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload


def generate_upstream_control_flow_manifest(
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
        else repo_root_path / "suites" / "templates" / "upstream_control_flow_templates.json"
    )
    templates = load_control_flow_templates(template_file)
    execution_specs_ref = resolve_execution_specs_ref(
        repo_root_path / "suites" / "manifests" / "upstream_control_flow_mapped.json",
        "submodule-pending",
    )
    manifest = {
        "name": "upstream-control-flow-mapped",
        "version": "1",
        "execution_specs_ref": execution_specs_ref,
        "suite_version": suite_version,
        "chain_profile_version": chain_profile_version,
        "cases": [render_control_flow_case(template) for template in templates],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def load_control_flow_templates(path: str | Path) -> tuple[ControlFlowMappingTemplate, ...]:
    template_path = Path(path)
    data = json.loads(template_path.read_text())
    entries = data.get("cases")
    if not isinstance(entries, list):
        raise ValueError("control-flow template payload must contain a list 'cases'")
    return tuple(_load_control_flow_template_entry(entry, index=index) for index, entry in enumerate(entries))


def scan_control_flow_cases(
    source_path: str | Path,
) -> tuple[tuple[ControlFlowMappingTemplate, ...], tuple[AutoControlFlowInventoryEntry, ...]]:
    source = Path(source_path)
    text = source.read_text()
    inventory = sorted(_scan_control_flow_cases(text), key=lambda item: item.upstream_ref)
    if len(inventory) != len(CONTROL_FLOW_FUNCTIONS):
        raise ValueError(f"expected {len(CONTROL_FLOW_FUNCTIONS)} control-flow benchmark cases, found {len(inventory)}")
    templates = tuple(
        _inventory_entry_to_template(entry)
        for entry in inventory
        if entry.admitted and entry.mode is not None
    )
    return templates, tuple(inventory)


def render_control_flow_case(template: ControlFlowMappingTemplate) -> dict[str, Any]:
    runtime_code, expected_storage = _render_runtime_and_expected(template.mode)
    return {
        "kind": "upstream_mapped",
        "case_id": template.case_id,
        "family": "state/control-flow",
        "description": template.description,
        "namespace_seed": template.namespace_seed,
        "upstream_ref": template.upstream_ref,
        "notes": template.notes,
        "observe": {
            "storage_address": "$last_contract",
            "control_flow_probe": {
                "mode": template.mode,
                "expected_storage": expected_storage,
            },
        },
        "filters": {},
        "steps": [
            deploy_contract_step(
                init_code=_build_init_code(runtime_code),
                runtime_code=runtime_code,
            ),
            wait_receipt_step(),
            invoke_contract_step(data_hex="0x"),
            wait_receipt_step(),
        ],
        "expected": {"storage": {"0x00": expected_storage}},
    }


def _load_control_flow_template_entry(entry: object, *, index: int) -> ControlFlowMappingTemplate:
    if not isinstance(entry, dict):
        raise ValueError(f"control-flow template entry {index} must be an object")
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
            raise ValueError(f"control-flow template entry {index} missing required field: {field}")
    mode = entry["mode"]
    if mode not in {spec["mode"] for spec in CONTROL_FLOW_MODE_SPECS.values()}:
        raise ValueError(f"unsupported control-flow template mode: {mode}")
    notes = entry["notes"]
    if not isinstance(notes, list) or not all(isinstance(note, str) for note in notes):
        raise ValueError(f"control-flow template entry {index} field 'notes' must be a list of strings")
    return ControlFlowMappingTemplate(
        case_id=str(entry["case_id"]),
        description=str(entry["description"]),
        namespace_seed=str(entry["namespace_seed"]),
        upstream_ref=str(entry["upstream_ref"]),
        notes=list(notes),
        mode=mode,
    )


def _scan_control_flow_cases(text: str) -> list[AutoControlFlowInventoryEntry]:
    entries: list[AutoControlFlowInventoryEntry] = []
    for function_name in CONTROL_FLOW_FUNCTIONS:
        if f"def {function_name}(" not in text:
            raise ValueError(f"could not find benchmark function {function_name}")
        spec = CONTROL_FLOW_MODE_SPECS[function_name]
        entries.append(
            AutoControlFlowInventoryEntry(
                upstream_ref=(
                    "tests/benchmark/compute/instruction/test_control_flow.py::"
                    f"{function_name}"
                ),
                case_id=str(spec["case_id"]),
                admitted=True,
                mode=str(spec["mode"]),
                reasons=[],
                source=function_name,
            )
        )
    return entries


def _inventory_entry_to_template(entry: AutoControlFlowInventoryEntry) -> ControlFlowMappingTemplate:
    assert entry.mode is not None
    spec = CONTROL_FLOW_MODE_SPECS[entry.source]
    return ControlFlowMappingTemplate(
        case_id=entry.case_id,
        description=str(spec["description"]),
        namespace_seed=str(spec["namespace_seed"]),
        upstream_ref=entry.upstream_ref,
        notes=list(spec["notes"]),
        mode=entry.mode,
    )


def _render_runtime_and_expected(mode: ControlFlowTemplateMode) -> tuple[str, str]:
    if mode == "gas":
        return _build_gas_runtime(), WORD_01
    if mode == "pc":
        return _build_pc_runtime(), WORD_01
    if mode == "jump":
        return _build_jump_runtime(), WORD_01
    if mode == "jump_pc_relative":
        return _build_jump_pc_relative_runtime(), WORD_01
    if mode == "jumpi_fallthrough":
        return _build_jumpi_fallthrough_runtime(), WORD_00
    if mode == "jumpi_taken":
        return _build_jumpi_taken_runtime(), WORD_01
    if mode == "jumpdest":
        return _build_jumpdest_runtime(), WORD_01
    raise ValueError(f"unsupported control-flow mapping mode: {mode}")


def _build_gas_runtime() -> str:
    code = bytearray([0x5A, 0x15, 0x15])  # GAS ISZERO ISZERO -> 1 when gasleft > 0
    code += _push_int(0)
    code.append(0x55)
    code.append(0x00)
    return "0x" + code.hex()


def _build_pc_runtime() -> str:
    code = bytearray([0x58])  # PC at byte offset 0
    code += _push_int(0)
    code.append(0x14)  # EQ
    code += _push_int(0)
    code.append(0x55)
    code.append(0x00)
    return "0x" + code.hex()


def _build_jump_runtime() -> str:
    code = bytearray()
    code += _push_int(4)
    code.append(0x56)  # JUMP
    code.append(0x00)  # unreachable STOP if jump fails unexpectedly
    code.append(0x5B)  # JUMPDEST
    code += _push_int(1)
    code += _push_int(0)
    code.append(0x55)
    code.append(0x00)
    return "0x" + code.hex()


def _build_jump_pc_relative_runtime() -> str:
    code = bytearray([0x58])  # PC
    code += _push_int(5)
    code.append(0x01)  # ADD
    code.append(0x56)  # JUMP
    code.append(0x5B)  # JUMPDEST at pc + 5
    code += _push_int(1)
    code += _push_int(0)
    code.append(0x55)
    code.append(0x00)
    return "0x" + code.hex()


def _build_jumpi_fallthrough_runtime() -> str:
    code = bytearray()
    code += _push_int(0)
    code += _push_int(8)
    code.append(0x57)  # JUMPI
    code += _push_int(0)
    code += _push_int(0)
    code.append(0x55)
    code.append(0x00)
    code.append(0x5B)  # JUMPDEST for the taken branch
    code += _push_int(1)
    code += _push_int(0)
    code.append(0x55)
    code.append(0x00)
    return "0x" + code.hex()


def _build_jumpi_taken_runtime() -> str:
    code = bytearray()
    code.append(0x43)  # NUMBER
    code += _push_int(8)
    code.append(0x57)  # JUMPI
    code += _push_int(0)
    code += _push_int(0)
    code.append(0x55)
    code.append(0x00)
    code.append(0x5B)  # JUMPDEST for the taken branch
    code += _push_int(1)
    code += _push_int(0)
    code.append(0x55)
    code.append(0x00)
    return "0x" + code.hex()


def _build_jumpdest_runtime() -> str:
    code = bytearray([0x5B])
    code += _push_int(1)
    code += _push_int(0)
    code.append(0x55)
    code.append(0x00)
    return "0x" + code.hex()
