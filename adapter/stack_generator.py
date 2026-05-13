from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from adapter.generator import build_case, deploy_contract_step, invoke_contract_step, wait_receipt_step
from adapter.inventory import write_inventory_payload
from adapter.manifest import resolve_execution_specs_ref
from adapter.assembler import _push_int, _word_hex, _build_init_code


@dataclass(frozen=True, slots=True)
class StackMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: str
    opcode: str


@dataclass(frozen=True, slots=True)
class AutoStackInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str
    opcode: str | None = None


def generate_upstream_stack_templates(
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
        / "third_party" / "execution-specs" / "tests" / "benchmark" / "compute" / "instruction" / "test_stack.py"
    )
    templates, inventory = scan_stack_cases(source)
    payload = {
        "name": "upstream-stack-mapping-templates",
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
            family="stack",
            name="upstream-stack-auto-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload


def generate_upstream_stack_manifest(
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
        else repo_root_path / "suites" / "templates" / "upstream_stack_templates.json"
    )
    data = json.loads(template_file.read_text())
    templates = [
        StackMappingTemplate(
            case_id=entry["case_id"],
            description=entry["description"],
            namespace_seed=entry["namespace_seed"],
            upstream_ref=entry["upstream_ref"],
            notes=list(entry["notes"]),
            mode=entry["mode"],
            opcode=entry["opcode"],
        )
        for entry in data["cases"]
    ]
    execution_specs_ref = resolve_execution_specs_ref(
        repo_root_path / "suites" / "manifests" / "upstream_stack_mapped.json",
        "submodule-pending",
    )
    manifest = {
        "name": "upstream-stack-mapped",
        "version": "1",
        "execution_specs_ref": execution_specs_ref,
        "suite_version": suite_version,
        "chain_profile_version": chain_profile_version,
        "cases": [render_stack_case(template) for template in templates],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def scan_stack_cases(
    source_path: str | Path,
) -> tuple[tuple[StackMappingTemplate, ...], tuple[AutoStackInventoryEntry, ...]]:
    source = Path(source_path)
    text = source.read_text()
    inventory = sorted(
        _scan_parametrized_cases(text, function_name="test_swap", expected_count=16)
        + _scan_parametrized_cases(text, function_name="test_dup", expected_count=16)
        + _scan_parametrized_cases(text, function_name="test_push", expected_count=33),
        key=lambda item: item.upstream_ref,
    )
    templates = tuple(_stack_inventory_entry_to_template(entry) for entry in inventory if entry.admitted)
    return templates, tuple(inventory)


def _scan_parametrized_cases(
    text: str,
    *,
    function_name: str,
    expected_count: int,
) -> list[AutoStackInventoryEntry]:
    block = _extract_param_block(text, function_name=function_name)
    opcodes = [
        match.group("opcode")
        for match in re.finditer(r"Op\.(?P<opcode>[A-Z0-9_]+)", block)
    ]
    family_label = function_name.removeprefix("test_")
    if len(opcodes) != expected_count:
        raise ValueError(
            f"expected {expected_count} {family_label} benchmark cases, found {len(opcodes)}"
        )
    entries: list[AutoStackInventoryEntry] = []
    for opcode in opcodes:
        upstream_ref = (
            "tests/benchmark/compute/instruction/test_stack.py::"
            f"{function_name}[opcode={opcode}]"
        )
        case_id = f"upstream.benchmark.stack.{function_name}.{opcode.lower()}"
        entries.append(
            AutoStackInventoryEntry(
                upstream_ref=upstream_ref,
                case_id=case_id,
                admitted=True,
                mode=function_name,
                reasons=[],
                source=function_name,
                opcode=opcode,
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


def _stack_inventory_entry_to_template(entry: AutoStackInventoryEntry) -> StackMappingTemplate:
    return StackMappingTemplate(
        case_id=entry.case_id,
        description=f"Mapped from execution-specs {entry.opcode} onto an RPC-only deploy/call/storage-assert flow.",
        namespace_seed=f"upstream-stack-{entry.opcode.lower()}",
        upstream_ref=entry.upstream_ref,
        notes=[
            f"Upstream intent: benchmark {entry.opcode}.",
            "RPC mapping: runtime setups stack, executes the opcode, and writes the top item to storage slot0.",
            "Admitted because stack operations are perfectly deterministic and observable in final storage.",
        ],
        mode=entry.mode or "",
        opcode=entry.opcode or "",
    )


OPCODES: dict[str, int] = {
    'PUSH0': 0x5F,
}
for i in range(1, 33):
    OPCODES[f'PUSH{i}'] = 0x5F + i
for i in range(1, 17):
    OPCODES[f'DUP{i}'] = 0x7F + i
for i in range(1, 17):
    OPCODES[f'SWAP{i}'] = 0x8F + i


def _build_stack_runtime(opcode: str) -> str:
    code = bytearray()
    magic = 42
    if opcode.startswith('PUSH'):
        n = int(opcode.removeprefix('PUSH'))
        if n == 0:
            code.append(OPCODES[opcode])
        else:
            code.append(OPCODES[opcode])
            code += magic.to_bytes(n, "big")
    elif opcode.startswith('DUP'):
        n = int(opcode.removeprefix('DUP'))
        code += _push_int(magic)
        for _ in range(n - 1):
            code += _push_int(0)
        code.append(OPCODES[opcode])
    elif opcode.startswith('SWAP'):
        n = int(opcode.removeprefix('SWAP'))
        code += _push_int(magic)
        for _ in range(n):
            code += _push_int(0)
        code.append(OPCODES[opcode])
    else:
        raise ValueError(f"unsupported stack opcode: {opcode}")
    
    code += _push_int(0)
    code.append(0x55)  # SSTORE
    code.append(0x00)  # STOP
    return "0x" + code.hex()


def render_stack_case(template: StackMappingTemplate) -> dict[str, Any]:
    expected_val = 42
    if template.opcode == 'PUSH0':
        expected_val = 0
    
    expected = {"storage": {"0x00": _word_hex(expected_val)}}
    runtime_code = _build_stack_runtime(template.opcode)
    
    observe = {
        "storage_address": "$last_contract",
        "stack_probe": {
            "opcode": template.opcode,
            "expected_result": expected_val,
        },
    }
    case = build_case(
        template,  # type: ignore[arg-type]
        steps=[
            deploy_contract_step(
                init_code=_build_init_code(runtime_code),
                runtime_code=runtime_code,
                gas="0x186a0",
            ),
            wait_receipt_step(),
            invoke_contract_step(data_hex="0x", gas="0xc350"),
            wait_receipt_step(),
        ],
        expected=expected,
    )
    case["family"] = "state/stack"
    case["observe"] = observe
    return case
