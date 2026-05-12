from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from adapter.assembler import _build_init_code, _push_int
from adapter.generator import deploy_contract_step, invoke_contract_step, wait_receipt_step
from adapter.inventory import write_inventory_payload
from adapter.manifest import resolve_execution_specs_ref
from adapter.system_witness import (
    _create_child_code_payload,
    build_create_child_code_system_witness,
    build_create_collision_system_witness,
    build_create_empty_child_system_witness,
    build_return_revert_system_witness,
    build_selfdestruct_single_system_witness,
)


BLOCKED_EXTERNAL_CALL_REASON = "requires multi-address external-call orchestration not yet mapped"
BLOCKED_CREATE_REASON = "requires create/create2 deployed-address witness not yet mapped"
BLOCKED_CREATE_COLLISION_REASON = "requires gas-capped create collision orchestration not yet mapped"
BLOCKED_CREATE_COLLISION_CREATE_REASON = "requires mutable pre-allocation of future CREATE addresses not available through the current RPC-only harness"
BLOCKED_SELFDESTRUCT_REASON = "requires selfdestruct lifecycle witness not yet mapped"

SystemTemplateMode = Literal["return_revert_self_call", "create_empty_child", "create_child_code", "create_collision", "selfdestruct_single"]
SYSTEM_DEFAULT_DEPLOY_GAS = 0x186A0
SYSTEM_DEPLOY_BASE_GAS = 32_000
SYSTEM_DEPLOY_CODE_DEPOSIT_GAS_PER_BYTE = 200
SYSTEM_DEPLOY_INITCODE_COPY_GAS_PER_BYTE = 20
SYSTEM_DEPLOY_GAS_MARGIN = 50_000


@dataclass(frozen=True, slots=True)
class SystemMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: SystemTemplateMode
    opcode: str
    return_size: int | None = None
    return_non_zero_data: bool | None = None
    create_value: int | None = None
    create_initcode_size: int | None = None
    create_data_kind: str | None = None
    create_salt: int | None = None
    proxy_call_gas: int | None = None
    selfdestruct_scenario: str | None = None
    hardfork_semantics: str | None = None


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
    create_value: int | None = None
    create_initcode_size: int | None = None
    create_data_kind: str | None = None
    create_salt: int | None = None
    proxy_call_gas: int | None = None
    selfdestruct_scenario: str | None = None
    hardfork_semantics: str | None = None


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
    if template.mode == "return_revert_self_call":
        return _render_return_revert_system_case(template)
    if template.mode == "create_empty_child":
        return _render_create_empty_child_system_case(template)
    if template.mode == "create_child_code":
        return _render_create_child_code_system_case(template)
    if template.mode == "create_collision":
        return _render_create_collision_system_case(template)
    if template.mode == "selfdestruct_single":
        return _render_selfdestruct_single_system_case(template)
    raise ValueError(f"unsupported system template mode: {template.mode}")


def _render_return_revert_system_case(template: SystemMappingTemplate) -> dict[str, Any]:
    return_size = _require_inventory_field(template.return_size, field="return_size")
    return_non_zero_data = _require_inventory_field(
        template.return_non_zero_data,
        field="return_non_zero_data",
    )
    payload = _payload_bytes(return_size, return_non_zero_data)
    runtime_code = _build_return_revert_wrapper_runtime(template)
    witness = build_return_revert_system_witness(
        opcode=template.opcode,
        returndata_size=return_size,
        returndata_payload=payload,
    )
    return _render_system_case_payload(
        template=template,
        runtime_code=runtime_code,
        witness=witness,
        invoke_gas=_invoke_gas(return_size),
    )


def _render_create_empty_child_system_case(template: SystemMappingTemplate) -> dict[str, Any]:
    create_value = _require_inventory_field(template.create_value, field="create_value")
    initcode_size = _require_inventory_field(template.create_initcode_size, field="create_initcode_size")
    runtime_code = _build_create_empty_child_runtime(template.opcode, value=create_value)
    witness = build_create_empty_child_system_witness(
        opcode=template.opcode,
        value=create_value,
        initcode_size=initcode_size,
        salt=template.create_salt,
    )
    return _render_system_case_payload(
        template=template,
        runtime_code=runtime_code,
        witness=witness,
        invoke_gas="0x1e8480",
    )


def _render_create_child_code_system_case(template: SystemMappingTemplate) -> dict[str, Any]:
    create_value = _require_inventory_field(template.create_value, field="create_value")
    initcode_size = _require_inventory_field(template.create_initcode_size, field="create_initcode_size")
    data_kind = _require_inventory_field(template.create_data_kind, field="create_data_kind")
    runtime_code = _build_create_child_code_runtime(
        template.opcode,
        initcode_size=initcode_size,
        data_kind=data_kind,
    )
    witness = build_create_child_code_system_witness(
        opcode=template.opcode,
        value=create_value,
        initcode_size=initcode_size,
        data_kind=data_kind,
        salt=template.create_salt,
    )
    return _render_system_case_payload(
        template=template,
        runtime_code=runtime_code,
        witness=witness,
        invoke_gas="0x4c4b40",
        deploy_gas=_deploy_gas_for_runtime(runtime_code),
    )


def _render_create_collision_system_case(template: SystemMappingTemplate) -> dict[str, Any]:
    proxy_call_gas = _require_inventory_field(template.proxy_call_gas, field="proxy_call_gas")
    runtime_code = _build_create_collision_runtime(template.opcode, proxy_call_gas=proxy_call_gas)
    witness = build_create_collision_system_witness(
        opcode=template.opcode,
        value=template.create_value or 0,
        initcode_size=template.create_initcode_size or 0,
        salt=template.create_salt or 0,
        proxy_call_gas=proxy_call_gas,
    )
    return _render_system_case_payload(
        template=template,
        runtime_code=runtime_code,
        witness=witness,
        invoke_gas="0x1e8480",
        deploy_gas=_deploy_gas_for_runtime(runtime_code),
    )


def _render_selfdestruct_single_system_case(template: SystemMappingTemplate) -> dict[str, Any]:
    value = _require_inventory_field(template.create_value, field="create_value")
    scenario = _require_inventory_field(template.selfdestruct_scenario, field="selfdestruct_scenario")
    hardfork_semantics = _require_inventory_field(template.hardfork_semantics, field="hardfork_semantics")
    if scenario == "created":
        runtime_code = _build_selfdestruct_created_runtime(value=value)
        invoke_steps = None
    elif scenario == "existing":
        runtime_code = _build_selfdestruct_existing_runtime(value=value)
        invoke_steps = [
            invoke_contract_step(data_hex=_selfdestruct_existing_mode_data(0), gas="0x1e8480"),
            wait_receipt_step(),
            invoke_contract_step(data_hex=_selfdestruct_existing_mode_data(1), gas="0x1e8480"),
            wait_receipt_step(),
        ]
    else:
        raise ValueError(f"unsupported selfdestruct scenario: {scenario}")
    witness = build_selfdestruct_single_system_witness(
        scenario=scenario,
        value=value,
        hardfork_semantics=hardfork_semantics,
    )
    return _render_system_case_payload(
        template=template,
        runtime_code=runtime_code,
        witness=witness,
        invoke_gas="0x1e8480",
        deploy_gas=_deploy_gas_for_runtime(runtime_code),
        invoke_steps=invoke_steps,
    )


def _render_system_case_payload(
    *,
    template: SystemMappingTemplate,
    runtime_code: str,
    witness: Any,
    invoke_gas: str,
    deploy_gas: str | None = None,
    invoke_steps: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "kind": "upstream_mapped",
        "case_id": template.case_id,
        "family": "state/system",
        "description": template.description,
        "namespace_seed": template.namespace_seed,
        "upstream_ref": template.upstream_ref,
        "notes": template.notes + list(witness.notes),
        "observe": witness.observe,
        "filters": {},
        "steps": [
            deploy_contract_step(
                init_code=_build_init_code(runtime_code),
                runtime_code=runtime_code,
                gas=deploy_gas or hex(SYSTEM_DEFAULT_DEPLOY_GAS),
                value="0x" + format(template.create_value, "x") if template.create_value else None,
            ),
            wait_receipt_step(),
            *(invoke_steps if invoke_steps is not None else [
                invoke_contract_step(data_hex="0x", gas=invoke_gas),
                wait_receipt_step(),
            ]),
        ],
        "expected": {
            "receipt_status": "0x1",
            **witness.expected,
        },
    }


def _runtime_byte_length(runtime_code: str) -> int:
    return len(bytes.fromhex(runtime_code.removeprefix("0x")))


def _deploy_gas_for_runtime(runtime_code: str) -> str:
    runtime_bytes = _runtime_byte_length(runtime_code)
    initcode_bytes = _runtime_byte_length(_build_init_code(runtime_code))
    budget = (
        SYSTEM_DEPLOY_BASE_GAS
        + SYSTEM_DEPLOY_CODE_DEPOSIT_GAS_PER_BYTE * runtime_bytes
        + SYSTEM_DEPLOY_INITCODE_COPY_GAS_PER_BYTE * initcode_bytes
        + SYSTEM_DEPLOY_GAS_MARGIN
    )
    return hex(max(SYSTEM_DEFAULT_DEPLOY_GAS, budget))


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
            is_empty_admitted = combo_label in {"0 bytes without value", "0 bytes with value"}
            create_child_code_size = _create_child_code_size_for_label(combo_label)
            is_child_code_admitted = create_child_code_size in {6144, 12288, 18432, 24576}
            admitted = is_empty_admitted or is_child_code_admitted
            create_value = 1 if combo_label == "0 bytes with value" else 0
            create_data_kind = "non_zero" if "non-zero data" in combo_label else "zero" if is_child_code_admitted else None
            results.append(
                AutoSystemInventoryEntry(
                    upstream_ref=upstream_ref,
                    case_id=case_id,
                    admitted=admitted,
                    mode=(
                        "create_empty_child"
                        if is_empty_admitted
                        else "create_child_code"
                        if is_child_code_admitted
                        else None
                    ),
                    reasons=[] if admitted else [BLOCKED_CREATE_REASON],
                    source="test_create",
                    opcode=opcode if admitted else None,
                    create_value=create_value if admitted else None,
                    create_initcode_size=create_child_code_size if is_child_code_admitted else 0 if is_empty_admitted else None,
                    create_data_kind=create_data_kind,
                    create_salt=42 if admitted and opcode == "CREATE2" else None,
                )
            )
    return results


def _create_child_code_size_for_label(combo_label: str) -> int | None:
    ratio_to_size = {
        "0.25x": 6144,
        "0.50x": 12288,
        "0.75x": 18432,
        "max": 24576,
    }
    if "max code size" not in combo_label:
        return None
    if combo_label.startswith("0.25x"):
        return ratio_to_size["0.25x"]
    if combo_label.startswith("0.50x"):
        return ratio_to_size["0.50x"]
    if combo_label.startswith("0.75x"):
        return ratio_to_size["0.75x"]
    if combo_label.startswith("max code size"):
        return ratio_to_size["max"]
    raise ValueError(f"unsupported create max-code-size label: {combo_label}")


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
    results: list[AutoSystemInventoryEntry] = []
    for opcode in opcodes:
        admitted = opcode == "CREATE2"
        results.append(
            AutoSystemInventoryEntry(
                upstream_ref=f"tests/benchmark/compute/instruction/test_system.py::test_creates_collisions[opcode={opcode}]",
                case_id=f"upstream.benchmark.system.test_creates_collisions.{opcode.lower()}",
                admitted=admitted,
                mode="create_collision" if admitted else None,
                reasons=[] if admitted else [BLOCKED_CREATE_COLLISION_CREATE_REASON],
                source="test_creates_collisions",
                opcode=opcode if admitted else None,
                create_value=0 if admitted else None,
                create_initcode_size=0 if admitted else None,
                create_salt=0 if admitted else None,
                proxy_call_gas=100_000 if admitted else None,
            )
        )
    return results


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
    return _scan_value_bearing_cases(text, function_name="test_selfdestruct_existing", admitted=True, scenario="existing")


def _scan_selfdestruct_created(text: str) -> list[AutoSystemInventoryEntry]:
    return _scan_value_bearing_cases(text, function_name="test_selfdestruct_created", admitted=True, scenario="created")


def _scan_selfdestruct_initcode(text: str) -> list[AutoSystemInventoryEntry]:
    return _scan_value_bearing_cases(text, function_name="test_selfdestruct_initcode")


def _scan_value_bearing_cases(
    text: str,
    *,
    function_name: str,
    admitted: bool = False,
    scenario: str | None = None,
) -> list[AutoSystemInventoryEntry]:
    block = _extract_param_block(text, function_name=function_name)
    values = [
        _parse_bool_literal(value)
        for value in _extract_param_values_from_block(block, "value_bearing", function_name=function_name)
    ]
    admitted_scenario = scenario or ("created" if admitted else None)
    return [
        AutoSystemInventoryEntry(
            upstream_ref=f"tests/benchmark/compute/instruction/test_system.py::{function_name}[value_bearing={value}]",
            case_id=f"upstream.benchmark.system.{function_name}.value_bearing_{str(value).lower()}",
            admitted=admitted,
            mode="selfdestruct_single" if admitted else None,
            reasons=[] if admitted else [BLOCKED_SELFDESTRUCT_REASON],
            source=function_name,
            create_value=1 if admitted and value else 0 if admitted else None,
            selfdestruct_scenario=admitted_scenario if admitted else None,
            hardfork_semantics="cancun" if admitted else None,
        )
        for value in values
    ]


def _inventory_entry_to_template(entry: AutoSystemInventoryEntry) -> SystemMappingTemplate:
    if entry.mode == "return_revert_self_call":
        return _return_revert_inventory_entry_to_template(entry)
    if entry.mode == "create_empty_child":
        return _create_empty_child_inventory_entry_to_template(entry)
    if entry.mode == "create_child_code":
        return _create_child_code_inventory_entry_to_template(entry)
    if entry.mode == "create_collision":
        return _create_collision_inventory_entry_to_template(entry)
    if entry.mode == "selfdestruct_single":
        return _selfdestruct_single_inventory_entry_to_template(entry)
    raise ValueError(f"unsupported admitted system mode: {entry.mode}")


def _return_revert_inventory_entry_to_template(entry: AutoSystemInventoryEntry) -> SystemMappingTemplate:
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


def _create_empty_child_inventory_entry_to_template(entry: AutoSystemInventoryEntry) -> SystemMappingTemplate:
    opcode = _require_inventory_field(entry.opcode, field="opcode")
    create_value = _require_inventory_field(entry.create_value, field="create_value")
    create_initcode_size = _require_inventory_field(entry.create_initcode_size, field="create_initcode_size")
    return SystemMappingTemplate(
        case_id=entry.case_id,
        description=(
            f"Mapped from execution-specs {opcode} zero-byte create benchmark onto a single wrapper "
            "that stores create success, created address, and created code size."
        ),
        namespace_seed=_build_namespace_seed(entry.case_id),
        upstream_ref=entry.upstream_ref,
        notes=_build_create_empty_child_notes(opcode=opcode, value=create_value),
        mode="create_empty_child",
        opcode=opcode,
        create_value=create_value,
        create_initcode_size=create_initcode_size,
        create_salt=entry.create_salt,
    )


def _create_child_code_inventory_entry_to_template(entry: AutoSystemInventoryEntry) -> SystemMappingTemplate:
    opcode = _require_inventory_field(entry.opcode, field="opcode")
    create_value = _require_inventory_field(entry.create_value, field="create_value")
    create_initcode_size = _require_inventory_field(entry.create_initcode_size, field="create_initcode_size")
    create_data_kind = _require_inventory_field(entry.create_data_kind, field="create_data_kind")
    return SystemMappingTemplate(
        case_id=entry.case_id,
        description=(
            f"Mapped from execution-specs {opcode} non-empty {create_data_kind.replace('_', '-')} data create benchmark onto a single wrapper "
            "that stores create success, created address, created code size, and created code hash."
        ),
        namespace_seed=_build_namespace_seed(entry.case_id),
        upstream_ref=entry.upstream_ref,
        notes=_build_create_child_code_notes(
            opcode=opcode,
            initcode_size=create_initcode_size,
            data_kind=create_data_kind,
        ),
        mode="create_child_code",
        opcode=opcode,
        create_value=create_value,
        create_initcode_size=create_initcode_size,
        create_data_kind=create_data_kind,
        create_salt=entry.create_salt,
    )


def _create_collision_inventory_entry_to_template(entry: AutoSystemInventoryEntry) -> SystemMappingTemplate:
    opcode = _require_inventory_field(entry.opcode, field="opcode")
    create_value = _require_inventory_field(entry.create_value, field="create_value")
    create_initcode_size = _require_inventory_field(entry.create_initcode_size, field="create_initcode_size")
    proxy_call_gas = _require_inventory_field(entry.proxy_call_gas, field="proxy_call_gas")
    return SystemMappingTemplate(
        case_id=entry.case_id,
        description=(
            f"Mapped from execution-specs {opcode} collision benchmark onto a single wrapper that deploys a proxy, "
            "calls it once to create an empty child, then calls it again with the same CREATE2 salt to observe collision failure."
        ),
        namespace_seed=_build_namespace_seed(entry.case_id),
        upstream_ref=entry.upstream_ref,
        notes=_build_create_collision_notes(opcode=opcode, proxy_call_gas=proxy_call_gas),
        mode="create_collision",
        opcode=opcode,
        create_value=create_value,
        create_initcode_size=create_initcode_size,
        create_salt=entry.create_salt,
        proxy_call_gas=proxy_call_gas,
    )


def _selfdestruct_single_inventory_entry_to_template(entry: AutoSystemInventoryEntry) -> SystemMappingTemplate:
    create_value = _require_inventory_field(entry.create_value, field="create_value")
    scenario = _require_inventory_field(entry.selfdestruct_scenario, field="selfdestruct_scenario")
    hardfork_semantics = _require_inventory_field(entry.hardfork_semantics, field="hardfork_semantics")
    scenario_label = "existing-account" if scenario == "existing" else "created-child"
    lifecycle = (
        "first creates and stores a persistent child in setup mode, then calls the stored child in execution mode"
        if scenario == "existing"
        else "creates a child, calls it so SELFDESTRUCT executes in the same transaction"
    )
    return SystemMappingTemplate(
        case_id=entry.case_id,
        description=(
            f"Mapped from execution-specs SELFDESTRUCT {scenario_label} benchmark onto a single persistent wrapper that {lifecycle} "
            "and stores final-state witness fields."
        ),
        namespace_seed=_build_namespace_seed(entry.case_id),
        upstream_ref=entry.upstream_ref,
        notes=_build_selfdestruct_single_notes(scenario=scenario, value=create_value, hardfork_semantics=hardfork_semantics),
        mode="selfdestruct_single",
        opcode="SELFDESTRUCT",
        create_value=create_value,
        selfdestruct_scenario=scenario,
        hardfork_semantics=hardfork_semantics,
    )


def _load_system_template_entry(entry: object, *, index: int) -> SystemMappingTemplate:
    if not isinstance(entry, dict):
        raise ValueError(f"system template entry {index} must be an object")
    common_required_fields = (
        "case_id",
        "description",
        "namespace_seed",
        "upstream_ref",
        "notes",
        "mode",
        "opcode",
    )
    for field in common_required_fields:
        if field not in entry:
            raise ValueError(f"system template entry {index} missing required field: {field}")
    notes = entry["notes"]
    if not isinstance(notes, list) or not all(isinstance(note, str) for note in notes):
        raise ValueError(f"system template entry {index} field 'notes' must be a list of strings")
    mode = entry["mode"]
    opcode = str(entry["opcode"])
    common = {
        "case_id": str(entry["case_id"]),
        "description": str(entry["description"]),
        "namespace_seed": str(entry["namespace_seed"]),
        "upstream_ref": str(entry["upstream_ref"]),
        "notes": list(notes),
        "opcode": opcode,
    }
    if mode == "return_revert_self_call":
        for field in ("return_size", "return_non_zero_data"):
            if field not in entry:
                raise ValueError(f"system template entry {index} missing required field: {field}")
        if opcode not in {"RETURN", "REVERT"}:
            raise ValueError(f"unsupported system template opcode: {opcode}")
        return SystemMappingTemplate(
            **common,
            mode="return_revert_self_call",
            return_size=int(entry["return_size"]),
            return_non_zero_data=bool(entry["return_non_zero_data"]),
        )
    if mode == "create_empty_child":
        for field in ("create_value", "create_initcode_size"):
            if field not in entry:
                raise ValueError(f"system template entry {index} missing required field: {field}")
        if opcode not in {"CREATE", "CREATE2"}:
            raise ValueError(f"unsupported system template opcode: {opcode}")
        return SystemMappingTemplate(
            **common,
            mode="create_empty_child",
            create_value=int(entry["create_value"]),
            create_initcode_size=int(entry["create_initcode_size"]),
            create_salt=None if entry.get("create_salt") is None else int(entry["create_salt"]),
        )
    if mode == "create_child_code":
        for field in ("create_value", "create_initcode_size", "create_data_kind"):
            if field not in entry:
                raise ValueError(f"system template entry {index} missing required field: {field}")
        if opcode not in {"CREATE", "CREATE2"}:
            raise ValueError(f"unsupported system template opcode: {opcode}")
        return SystemMappingTemplate(
            **common,
            mode="create_child_code",
            create_value=int(entry["create_value"]),
            create_initcode_size=int(entry["create_initcode_size"]),
            create_data_kind=str(entry["create_data_kind"]),
            create_salt=None if entry.get("create_salt") is None else int(entry["create_salt"]),
        )
    if mode == "create_collision":
        for field in ("create_value", "create_initcode_size", "create_salt", "proxy_call_gas"):
            if field not in entry:
                raise ValueError(f"system template entry {index} missing required field: {field}")
        if opcode != "CREATE2":
            raise ValueError(f"unsupported system template opcode for create_collision: {opcode}")
        return SystemMappingTemplate(
            **common,
            mode="create_collision",
            create_value=int(entry["create_value"]),
            create_initcode_size=int(entry["create_initcode_size"]),
            create_salt=int(entry["create_salt"]),
            proxy_call_gas=int(entry["proxy_call_gas"]),
        )
    if mode == "selfdestruct_single":
        for field in ("create_value", "selfdestruct_scenario", "hardfork_semantics"):
            if field not in entry:
                raise ValueError(f"system template entry {index} missing required field: {field}")
        if opcode != "SELFDESTRUCT":
            raise ValueError(f"unsupported system template opcode for selfdestruct_single: {opcode}")
        return SystemMappingTemplate(
            **common,
            mode="selfdestruct_single",
            create_value=int(entry["create_value"]),
            selfdestruct_scenario=str(entry["selfdestruct_scenario"]),
            hardfork_semantics=str(entry["hardfork_semantics"]),
        )
    raise ValueError(f"unsupported system template mode: {mode}")


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


def _build_create_empty_child_notes(*, opcode: str, value: int) -> list[str]:
    salt_note = " with CREATE2 salt 42" if opcode == "CREATE2" else ""
    value_note = "zero value" if value == 0 else f"value {value}"
    balance_note = "" if value == 0 else " and child balance"
    return [
        f"Upstream intent: benchmark {opcode} with zero-byte initcode and {value_note}.",
        f"RPC mapping: a single funded deployed wrapper performs one {value_note} {opcode}{salt_note}, then stores create success, the returned child address, EXTCODESIZE(child){balance_note} as deterministic witness fields.",
        "Only zero-byte variants are admitted; non-empty/max-code-size variants remain blocked until their code-size witness contracts are mapped.",
        f"Admitted because final receipt status plus wrapper-exposed create success, nonzero child address, zero child code size{balance_note} are deterministic final observables.",
    ]


def _build_create_child_code_notes(*, opcode: str, initcode_size: int, data_kind: str) -> list[str]:
    salt_note = " with CREATE2 salt 42" if opcode == "CREATE2" else ""
    data_label = data_kind.replace("_", "-")
    blocked_neighbor_note = (
        "Only the smallest non-zero-data and zero-data non-empty variants are admitted; larger code-size ratios and value-bearing non-empty variants remain blocked until separate witness contracts are mapped."
    )
    return [
        f"Upstream intent: benchmark {opcode} with {initcode_size}-byte {data_label} initcode that deploys {initcode_size}-byte child code.",
        f"RPC mapping: a single deployed wrapper performs one zero value {opcode}{salt_note}, then stores create success, the returned child address, EXTCODESIZE(child), and EXTCODEHASH(child) as deterministic witness fields.",
        blocked_neighbor_note,
        "Admitted because final receipt status plus wrapper-exposed create success, nonzero child address, child code size, and child code hash are deterministic final observables.",
    ]


def _build_create_collision_notes(*, opcode: str, proxy_call_gas: int) -> list[str]:
    return [
        f"Upstream intent: benchmark {opcode} collision behavior with empty initcode.",
        "RPC mapping: a single wrapper deploys a proxy, calls it once to perform CREATE2 with salt 0 and empty initcode, then calls the same proxy again with the same salt so the second CREATE2 collides.",
        f"The proxy call gas is capped at {proxy_call_gas} so the collision exhausts only the inner frame while the outer wrapper retains gas to store witness slots.",
        "CREATE collision remains blocked because upstream depends on mutable pre-allocation of future CREATE addresses, which the current RPC-only harness cannot reproduce.",
        "Admitted because final receipt status plus wrapper-exposed proxy deploy success, first create result, child code size, collision call failure, and collision returndata size are deterministic final observables.",
    ]


def _build_selfdestruct_single_notes(*, scenario: str, value: int, hardfork_semantics: str) -> list[str]:
    value_note = "zero value" if value == 0 else "value 1"
    if scenario == "existing":
        return [
            f"Upstream intent: benchmark SELFDESTRUCT for an existing child with {value_note} under {hardfork_semantics} semantics.",
            "RPC mapping: a single persistent wrapper uses two ordinary invocations: setup mode CREATE2s and stores a child whose runtime is CALLER; SELFDESTRUCT, then execution mode CALLs the stored child.",
            "Setup mode stores setup_create_success, child address, and EXTCODESIZE(child) before execution; execution mode stores call success, post-call EXTCODESIZE(child), and optional beneficiary balance.",
            "The existing-account scenario is admitted because post-Cancun SELFDESTRUCT preserves pre-existing code, making setup/execution lifecycle evidence deterministic without traces or mutable prestate.",
            "Initcode SELFDESTRUCT variants remain blocked until their CREATE-result semantics are mapped separately.",
            "Admitted because final receipt status plus wrapper-exposed setup create success, child address, pre/post child code sizes, call success, and optional beneficiary balance are deterministic final observables.",
        ]
    return [
        f"Upstream intent: benchmark SELFDESTRUCT for a {scenario} child with {value_note} under {hardfork_semantics} semantics.",
        "RPC mapping: a single wrapper creates a child whose runtime is CALLER; SELFDESTRUCT, calls it in the same transaction, then stores create success, child address, call success, and post-call child code size.",
        "The created-child scenario is admitted because same-transaction create plus SELFDESTRUCT has deterministic final-state evidence under Cancun without requiring traces or mutable prestate.",
        "Existing-account SELFDESTRUCT variants use a separate setup/execution wrapper; initcode SELFDESTRUCT variants remain blocked until their CREATE-result semantics are mapped separately.",
        "Admitted because final receipt status plus wrapper-exposed child address, call success, post-call code size, and optional beneficiary balance are deterministic final observables.",
    ]


def _selfdestruct_existing_mode_data(mode: int) -> str:
    if mode not in {0, 1}:
        raise ValueError("selfdestruct existing mode must be 0 or 1")
    return "0x" + mode.to_bytes(32, "big").hex()


def _selfdestruct_child_initcode() -> bytes:
    child_runtime = bytes([0x33, 0xFF])  # CALLER; SELFDESTRUCT
    return bytes.fromhex(_build_init_code("0x" + child_runtime.hex())[2:])


def _build_selfdestruct_existing_runtime(*, value: int = 0) -> str:
    if value not in {0, 1}:
        raise ValueError("selfdestruct existing value must be 0 or 1")
    child_initcode = _selfdestruct_child_initcode()

    builder = _BytecodeBuilder()
    builder.push_int(0)
    builder.op(0x35)  # CALLDATALOAD(0) mode: 0 = setup, nonzero = execution
    builder.push_label("execute")
    builder.op(0x57)  # JUMPI

    builder.push_int(len(child_initcode))
    builder.push_label("child_initcode")
    builder.push_int(0)
    builder.op(0x39)  # CODECOPY(0, child_initcode_offset, child_initcode_size)
    builder.push_int(42)
    builder.push_int(len(child_initcode))
    builder.push_int(0)
    builder.push_int(value)
    builder.op(0xF5)  # CREATE2 persistent child

    builder.op(0x80)  # DUP1 child_address
    builder.op(0x15)
    builder.op(0x15)
    builder.push_int(0)
    builder.op(0x55)  # slot0 <- setup_create_success

    builder.op(0x80)  # DUP1 child_address
    builder.push_int(1)
    builder.op(0x55)  # slot1 <- child_address

    builder.op(0x80)  # DUP1 child_address
    builder.op(0x3B)  # EXTCODESIZE(child) before execution
    builder.push_int(2)
    builder.op(0x55)  # slot2 <- child_code_size_before

    builder.op(0x50)  # POP child_address
    builder.op(0x00)  # STOP

    builder.mark("execute")
    builder.push_int(1)
    builder.op(0x54)  # SLOAD slot1 child_address

    builder.push_int(0)  # out_size
    builder.push_int(0)  # out_offset
    builder.push_int(0)  # in_size
    builder.push_int(0)  # in_offset
    builder.push_int(0)  # value
    builder.op(0x85)  # DUP6 child_address
    builder.op(0x5A)  # GAS
    builder.op(0xF1)  # CALL child; child selfdestructs to wrapper
    builder.push_int(3)
    builder.op(0x55)  # slot3 <- selfdestruct_call_success

    builder.op(0x80)  # DUP1 child_address
    builder.op(0x3B)  # EXTCODESIZE(child) after call
    builder.push_int(4)
    builder.op(0x55)  # slot4 <- child_code_size_after

    if value > 0:
        builder.op(0x30)  # ADDRESS
        builder.op(0x31)  # BALANCE(wrapper)
        builder.push_int(5)
        builder.op(0x55)  # slot5 <- beneficiary_balance_after

    builder.op(0x50)  # POP child_address
    builder.op(0x00)  # STOP
    builder.labels["child_initcode"] = len(builder.code)
    builder.extend(child_initcode)
    return "0x" + builder.finish().hex()


def _build_selfdestruct_created_runtime(*, value: int = 0) -> str:
    if value not in {0, 1}:
        raise ValueError("selfdestruct created value must be 0 or 1")
    child_initcode = _selfdestruct_child_initcode()

    builder = _BytecodeBuilder()
    builder.push_int(len(child_initcode))
    builder.push_label("child_initcode")
    builder.push_int(0)
    builder.op(0x39)  # CODECOPY(0, child_initcode_offset, child_initcode_size)
    builder.push_int(len(child_initcode))
    builder.push_int(0)
    builder.push_int(value)
    builder.op(0xF0)  # CREATE child

    builder.op(0x80)  # DUP1 child_address
    builder.op(0x15)
    builder.op(0x15)
    builder.push_int(0)
    builder.op(0x55)  # slot0 <- create_success

    builder.op(0x80)  # DUP1 child_address
    builder.push_int(1)
    builder.op(0x55)  # slot1 <- child_address

    builder.push_int(0)  # out_size
    builder.push_int(0)  # out_offset
    builder.push_int(0)  # in_size
    builder.push_int(0)  # in_offset
    builder.push_int(0)  # value
    builder.op(0x85)  # DUP6 child_address
    builder.op(0x5A)  # GAS
    builder.op(0xF1)  # CALL child; child selfdestructs to wrapper
    builder.push_int(2)
    builder.op(0x55)  # slot2 <- selfdestruct_call_success

    builder.op(0x80)  # DUP1 child_address
    builder.op(0x3B)  # EXTCODESIZE(child) after call
    builder.push_int(3)
    builder.op(0x55)  # slot3 <- child_code_size_after

    if value > 0:
        builder.op(0x30)  # ADDRESS
        builder.op(0x31)  # BALANCE(wrapper)
        builder.push_int(4)
        builder.op(0x55)  # slot4 <- beneficiary_balance_after

    builder.op(0x50)  # POP child_address
    builder.op(0x00)  # STOP
    builder.labels["child_initcode"] = len(builder.code)
    builder.extend(child_initcode)
    return "0x" + builder.finish().hex()


def _build_create_empty_child_runtime(opcode: str, *, value: int = 0) -> str:
    builder = _BytecodeBuilder()
    if opcode == "CREATE":
        builder.push_int(0)  # size
        builder.push_int(0)  # offset
        builder.push_int(value)  # value
        builder.op(0xF0)  # CREATE
    elif opcode == "CREATE2":
        builder.push_int(42)  # salt
        builder.push_int(0)  # size
        builder.push_int(0)  # offset
        builder.push_int(value)  # value
        builder.op(0xF5)  # CREATE2
    else:
        raise ValueError(f"unsupported create-empty opcode: {opcode}")

    builder.op(0x80)  # DUP1
    builder.push_int(1)
    builder.op(0x55)  # SSTORE slot1 <- created address

    builder.op(0x80)  # DUP1
    builder.op(0x3B)  # EXTCODESIZE
    builder.push_int(2)
    builder.op(0x55)  # SSTORE slot2 <- created code size

    if value > 0:
        builder.op(0x80)  # DUP1
        builder.op(0x31)  # BALANCE
        builder.push_int(3)
        builder.op(0x55)  # SSTORE slot3 <- created balance

    builder.op(0x15)  # ISZERO
    builder.op(0x15)  # ISZERO
    builder.push_int(0)
    builder.op(0x55)  # SSTORE slot0 <- success bool
    builder.op(0x00)  # STOP
    return "0x" + builder.finish().hex()


def _build_create_child_code_runtime(opcode: str, *, initcode_size: int, data_kind: str) -> str:
    child_code = _create_child_code_payload(initcode_size=initcode_size, data_kind=data_kind)
    if data_kind == "zero":
        builder = _BytecodeBuilder()
        builder.push_int(initcode_size)
        builder.push_int(0)
        builder.op(0xF3)  # child initcode: RETURN(0, initcode_size) from zero memory
        initcode = builder.finish()
    elif data_kind == "non_zero":
        initcode = child_code
    else:
        raise ValueError(f"unsupported create child code data kind: {data_kind}")

    runtime = _BytecodeBuilder()
    runtime.push_int(len(initcode))
    runtime.push_label("initcode")
    runtime.push_int(0)
    runtime.op(0x39)  # CODECOPY(0, initcode_offset, initcode_size)
    if opcode == "CREATE":
        runtime.push_int(len(initcode))
        runtime.push_int(0)
        runtime.push_int(0)
        runtime.op(0xF0)  # CREATE
    elif opcode == "CREATE2":
        runtime.push_int(42)
        runtime.push_int(len(initcode))
        runtime.push_int(0)
        runtime.push_int(0)
        runtime.op(0xF5)  # CREATE2
    else:
        raise ValueError(f"unsupported create-child-code opcode: {opcode}")

    runtime.op(0x80)  # DUP1
    runtime.push_int(1)
    runtime.op(0x55)  # SSTORE slot1 <- created address

    runtime.op(0x80)  # DUP1
    runtime.op(0x3B)  # EXTCODESIZE
    runtime.push_int(2)
    runtime.op(0x55)  # SSTORE slot2 <- created code size

    runtime.op(0x80)  # DUP1
    runtime.op(0x3F)  # EXTCODEHASH
    runtime.push_int(3)
    runtime.op(0x55)  # SSTORE slot3 <- created code hash

    runtime.op(0x15)  # ISZERO
    runtime.op(0x15)  # ISZERO
    runtime.push_int(0)
    runtime.op(0x55)  # SSTORE slot0 <- success bool
    runtime.op(0x00)  # STOP
    runtime.labels["initcode"] = len(runtime.code)
    runtime.extend(initcode)
    return "0x" + runtime.finish().hex()


def _build_create_collision_runtime(opcode: str, *, proxy_call_gas: int = 100_000) -> str:
    if opcode != "CREATE2":
        raise ValueError("create_collision runtime is only supported for CREATE2 under the RPC-only proof model")
    if proxy_call_gas <= 0:
        raise ValueError("create_collision proxy_call_gas must be positive")

    proxy = _BytecodeBuilder()
    proxy.push_int(0)  # salt
    proxy.push_int(0)  # size
    proxy.push_int(0)  # offset
    proxy.push_int(0)  # value
    proxy.op(0xF5)  # CREATE2
    proxy.push_int(0)
    proxy.op(0x52)  # MSTORE(0, created_address)
    proxy.push_int(32)
    proxy.push_int(0)
    proxy.op(0xF3)  # RETURN(0, 32)
    proxy_runtime = proxy.finish()
    proxy_initcode = bytes.fromhex(_build_init_code("0x" + proxy_runtime.hex())[2:])

    builder = _BytecodeBuilder()
    builder.push_int(len(proxy_initcode))
    builder.push_label("proxy_initcode")
    builder.push_int(0)
    builder.op(0x39)  # CODECOPY(0, proxy_initcode_offset, proxy_initcode_size)
    builder.push_int(len(proxy_initcode))
    builder.push_int(0)
    builder.push_int(0)
    builder.op(0xF0)  # CREATE proxy

    builder.op(0x80)  # DUP1 proxy_address
    builder.op(0x15)
    builder.op(0x15)
    builder.push_int(0)
    builder.op(0x55)  # slot0 <- proxy_deploy_success

    builder.op(0x80)  # DUP1 proxy_address
    builder.push_int(0)  # out_size
    builder.push_int(0)  # out_offset
    builder.push_int(0)  # in_size
    builder.push_int(0)  # in_offset
    builder.push_int(0)  # value
    builder.op(0x85)  # DUP6 proxy_address
    builder.push_int(proxy_call_gas)
    builder.op(0xF1)  # CALL proxy first time
    builder.push_int(1)
    builder.op(0x55)  # slot1 <- first_create_call_success

    builder.push_int(32)
    builder.push_int(0)
    builder.push_int(0)
    builder.op(0x3E)  # RETURNDATACOPY(0, 0, 32)
    builder.push_int(0)
    builder.op(0x51)  # MLOAD(0) first_created_address
    builder.op(0x80)  # DUP1
    builder.push_int(2)
    builder.op(0x55)  # slot2 <- first_created_address
    builder.op(0x80)  # DUP1
    builder.op(0x3B)  # EXTCODESIZE
    builder.push_int(3)
    builder.op(0x55)  # slot3 <- first_created_code_size
    builder.op(0x50)  # POP first_created_address

    builder.push_int(0)  # out_size
    builder.push_int(0)  # out_offset
    builder.push_int(0)  # in_size
    builder.push_int(0)  # in_offset
    builder.push_int(0)  # value
    builder.op(0x84)  # DUP5 proxy_address
    builder.push_int(proxy_call_gas)
    builder.op(0xF1)  # CALL proxy second time; collision should fail inner call
    builder.push_int(4)
    builder.op(0x55)  # slot4 <- collision_call_success
    builder.op(0x3D)  # RETURNDATASIZE
    builder.push_int(5)
    builder.op(0x55)  # slot5 <- collision_returndata_size
    builder.op(0x50)  # POP proxy_address
    builder.op(0x00)  # STOP
    builder.labels["proxy_initcode"] = len(builder.code)
    builder.extend(proxy_initcode)
    return "0x" + builder.finish().hex()


def _build_return_revert_wrapper_runtime(template: SystemMappingTemplate) -> str:
    return_size = _require_inventory_field(template.return_size, field="return_size")
    return_non_zero_data = _require_inventory_field(
        template.return_non_zero_data,
        field="return_non_zero_data",
    )
    builder = _BytecodeBuilder()

    builder.op(0x36)  # CALLDATASIZE
    builder.push_int(0)
    builder.op(0x14)  # EQ
    builder.push_label("wrapper")
    builder.op(0x57)  # JUMPI

    if return_non_zero_data and return_size > 0:
        builder.extend(_build_fill_ff_prefix(return_size))
    builder.push_int(return_size)
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
