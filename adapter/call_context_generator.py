from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from adapter.generator import build_case, deploy_contract_step, invoke_contract_step, wait_receipt_step
from adapter.inventory import write_inventory_payload
from adapter.manifest import resolve_execution_specs_ref


CALL_CONTEXT_ADDRESS_INIT = "0x0f600c6000390f6000f33060005500"
CALL_CONTEXT_ADDRESS_RUNTIME = "0x3060005500"
CALL_CONTEXT_CALLER_INIT = "0x0f600c6000390f6000f33360005500"
CALL_CONTEXT_CALLER_RUNTIME = "0x3360005500"
CALL_CONTEXT_CALLVALUE_INIT = "0x0f600c6000390f6000f33460005500"
CALL_CONTEXT_CALLVALUE_RUNTIME = "0x3460005500"
CALL_CONTEXT_CALLDATASIZE_INIT = "0x0f600c6000390f6000f33660005500"
CALL_CONTEXT_CALLDATASIZE_RUNTIME = "0x3660005500"
CALL_CONTEXT_CALLDATALOAD_INIT = "0x11600c600039116000f35f3560005500"
CALL_CONTEXT_CALLDATALOAD_RUNTIME = "0x5f3560005500"

ADDRESS_WORD = "0x000000000000000000000000cccccccccccccccccccccccccccccccccccccccc"
CALLER_WORD = "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
VALUE_WORD_00 = "0x0000000000000000000000000000000000000000000000000000000000000000"
VALUE_WORD_01 = "0x0000000000000000000000000000000000000000000000000000000000000001"
CALLDATA_WORD_ZERO = "0x0000000000000000000000000000000000000000000000000000000000000000"
CALLDATA_WORD_PATTERN = "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
CALLDATASIZE_00 = "0x0000000000000000000000000000000000000000000000000000000000000000"
CALLDATASIZE_20 = "0x0000000000000000000000000000000000000000000000000000000000000020"
CALLDATASIZE_100 = "0x0000000000000000000000000000000000000000000000000000000000000100"
CALLDATASIZE_400 = "0x0000000000000000000000000000000000000000000000000000000000000400"

CallContextTemplateMode = Literal[
    "address",
    "caller",
    "callvalue_zero",
    "callvalue_one",
    "calldatasize_0_zero",
    "calldatasize_32_zero",
    "calldatasize_32_nonzero",
    "calldataload_0_zero",
    "calldataload_32_nonzero",
]


@dataclass(frozen=True, slots=True)
class CallContextMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: CallContextTemplateMode


@dataclass(frozen=True, slots=True)
class AutoCallContextInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str


CALL_CONTEXT_MODE_SPECS: dict[CallContextTemplateMode, dict[str, str]] = {
    "address": {
        "description": "Mapped from execution-specs ADDRESS onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-call-context-address",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark ADDRESS in an external-call frame.",
                "RPC mapping: runtime writes ADDRESS to storage slot0 after deployment, then the harness asserts it against the deployed contract address resolved at runtime.",
                "Admitted because the final contract address is observable from the deployment receipt and can be resolved via placeholders without genesis control.",
            ]
        ),
    },
    "caller": {
        "description": "Mapped from execution-specs CALLER onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-call-context-caller",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark CALLER in an external-call frame.",
                "RPC mapping: runtime writes CALLER to storage slot0 after deployment, then the harness asserts it against the admin sender address resolved at runtime.",
                "Admitted because the sender address is known from the active chain profile and can be resolved via placeholders.",
            ]
        ),
    },
    "callvalue_zero": {
        "description": "Mapped from execution-specs CALLVALUE with zero value onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-call-context-callvalue-zero",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark CALLVALUE for a zero-value origin transaction.",
                "RPC mapping: runtime writes CALLVALUE to storage slot0; the invoke step sends value 0x0.",
                "Admitted because the final value word is directly observable in storage.",
            ]
        ),
    },
    "callvalue_one": {
        "description": "Mapped from execution-specs CALLVALUE with non-zero value onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-call-context-callvalue-one",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark CALLVALUE for a non-zero origin transaction.",
                "RPC mapping: runtime writes CALLVALUE to storage slot0; the invoke step sends value 0x1.",
                "Admitted because the final value word is directly observable in storage.",
            ]
        ),
    },
    "calldatasize_0_zero": {
        "description": "Mapped from execution-specs CALLDATASIZE with zero calldata onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-call-context-calldatasize-0",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark CALLDATASIZE with empty calldata.",
                "RPC mapping: runtime writes CALLDATASIZE to storage slot0 using an empty call payload.",
                "Admitted because the resulting size word is directly observable in storage.",
            ]
        ),
    },
    "calldatasize_32_zero": {
        "description": "Mapped from execution-specs CALLDATASIZE with 32 zero bytes onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-call-context-calldatasize-32-zero",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark CALLDATASIZE with 32 bytes of zero calldata.",
                "RPC mapping: runtime writes CALLDATASIZE to storage slot0 using a 32-byte zero payload.",
                "Admitted because the resulting size word is directly observable in storage.",
            ]
        ),
    },
    "calldatasize_32_nonzero": {
        "description": "Mapped from execution-specs CALLDATASIZE with 32 non-zero bytes onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-call-context-calldatasize-32-nonzero",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark CALLDATASIZE with 32 bytes of non-zero calldata.",
                "RPC mapping: runtime writes CALLDATASIZE to storage slot0 using a 32-byte deterministic payload.",
                "Admitted because the resulting size word is directly observable in storage.",
            ]
        ),
    },
    "calldataload_0_zero": {
        "description": "Mapped from execution-specs CALLDATALOAD with empty calldata onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-call-context-calldataload-0-zero",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark CALLDATALOAD at offset 0 with empty calldata.",
                "RPC mapping: runtime CALLDATALOADs offset 0 and stores the resulting word into storage slot0.",
                "Admitted because the resulting zero word is directly observable in storage.",
            ]
        ),
    },
    "calldataload_32_nonzero": {
        "description": "Mapped from execution-specs CALLDATALOAD with 32 bytes of non-zero calldata onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-call-context-calldataload-32-nonzero",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark CALLDATALOAD at offset 0 with 32 bytes of deterministic calldata.",
                "RPC mapping: runtime CALLDATALOADs offset 0 and stores the resulting word into storage slot0.",
                "Admitted because the loaded word is directly observable in storage.",
            ]
        ),
    },
}


def generate_upstream_call_context_templates(
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
        else repo_root_path / "third_party" / "execution-specs" / "tests" / "benchmark" / "compute" / "instruction" / "test_call_context.py"
    )
    templates, inventory = scan_call_context_cases(source)
    payload = {
        "name": "upstream-call-context-mapping-templates",
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
            family="call-context",
            name="upstream-call-context-auto-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload


def generate_upstream_call_context_manifest(
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
        else repo_root_path / "suites" / "templates" / "upstream_call_context_templates.json"
    )
    templates = load_call_context_templates(template_file)
    execution_specs_ref = resolve_execution_specs_ref(
        repo_root_path / "suites" / "manifests" / "upstream_call_context_mapped.json",
        "submodule-pending",
    )
    manifest = {
        "name": "upstream-call-context-mapped",
        "version": "1",
        "execution_specs_ref": execution_specs_ref,
        "suite_version": suite_version,
        "chain_profile_version": chain_profile_version,
        "cases": [render_call_context_case(template) for template in templates],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def load_call_context_templates(path: str | Path) -> tuple[CallContextMappingTemplate, ...]:
    template_path = Path(path)
    data = json.loads(template_path.read_text())
    return tuple(
        CallContextMappingTemplate(
            case_id=entry["case_id"],
            description=entry["description"],
            namespace_seed=entry["namespace_seed"],
            upstream_ref=entry["upstream_ref"],
            notes=list(entry["notes"]),
            mode=entry["mode"],
        )
        for entry in data["cases"]
    )


def scan_call_context_cases(
    source_path: str | Path,
) -> tuple[tuple[CallContextMappingTemplate, ...], tuple[AutoCallContextInventoryEntry, ...]]:
    source = Path(source_path)
    text = source.read_text()
    inventory = sorted(
        _scan_zero_param_cases(text)
        + _scan_calldatasize_cases(text)
        + _scan_callvalue_origin_cases(text)
        + _scan_calldataload_cases(text),
        key=lambda item: item.upstream_ref,
    )
    templates = tuple(
        _inventory_entry_to_template(entry)
        for entry in inventory
        if entry.admitted and entry.mode is not None
    )
    return templates, tuple(inventory)


def _scan_zero_param_cases(text: str) -> list[AutoCallContextInventoryEntry]:
    values = _extract_param_values(text, r'@pytest\.mark\.parametrize\(\s*"opcode",\s*\[(?P<values>[^\]]+)\]\s*,?\s*\)\s*def test_call_frame_context_ops')
    results: list[AutoCallContextInventoryEntry] = []
    for raw in values:
        opcode = raw.split(".")[-1]
        upstream_ref = f"tests/benchmark/compute/instruction/test_call_context.py::test_call_frame_context_ops[opcode={opcode}]"
        case_id = f"upstream.benchmark.call_context.{opcode.lower()}.success"
        admitted_mode, reasons = _resolve_zero_param_mode(opcode)
        results.append(
            AutoCallContextInventoryEntry(
                upstream_ref=upstream_ref,
                case_id=case_id,
                admitted=admitted_mode is not None,
                mode=admitted_mode,
                reasons=reasons,
                source="zero_param",
            )
        )
    return results


def _scan_calldatasize_cases(text: str) -> list[AutoCallContextInventoryEntry]:
    sizes = [_parse_int_literal(value) for value in _extract_param_values(text, r'@pytest\.mark\.parametrize\("calldata_size", \[(?P<values>[^\]]+)\]\)')]
    zero_data_values = [value == "True" for value in _extract_param_values(text, r'@pytest\.mark\.parametrize\("zero_data", \[(?P<values>[^\]]+)\]\)\ndef test_calldatasize')]
    results: list[AutoCallContextInventoryEntry] = []
    for calldata_size in sizes:
        for zero_data in zero_data_values:
            upstream_ref = (
                "tests/benchmark/compute/instruction/test_call_context.py::"
                f"test_calldatasize[zero_data={zero_data}-calldata_size={calldata_size}]"
            )
            case_id = (
                "upstream.benchmark.call_context.calldatasize."
                f"calldata_size_{calldata_size}."
                f"{'zero' if zero_data else 'nonzero'}.success"
            )
            admitted_mode, reasons = _resolve_calldatasize_mode(calldata_size, zero_data)
            results.append(
                AutoCallContextInventoryEntry(
                    upstream_ref=upstream_ref,
                    case_id=case_id,
                    admitted=admitted_mode is not None,
                    mode=admitted_mode,
                    reasons=reasons,
                    source="calldatasize",
                )
            )
    return results


def _scan_callvalue_origin_cases(text: str) -> list[AutoCallContextInventoryEntry]:
    values = [value == "True" for value in _extract_param_values(text, r'@pytest\.mark\.parametrize\("non_zero_value", \[(?P<values>[^\]]+)\]\)\ndef test_callvalue_from_origin')]
    results: list[AutoCallContextInventoryEntry] = []
    for non_zero_value in values:
        upstream_ref = (
            "tests/benchmark/compute/instruction/test_call_context.py::"
            f"test_callvalue_from_origin[non_zero_value={non_zero_value}]"
        )
        case_id = f"upstream.benchmark.call_context.callvalue.origin.{'nonzero' if non_zero_value else 'zero'}.success"
        admitted_mode = "callvalue_one" if non_zero_value else "callvalue_zero"
        results.append(
            AutoCallContextInventoryEntry(
                upstream_ref=upstream_ref,
                case_id=case_id,
                admitted=True,
                mode=admitted_mode,
                reasons=[],
                source="callvalue_origin",
            )
        )
    return results


def _scan_calldataload_cases(text: str) -> list[AutoCallContextInventoryEntry]:
    sizes = [_parse_int_literal(value) for value in _extract_param_values(text, r'@pytest\.mark\.parametrize\("calldata_size", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("zero_data", \[(?P<values2>[^\]]+)\]\)\ndef test_calldataload')]
    zero_data_values = [value == "True" for value in _extract_param_values(text, r'@pytest\.mark\.parametrize\("zero_data", \[(?P<values>[^\]]+)\]\)\ndef test_calldataload')]
    results: list[AutoCallContextInventoryEntry] = []
    for calldata_size in sizes:
        for zero_data in zero_data_values:
            upstream_ref = (
                "tests/benchmark/compute/instruction/test_call_context.py::"
                f"test_calldataload[zero_data={zero_data}-calldata_size={calldata_size}]"
            )
            case_id = (
                "upstream.benchmark.call_context.calldataload."
                f"calldata_size_{calldata_size}."
                f"{'zero' if zero_data else 'nonzero'}.success"
            )
            admitted_mode, reasons = _resolve_calldataload_mode(calldata_size, zero_data)
            results.append(
                AutoCallContextInventoryEntry(
                    upstream_ref=upstream_ref,
                    case_id=case_id,
                    admitted=admitted_mode is not None,
                    mode=admitted_mode,
                    reasons=reasons,
                    source="calldataload",
                )
            )
    return results


def _extract_param_values(text: str, pattern: str) -> list[str]:
    match = re.search(pattern, text, re.MULTILINE | re.DOTALL)
    if not match:
        raise ValueError(f"could not match pattern: {pattern}")
    values = match.groupdict().get("values")
    if values is None:
        raise ValueError(f"pattern missing named group 'values': {pattern}")
    return [value.strip() for value in values.split(",")]


def _parse_int_literal(value: str) -> int:
    normalized = value.replace("_", "").strip()
    if "*" in normalized:
        left, right = [part.strip() for part in normalized.split("*", 1)]
        return int(left) * int(right)
    return int(normalized)


def _resolve_zero_param_mode(opcode: str) -> tuple[CallContextTemplateMode | None, list[str]]:
    if opcode == "ADDRESS":
        return "address", []
    if opcode == "CALLER":
        return "caller", []
    return None, ["unsupported zero-parameter call-context opcode"]


def _resolve_calldatasize_mode(
    calldata_size: int,
    zero_data: bool,
) -> tuple[CallContextTemplateMode | None, list[str]]:
    if calldata_size == 0 and zero_data:
        return "calldatasize_0_zero", []
    if calldata_size == 32 and zero_data:
        return "calldatasize_32_zero", []
    if calldata_size == 32 and not zero_data:
        return "calldatasize_32_nonzero", []
    return None, ["requires broader calldata-size matrix not yet mapped"]


def _resolve_calldataload_mode(
    calldata_size: int,
    zero_data: bool,
) -> tuple[CallContextTemplateMode | None, list[str]]:
    if calldata_size == 0 and zero_data:
        return "calldataload_0_zero", []
    if calldata_size == 32 and not zero_data:
        return "calldataload_32_nonzero", []
    return None, ["requires broader calldataload matrix not yet mapped"]


def _inventory_entry_to_template(entry: AutoCallContextInventoryEntry) -> CallContextMappingTemplate:
    assert entry.mode is not None
    spec = CALL_CONTEXT_MODE_SPECS[entry.mode]
    return CallContextMappingTemplate(
        case_id=entry.case_id,
        description=spec["description"],
        namespace_seed=spec["namespace_seed"],
        upstream_ref=entry.upstream_ref,
        notes=json.loads(spec["notes"]),
        mode=entry.mode,
    )


def render_call_context_case(template: CallContextMappingTemplate) -> dict[str, Any]:
    if template.mode == "address":
        return _build_call_context_case(
            template,
            init_code=CALL_CONTEXT_ADDRESS_INIT,
            runtime_code=CALL_CONTEXT_ADDRESS_RUNTIME,
            expected={"storage": {"0x00": "$last_contract_word"}},
        )
    if template.mode == "caller":
        return _build_call_context_case(
            template,
            init_code=CALL_CONTEXT_CALLER_INIT,
            runtime_code=CALL_CONTEXT_CALLER_RUNTIME,
            expected={"storage": {"0x00": "$admin_account_word"}},
        )
    if template.mode == "callvalue_zero":
        return _build_call_context_case(
            template,
            init_code=CALL_CONTEXT_CALLVALUE_INIT,
            runtime_code=CALL_CONTEXT_CALLVALUE_RUNTIME,
            expected={"storage": {"0x00": VALUE_WORD_00}},
            invoke_value="0x0",
        )
    if template.mode == "callvalue_one":
        return _build_call_context_case(
            template,
            init_code=CALL_CONTEXT_CALLVALUE_INIT,
            runtime_code=CALL_CONTEXT_CALLVALUE_RUNTIME,
            expected={"storage": {"0x00": VALUE_WORD_01}},
            invoke_value="0x1",
        )
    if template.mode == "calldatasize_0_zero":
        return _build_call_context_case(
            template,
            init_code=CALL_CONTEXT_CALLDATASIZE_INIT,
            runtime_code=CALL_CONTEXT_CALLDATASIZE_RUNTIME,
            expected={"storage": {"0x00": CALLDATASIZE_00}},
            data_hex="0x",
        )
    if template.mode == "calldatasize_32_zero":
        return _build_call_context_case(
            template,
            init_code=CALL_CONTEXT_CALLDATASIZE_INIT,
            runtime_code=CALL_CONTEXT_CALLDATASIZE_RUNTIME,
            expected={"storage": {"0x00": CALLDATASIZE_20}},
            data_hex="0x" + "00" * 32,
        )
    if template.mode == "calldatasize_32_nonzero":
        return _build_call_context_case(
            template,
            init_code=CALL_CONTEXT_CALLDATASIZE_INIT,
            runtime_code=CALL_CONTEXT_CALLDATASIZE_RUNTIME,
            expected={"storage": {"0x00": CALLDATASIZE_20}},
            data_hex=CALLDATA_WORD_PATTERN,
        )
    if template.mode == "calldataload_0_zero":
        return _build_call_context_case(
            template,
            init_code=CALL_CONTEXT_CALLDATALOAD_INIT,
            runtime_code=CALL_CONTEXT_CALLDATALOAD_RUNTIME,
            expected={"storage": {"0x00": CALLDATA_WORD_ZERO}},
            data_hex="0x",
        )
    if template.mode == "calldataload_32_nonzero":
        return _build_call_context_case(
            template,
            init_code=CALL_CONTEXT_CALLDATALOAD_INIT,
            runtime_code=CALL_CONTEXT_CALLDATALOAD_RUNTIME,
            expected={"storage": {"0x00": CALLDATA_WORD_PATTERN}},
            data_hex=CALLDATA_WORD_PATTERN,
        )
    raise ValueError(f"unsupported call-context mapping mode: {template.mode}")


def _build_call_context_case(
    template: CallContextMappingTemplate,
    *,
    init_code: str,
    runtime_code: str,
    expected: dict[str, Any],
    data_hex: str = "0x",
    invoke_value: str = "0x0",
) -> dict[str, Any]:
    case = build_case(
        template,  # type: ignore[arg-type]
        steps=[
            deploy_contract_step(init_code=init_code, runtime_code=runtime_code),
            wait_receipt_step(),
            {
                **invoke_contract_step(data_hex=data_hex),
                "value": invoke_value,
            },
            wait_receipt_step(),
        ],
        expected=expected,
    )
    case["family"] = "state/call-context"
    return case
