from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from adapter.generator import build_case, deploy_contract_step, invoke_contract_step, wait_receipt_step
from adapter.inventory import write_inventory_payload
from adapter.manifest import resolve_execution_specs_ref


BLOCKHASH_HISTORICAL_BLOCKED_REASON = "requires controllable historical block-hash witness not available through the current RPC-only harness"
BLOCKHASH_DYNAMIC_BLOCKED_REASON = "requires gas-derived dynamic block index plus historical block-hash witness not available through the current RPC-only harness"
BLOBBASEFEE_BLOCKED_REASON = "requires blob-base-fee opcode support plus a blob-capable profile witness not yet proven"

BLOCK_CONTEXT_BLOCKHASH_CURRENT_RUNTIME = "0x43405f5500"
BLOCK_CONTEXT_COINBASE_RUNTIME = "0x4160005500"
BLOCK_CONTEXT_TIMESTAMP_RUNTIME = "0x4260005500"
BLOCK_CONTEXT_NUMBER_RUNTIME = "0x4360005500"
BLOCK_CONTEXT_PREVRANDAO_RUNTIME = "0x4460005500"
BLOCK_CONTEXT_GASLIMIT_RUNTIME = "0x4560005500"
BLOCK_CONTEXT_CHAINID_RUNTIME = "0x4660005500"
BLOCK_CONTEXT_BASEFEE_RUNTIME = "0x4860005500"

BlockContextTemplateMode = Literal[
    "basefee",
    "blockhash_current",
    "chainid",
    "coinbase",
    "gaslimit",
    "number",
    "prevrandao",
    "timestamp",
]


@dataclass(frozen=True, slots=True)
class BlockContextMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: BlockContextTemplateMode


@dataclass(frozen=True, slots=True)
class AutoBlockContextInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str


BLOCK_CONTEXT_MODE_SPECS: dict[BlockContextTemplateMode, dict[str, str]] = {
    "basefee": {
        "description": "Mapped from execution-specs BASEFEE onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-block-context-basefee",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark BASEFEE in an external-call frame.",
                "RPC mapping: runtime writes BASEFEE to storage slot0 after deployment, then the harness asserts it against the effective block base fee witness captured at execution time.",
                "Admitted because the block base fee is a truthful runtime environment value that can be proven without genesis rewriting or trace equivalence.",
            ]
        ),
        "runtime_code": BLOCK_CONTEXT_BASEFEE_RUNTIME,
        "expected_word": "$block_basefee_word",
    },
    "blockhash_current": {
        "description": "Mapped from execution-specs BLOCKHASH current-block benchmark onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-block-context-blockhash-current",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark BLOCKHASH with the current block number.",
                "RPC mapping: runtime stores BLOCKHASH(NUMBER) in slot0 after deployment and invocation.",
                "Admitted narrowly because the EVM specifies BLOCKHASH for the current block returns zero, making the proof independent of historical block fixtures while still exercising the opcode path.",
            ]
        ),
        "runtime_code": BLOCK_CONTEXT_BLOCKHASH_CURRENT_RUNTIME,
        "expected_word": "0x0000000000000000000000000000000000000000000000000000000000000000",
    },
    "chainid": {
        "description": "Mapped from execution-specs CHAINID onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-block-context-chainid",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark CHAINID in an external-call frame.",
                "RPC mapping: runtime writes CHAINID to storage slot0 after deployment, then the harness asserts it against the active chain profile chain id resolved at execution time.",
                "Admitted because the selected profile already names the chain id truthfully and the runtime opcode exposes the same value without block control.",
            ]
        ),
        "runtime_code": BLOCK_CONTEXT_CHAINID_RUNTIME,
        "expected_word": "$chain_id_word",
    },
    "coinbase": {
        "description": "Mapped from execution-specs COINBASE onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-block-context-coinbase",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark COINBASE in an external-call frame.",
                "RPC mapping: runtime writes COINBASE to storage slot0 after deployment, then the harness asserts it against the execution block beneficiary witness captured at run time.",
                "Admitted because the block beneficiary is a truthful runtime environment value that can be observed per execution without fixture-level block rewriting.",
            ]
        ),
        "runtime_code": BLOCK_CONTEXT_COINBASE_RUNTIME,
        "expected_word": "$block_coinbase_word",
    },
    "gaslimit": {
        "description": "Mapped from execution-specs GASLIMIT onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-block-context-gaslimit",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark GASLIMIT in an external-call frame.",
                "RPC mapping: runtime writes GASLIMIT to storage slot0 after deployment, then the harness asserts it against the execution block gas-limit witness captured at run time.",
                "Admitted because the block gas limit is a truthful runtime environment value that can be proven without custom block construction.",
            ]
        ),
        "runtime_code": BLOCK_CONTEXT_GASLIMIT_RUNTIME,
        "expected_word": "$block_gaslimit_word",
    },
    "number": {
        "description": "Mapped from execution-specs NUMBER onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-block-context-number",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark NUMBER in an external-call frame.",
                "RPC mapping: runtime writes NUMBER to storage slot0 after deployment, then the harness asserts it against the execution block number witness captured at run time.",
                "Admitted because the block number is a truthful runtime environment value that can be observed from the actual execution result without block control.",
            ]
        ),
        "runtime_code": BLOCK_CONTEXT_NUMBER_RUNTIME,
        "expected_word": "$block_number_word",
    },
    "prevrandao": {
        "description": "Mapped from execution-specs PREVRANDAO onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-block-context-prevrandao",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark PREVRANDAO in an external-call frame.",
                "RPC mapping: runtime writes PREVRANDAO to storage slot0 after deployment, then the harness asserts it against the execution block randomness witness captured at run time.",
                "Admitted because PREVRANDAO is a truthful runtime environment value available from the executed block without needing historical block fixtures.",
            ]
        ),
        "runtime_code": BLOCK_CONTEXT_PREVRANDAO_RUNTIME,
        "expected_word": "$block_prevrandao_word",
    },
    "timestamp": {
        "description": "Mapped from execution-specs TIMESTAMP onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-block-context-timestamp",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark TIMESTAMP in an external-call frame.",
                "RPC mapping: runtime writes TIMESTAMP to storage slot0 after deployment, then the harness asserts it against the execution block timestamp witness captured at run time.",
                "Admitted because the block timestamp is a truthful runtime environment value that can be observed from the actual execution result without special fixtures.",
            ]
        ),
        "runtime_code": BLOCK_CONTEXT_TIMESTAMP_RUNTIME,
        "expected_word": "$block_timestamp_word",
    },
}


ZERO_PARAM_OPCODE_TO_MODE: dict[str, BlockContextTemplateMode] = {
    "BASEFEE": "basefee",
    "CHAINID": "chainid",
    "COINBASE": "coinbase",
    "GASLIMIT": "gaslimit",
    "NUMBER": "number",
    "PREVRANDAO": "prevrandao",
    "TIMESTAMP": "timestamp",
}


def generate_upstream_block_context_templates(
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
        / "test_block_context.py"
    )
    templates, inventory = scan_block_context_cases(source)
    payload = {
        "name": "upstream-block-context-mapping-templates",
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
            family="block-context",
            name="upstream-block-context-auto-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload


def generate_upstream_block_context_manifest(
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
        else repo_root_path / "suites" / "templates" / "upstream_block_context_templates.json"
    )
    templates = load_block_context_templates(template_file)
    execution_specs_ref = resolve_execution_specs_ref(
        repo_root_path / "suites" / "manifests" / "upstream_block_context_mapped.json",
        "submodule-pending",
    )
    manifest = {
        "name": "upstream-block-context-mapped",
        "version": "1",
        "execution_specs_ref": execution_specs_ref,
        "suite_version": suite_version,
        "chain_profile_version": chain_profile_version,
        "cases": [render_block_context_case(template) for template in templates],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def load_block_context_templates(path: str | Path) -> tuple[BlockContextMappingTemplate, ...]:
    template_path = Path(path)
    data = json.loads(template_path.read_text())
    return tuple(
        BlockContextMappingTemplate(
            case_id=entry["case_id"],
            description=entry["description"],
            namespace_seed=entry["namespace_seed"],
            upstream_ref=entry["upstream_ref"],
            notes=list(entry["notes"]),
            mode=entry["mode"],
        )
        for entry in data["cases"]
    )


def scan_block_context_cases(
    source_path: str | Path,
) -> tuple[tuple[BlockContextMappingTemplate, ...], tuple[AutoBlockContextInventoryEntry, ...]]:
    source = Path(source_path)
    text = source.read_text()
    inventory = sorted(
        _scan_zero_param_cases(text) + _scan_blockhash_cases(text),
        key=lambda item: item.upstream_ref,
    )
    if len(inventory) != 13:
        raise ValueError(f"expected 13 block-context benchmark cases, found {len(inventory)}")
    templates = tuple(
        _inventory_entry_to_template(entry)
        for entry in inventory
        if entry.admitted and entry.mode is not None
    )
    return templates, tuple(inventory)


def _scan_zero_param_cases(text: str) -> list[AutoBlockContextInventoryEntry]:
    values = _extract_param_values(
        text,
        r'@pytest\.mark\.parametrize\(\s*"opcode",\s*\[(?P<values>[^\]]+)\]\s*,?\s*\)\s*def test_block_context_ops',
    )
    results: list[AutoBlockContextInventoryEntry] = []
    for opcode in [value.split(".")[-1] for value in values]:
        admitted_mode, reasons = _resolve_zero_param_mode(opcode)
        results.append(
            AutoBlockContextInventoryEntry(
                upstream_ref=f"tests/benchmark/compute/instruction/test_block_context.py::test_block_context_ops[opcode={opcode}]",
                case_id=f"upstream.benchmark.block_context.test_block_context_ops.{opcode.lower()}",
                admitted=admitted_mode is not None,
                mode=admitted_mode,
                reasons=reasons,
                source="test_block_context_ops",
            )
        )
    return results


def _scan_blockhash_cases(text: str) -> list[AutoBlockContextInventoryEntry]:
    block = _extract_param_block(text, function_name="test_blockhash")
    labels = [match.group("label") for match in re.finditer(r'id="(?P<label>[^"]+)"', block)]
    if len(labels) != 5:
        raise ValueError(f"expected 5 blockhash benchmark cases, found {len(labels)}")
    return [
        AutoBlockContextInventoryEntry(
            upstream_ref=f"tests/benchmark/compute/instruction/test_block_context.py::test_blockhash[index={label}]",
            case_id=f"upstream.benchmark.block_context.test_blockhash.{label}",
            admitted=label == "current_block",
            mode="blockhash_current" if label == "current_block" else None,
            reasons=[] if label == "current_block" else [_blockhash_blocked_reason(label)],
            source="test_blockhash",
        )
        for label in labels
    ]


def _blockhash_blocked_reason(label: str) -> str:
    if label == "random":
        return BLOCKHASH_DYNAMIC_BLOCKED_REASON
    return BLOCKHASH_HISTORICAL_BLOCKED_REASON


def _resolve_zero_param_mode(opcode: str) -> tuple[BlockContextTemplateMode | None, list[str]]:
    if opcode == "BLOBBASEFEE":
        return None, [BLOBBASEFEE_BLOCKED_REASON]
    mode = ZERO_PARAM_OPCODE_TO_MODE.get(opcode)
    if mode is None:
        raise ValueError(f"unsupported block-context opcode {opcode}")
    return mode, []


def _inventory_entry_to_template(entry: AutoBlockContextInventoryEntry) -> BlockContextMappingTemplate:
    assert entry.mode is not None
    spec = BLOCK_CONTEXT_MODE_SPECS[entry.mode]
    return BlockContextMappingTemplate(
        case_id=entry.case_id,
        description=spec["description"],
        namespace_seed=spec["namespace_seed"],
        upstream_ref=entry.upstream_ref,
        notes=json.loads(spec["notes"]),
        mode=entry.mode,
    )


def render_block_context_case(template: BlockContextMappingTemplate) -> dict[str, Any]:
    spec = BLOCK_CONTEXT_MODE_SPECS[template.mode]
    case = build_case(  # type: ignore[arg-type]
        template,
        steps=[
            deploy_contract_step(
                init_code=_build_init_code(spec["runtime_code"]),
                runtime_code=spec["runtime_code"],
            ),
            wait_receipt_step(),
            invoke_contract_step(data_hex="0x"),
            wait_receipt_step(),
        ],
        expected={"storage": {"0x00": spec["expected_word"]}},
    )
    case["family"] = "state/block-context"
    case["observe"] = {
        "storage_address": "$last_contract",
        "block_context_probe": {"mode": template.mode},
    }
    return case


def _build_init_code(runtime_code: str) -> str:
    runtime_hex = runtime_code.removeprefix("0x")
    runtime_bytes = bytes.fromhex(runtime_hex)
    length = len(runtime_bytes)
    if length == 0:
        raise ValueError("runtime_code must not be empty")
    if length > 0xFF:
        raise ValueError("runtime_code too long for PUSH1 init helper")
    return f"0x60{length:02x}600c60003960{length:02x}6000f3{runtime_hex}"


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


def _extract_param_values(text: str, pattern: str) -> list[str]:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise ValueError(f"could not match pattern: {pattern}")
    return [value.strip() for value in match.group("values").split(",") if value.strip()]
