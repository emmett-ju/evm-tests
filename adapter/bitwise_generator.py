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


BLOCKED_REASON = "requires gas-sensitive benchmark shape not yet mapped"


@dataclass(frozen=True, slots=True)
class BitwiseMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: str
    opcode: str
    args: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class AutoBitwiseInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str
    opcode: str | None = None
    args: tuple[int, ...] | None = None


def generate_upstream_bitwise_templates(
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
        else repo_root_path / "third_party" / "execution-specs" / "tests" / "benchmark" / "compute" / "instruction" / "test_bitwise.py"
    )
    templates, inventory = scan_bitwise_cases(source)
    payload = {
        "name": "upstream-bitwise-mapping-templates",
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
            family="bitwise",
            name="upstream-bitwise-auto-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload


def generate_upstream_bitwise_manifest(
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
        else repo_root_path / "suites" / "templates" / "upstream_bitwise_templates.json"
    )
    data = json.loads(template_file.read_text())
    templates = [
        BitwiseMappingTemplate(
            case_id=entry["case_id"],
            description=entry["description"],
            namespace_seed=entry["namespace_seed"],
            upstream_ref=entry["upstream_ref"],
            notes=list(entry["notes"]),
            mode=entry["mode"],
            opcode=entry["opcode"],
            args=tuple(entry["args"]),
        )
        for entry in data["cases"]
    ]
    execution_specs_ref = resolve_execution_specs_ref(
        repo_root_path / "suites" / "manifests" / "upstream_bitwise_mapped.json",
        "submodule-pending",
    )
    manifest = {
        "name": "upstream-bitwise-mapped",
        "version": "1",
        "execution_specs_ref": execution_specs_ref,
        "suite_version": suite_version,
        "chain_profile_version": chain_profile_version,
        "cases": [render_bitwise_case(template) for template in templates],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def scan_bitwise_cases(
    source_path: str | Path,
) -> tuple[tuple[BitwiseMappingTemplate, ...], tuple[AutoBitwiseInventoryEntry, ...]]:
    source = Path(source_path)
    text = source.read_text()
    inventory = sorted(
        _scan_test_bitwise_cases(text)
        + _scan_test_shifts_cases(text)
        + _scan_standalone_cases(text),
        key=lambda item: item.upstream_ref,
    )
    templates = tuple(_bitwise_inventory_entry_to_template(entry) for entry in inventory if entry.admitted)
    return templates, tuple(inventory)


def _scan_test_bitwise_cases(text: str) -> list[AutoBitwiseInventoryEntry]:
    block = _extract_param_block(text, function_name="test_bitwise")
    opcodes = [
        match.group("opcode")
        for match in re.finditer(r"^\s*Op\.(?P<opcode>[A-Z0-9_]+),", block, re.MULTILINE)
    ]
    if len(opcodes) != 7:
        raise ValueError(f"expected 7 bitwise benchmark cases, found {len(opcodes)}")
    
    exact_args = [
        ('AND', (115792089237316195423570985008687907853269984665640564039457584007908834671663, 52435875175126190479447740508185965837690552500527637822603658699938581184513)), 
        ('OR', (115792089237316195423570985008687907853269984665640564039457584007908834671663, 52435875175126190479447740508185965837690552500527637822603658699938581184513)), 
        ('XOR', (115792089237316195423570985008687907853269984665640564039457584007908834671663, 52435875175126190479447740508185965837690552500527637822603658699938581184513)), 
        ('BYTE', (31, 115792089237316195423570985008687907853269984665640564039457584007908834671663)), 
        ('SHL', (1, 115792089237316195423570985008687907853269984665640564039457584007908834671663)), 
        ('SHR', (1, 115792089237316195423570985008687907853269984665640564039457584007908834671663)), 
        ('SAR', (1, 115792089237316195423570985008687907853269984665640564039457584007908834671663))
    ]

    entries: list[AutoBitwiseInventoryEntry] = []
    for opcode, args in zip(opcodes, [v[1] for v in exact_args]):
        upstream_ref = (
            "tests/benchmark/compute/instruction/test_bitwise.py::"
            f"test_bitwise[opcode={opcode}]"
        )
        case_id = f"upstream.benchmark.bitwise.test_bitwise.{opcode.lower()}"
        entries.append(
            AutoBitwiseInventoryEntry(
                upstream_ref=upstream_ref,
                case_id=case_id,
                admitted=True,
                mode="test_bitwise",
                reasons=[],
                source="test_bitwise",
                opcode=opcode,
                args=args,
            )
        )
    return entries


def _scan_test_shifts_cases(text: str) -> list[AutoBitwiseInventoryEntry]:
    block = _extract_param_block(text, function_name="test_shifts")
    opcodes = [
        match.group("opcode")
        for match in re.finditer(r"Op\.(?P<opcode>[A-Z0-9_]+)", block)
    ]
    if len(opcodes) != 2:
        raise ValueError(f"expected 2 shift benchmark cases, found {len(opcodes)}")
    entries: list[AutoBitwiseInventoryEntry] = []
    for opcode in opcodes:
        upstream_ref = (
            "tests/benchmark/compute/instruction/test_bitwise.py::"
            f"test_shifts[opcode={opcode}]"
        )
        case_id = f"upstream.benchmark.bitwise.test_shifts.{opcode.lower()}"
        entries.append(
            AutoBitwiseInventoryEntry(
                upstream_ref=upstream_ref,
                case_id=case_id,
                admitted=False,
                mode=None,
                reasons=[BLOCKED_REASON],
                source="test_shifts",
            )
        )
    return entries


def _scan_standalone_cases(text: str) -> list[AutoBitwiseInventoryEntry]:
    entries: list[AutoBitwiseInventoryEntry] = []
    if "def test_not_op(" in text:
        entries.append(
            AutoBitwiseInventoryEntry(
                upstream_ref="tests/benchmark/compute/instruction/test_bitwise.py::test_not_op",
                case_id="upstream.benchmark.bitwise.test_not_op.not",
                admitted=True,
                mode="test_not_op",
                reasons=[],
                source="test_not_op",
                opcode="NOT",
                args=(0,),
            )
        )
    if "def test_clz_same(" in text:
        entries.append(
            AutoBitwiseInventoryEntry(
                upstream_ref="tests/benchmark/compute/instruction/test_bitwise.py::test_clz_same",
                case_id="upstream.benchmark.bitwise.test_clz_same.clz",
                admitted=True,
                mode="test_clz_same",
                reasons=[],
                source="test_clz_same",
                opcode="CLZ",
                args=(248,),
            )
        )
    if "def test_clz_diff(" in text:
        entries.append(
            AutoBitwiseInventoryEntry(
                upstream_ref="tests/benchmark/compute/instruction/test_bitwise.py::test_clz_diff",
                case_id="upstream.benchmark.bitwise.test_clz_diff.clz",
                admitted=False,
                mode=None,
                reasons=[BLOCKED_REASON],
                source="test_clz_diff",
            )
        )
    if len(entries) != 3:
        raise ValueError(f"expected 3 standalone bitwise benchmark cases, found {len(entries)}")
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


def _bitwise_inventory_entry_to_template(entry: AutoBitwiseInventoryEntry) -> BitwiseMappingTemplate:
    return BitwiseMappingTemplate(
        case_id=entry.case_id,
        description=f"Mapped from execution-specs {entry.opcode} onto an RPC-only deploy/call/storage-assert flow.",
        namespace_seed=f"upstream-bitwise-{entry.opcode.lower()}",
        upstream_ref=entry.upstream_ref,
        notes=[
            f"Upstream intent: benchmark {entry.opcode} with specific parameters.",
            "RPC mapping: runtime pushes parameters, executes the opcode, and writes the result to storage slot0.",
            "Admitted because the mathematical result is perfectly deterministic and observable in final storage.",
        ],
        mode=entry.mode or "",
        opcode=entry.opcode or "",
        args=entry.args or (),
    )


def _simulate_bitwise(opcode: str, args: tuple[int, ...]) -> int:
    if opcode == 'AND':
        return args[0] & args[1]
    elif opcode == 'OR':
        return args[0] | args[1]
    elif opcode == 'XOR':
        return args[0] ^ args[1]
    elif opcode == 'NOT':
        return ~args[0] & ((1<<256)-1)
    elif opcode == 'BYTE':
        idx, val = args[0], args[1]
        if idx >= 32:
            return 0
        return (val >> ((31 - idx) * 8)) & 0xFF
    elif opcode == 'SHL':
        shift, val = args[0], args[1]
        if shift >= 256:
            return 0
        return (val << shift) & ((1<<256)-1)
    elif opcode == 'SHR':
        shift, val = args[0], args[1]
        if shift >= 256:
            return 0
        return val >> shift
    elif opcode == 'SAR':
        shift, val = args[0], args[1]
        is_neg = (val & (1 << 255)) != 0
        if shift >= 256:
            return ((1<<256)-1) if is_neg else 0
        if is_neg:
            val_signed = val - (1<<256)
            res = val_signed >> shift
            return res + (1<<256)
        else:
            return val >> shift
    elif opcode == 'CLZ':
        val = args[0]
        if val == 0:
            return 256
        return 256 - val.bit_length()
    raise ValueError(f"unsupported bitwise opcode: {opcode}")


OPCODES: dict[str, int] = {
    'AND': 0x16,
    'OR': 0x17,
    'XOR': 0x18,
    'NOT': 0x19,
    'BYTE': 0x1A,
    'SHL': 0x1B,
    'SHR': 0x1C,
    'SAR': 0x1D,
    'CLZ': 0x1E,
}


def _build_bitwise_runtime(opcode: str, args: tuple[int, ...]) -> str:
    code = bytearray()
    for arg in reversed(args):
        code += _push_int(arg)
    code.append(OPCODES[opcode])
    code += _push_int(0)
    code.append(0x55)  # SSTORE
    code.append(0x00)  # STOP
    return "0x" + code.hex()


def render_bitwise_case(template: BitwiseMappingTemplate) -> dict[str, Any]:
    expected_val = _simulate_bitwise(template.opcode, template.args)
    expected = {"storage": {"0x00": _word_hex(expected_val)}}
    runtime_code = _build_bitwise_runtime(template.opcode, template.args)
    
    observe = {
        "storage_address": "$last_contract",
        "bitwise_probe": {
            "opcode": template.opcode,
            "args": template.args,
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
    case["family"] = "state/bitwise"
    case["observe"] = observe
    return case
