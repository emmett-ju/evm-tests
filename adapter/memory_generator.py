from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from adapter.generator import build_case, deploy_contract_step, invoke_contract_step, wait_receipt_step
from adapter.inventory import write_inventory_payload
from adapter.manifest import resolve_execution_specs_ref
from adapter.assembler import _build_init_code, _push_int, _word_hex

MemoryTemplateMode = Literal[
    "mcopy",
    "memory_access",
    "msize",
]

WORD_2A = 42
WORD_2B = 43
BLOCKED_MCOPY_REASON = "requires gas-derived dynamic MCOPY source/destination expansion observation not yet mapped"


@dataclass(frozen=True, slots=True)
class MemoryMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: MemoryTemplateMode
    opcode: str
    offset: int | None
    offset_initialized: bool | None
    mem_size: int
    copy_size: int | None = None
    fixed_src_dst: bool | None = None


@dataclass(frozen=True, slots=True)
class AutoMemoryInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str
    opcode: str | None = None
    offset: int | None = None
    offset_initialized: bool | None = None
    mem_size: int | None = None
    copy_size: int | None = None
    fixed_src_dst: bool | None = None


def generate_upstream_memory_templates(
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
        else repo_root_path / "third_party" / "execution-specs" / "tests" / "benchmark" / "compute" / "instruction" / "test_memory.py"
    )
    templates, inventory = scan_memory_cases(source)
    payload = {
        "name": "upstream-memory-mapping-templates",
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
            family="memory",
            name="upstream-memory-auto-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload


def generate_upstream_memory_manifest(
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
        else repo_root_path / "suites" / "templates" / "upstream_memory_templates.json"
    )
    templates = load_memory_templates(template_file)
    execution_specs_ref = resolve_execution_specs_ref(
        repo_root_path / "suites" / "manifests" / "upstream_memory_mapped.json",
        "submodule-pending",
    )
    manifest = {
        "name": "upstream-memory-mapped",
        "version": "1",
        "execution_specs_ref": execution_specs_ref,
        "suite_version": suite_version,
        "chain_profile_version": chain_profile_version,
        "cases": [render_memory_case(template) for template in templates],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def load_memory_templates(path: str | Path) -> tuple[MemoryMappingTemplate, ...]:
    template_path = Path(path)
    data = json.loads(template_path.read_text())
    return tuple(
        MemoryMappingTemplate(
            case_id=entry["case_id"],
            description=entry["description"],
            namespace_seed=entry["namespace_seed"],
            upstream_ref=entry["upstream_ref"],
            notes=list(entry["notes"]),
            mode=entry["mode"],
            opcode=entry["opcode"],
            offset=entry["offset"],
            offset_initialized=entry["offset_initialized"],
            mem_size=entry["mem_size"],
            copy_size=entry.get("copy_size"),
            fixed_src_dst=entry.get("fixed_src_dst"),
        )
        for entry in data["cases"]
    )


def scan_memory_cases(
    source_path: str | Path,
) -> tuple[tuple[MemoryMappingTemplate, ...], tuple[AutoMemoryInventoryEntry, ...]]:
    text = Path(source_path).read_text()
    inventory = sorted(
        _scan_msize_cases(text) + _scan_memory_access_cases(text) + _scan_mcopy_cases(text),
        key=lambda item: item.upstream_ref,
    )
    templates = tuple(
        _memory_inventory_entry_to_template(entry)
        for entry in inventory
        if entry.admitted
    )
    return templates, tuple(inventory)


def _scan_msize_cases(text: str) -> list[AutoMemoryInventoryEntry]:
    values = _extract_param_values(
        text,
        r'@pytest\.mark\.parametrize\("mem_size", \[(?P<values>[^\]]+)\]\)\ndef test_msize',
    )
    results: list[AutoMemoryInventoryEntry] = []
    for raw in values:
        mem_size = _parse_int_literal(raw)
        results.append(
            AutoMemoryInventoryEntry(
                upstream_ref=f"tests/benchmark/compute/instruction/test_memory.py::test_msize[mem_size={mem_size}]",
                case_id=f"upstream.benchmark.memory.msize.mem_size_{mem_size}.success",
                admitted=True,
                mode="msize",
                reasons=[],
                source="msize",
                opcode="MSIZE",
                mem_size=mem_size,
            )
        )
    return results


def _scan_memory_access_cases(text: str) -> list[AutoMemoryInventoryEntry]:
    opcodes = [
        value.split(".")[-1]
        for value in _extract_param_values(text, r'@pytest\.mark\.parametrize\("opcode", \[(?P<values>[^\]]+)\]\)')
    ]
    offsets = [
        _parse_int_literal(value)
        for value in _extract_param_values(text, r'@pytest\.mark\.parametrize\("offset", \[(?P<values>[^\]]+)\]\)')
    ]
    initialized = [
        value == "True"
        for value in _extract_param_values(text, r'@pytest\.mark\.parametrize\("offset_initialized", \[(?P<values>[^\]]+)\]\)')
    ]
    mem_sizes = [
        _parse_int_literal(value)
        for value in _extract_param_values(
            text,
            r'@pytest\.mark\.parametrize\("mem_size", \[(?P<values>[^\]]+)\]\)\ndef test_memory_access',
        )
    ]
    results: list[AutoMemoryInventoryEntry] = []
    for opcode in opcodes:
        for offset in offsets:
            for offset_initialized in initialized:
                for mem_size in mem_sizes:
                    results.append(
                        AutoMemoryInventoryEntry(
                            upstream_ref=(
                                "tests/benchmark/compute/instruction/test_memory.py::"
                                f"test_memory_access[mem_size={mem_size}-offset_initialized={offset_initialized}-offset={offset}-opcode={opcode}]"
                            ),
                            case_id=(
                                f"upstream.benchmark.memory.{opcode.lower()}.offset_{offset}."
                                f"{'initialized' if offset_initialized else 'uninitialized'}.mem_size_{mem_size}.success"
                            ),
                            admitted=True,
                            mode="memory_access",
                            reasons=[],
                            source="memory_access",
                            opcode=opcode,
                            offset=offset,
                            offset_initialized=offset_initialized,
                            mem_size=mem_size,
                        )
                    )
    return results


def _scan_mcopy_cases(text: str) -> list[AutoMemoryInventoryEntry]:
    block = _extract_decorator_region(text, function_name="test_mcopy")
    mem_sizes = [
        _parse_int_literal(value)
        for value in _extract_param_values_from_block(block, "mem_size", function_name="test_mcopy")
    ]
    copy_sizes = [
        _parse_int_literal(value)
        for value in _extract_param_values_from_block(block, "copy_size", function_name="test_mcopy")
    ]
    fixed_src_dst_values = [
        _parse_bool_literal(value)
        for value in _extract_param_values_from_block(block, "fixed_src_dst", function_name="test_mcopy")
    ]
    results: list[AutoMemoryInventoryEntry] = []
    for mem_size in mem_sizes:
        for copy_size in copy_sizes:
            for fixed_src_dst in fixed_src_dst_values:
                admitted = fixed_src_dst or copy_size == 0
                results.append(
                    AutoMemoryInventoryEntry(
                        upstream_ref=(
                            "tests/benchmark/compute/instruction/test_memory.py::"
                            f"test_mcopy[mem_size={mem_size}-copy_size={copy_size}-fixed_src_dst={fixed_src_dst}]"
                        ),
                        case_id=(
                            "upstream.benchmark.memory.mcopy."
                            f"mem_size_{mem_size}.copy_size_{copy_size}.{'fixed' if fixed_src_dst else 'dynamic'}.success"
                        ),
                        admitted=admitted,
                        mode="mcopy" if admitted else None,
                        reasons=[] if admitted else [BLOCKED_MCOPY_REASON],
                        source="mcopy",
                        opcode="MCOPY",
                        mem_size=mem_size,
                        copy_size=copy_size,
                        fixed_src_dst=fixed_src_dst,
                    )
                )
    if len(results) != 48:
        raise ValueError(f"expected 48 mcopy benchmark cases, found {len(results)}")
    return results


def _memory_inventory_entry_to_template(entry: AutoMemoryInventoryEntry) -> MemoryMappingTemplate:
    assert entry.mode is not None and entry.opcode is not None and entry.mem_size is not None
    if entry.mode == "msize":
        description = (
            "Mapped from execution-specs MSIZE after expanding memory via MLOAD at offset "
            f"{entry.mem_size} onto an RPC-only deploy/call/storage-assert flow."
        )
        namespace_seed = f"upstream-memory-msize-mem{entry.mem_size}"
        notes = [
            f"Upstream intent: benchmark MSIZE after setup expands memory using MLOAD at offset {entry.mem_size}.",
            "RPC mapping: runtime performs the same memory-touch shape, then persists MSIZE into storage slot0.",
            "Admitted because the resulting memory-size word is directly observable in final storage.",
        ]
    elif entry.mode == "mcopy":
        assert entry.copy_size is not None and entry.fixed_src_dst is not None
        target_kind = "fixed source/destination 0" if entry.fixed_src_dst else "dynamic source/destination with zero copy size"
        description = (
            f"Mapped from execution-specs MCOPY with mem_size {entry.mem_size}, copy_size {entry.copy_size}, "
            f"and {target_kind} onto an RPC-only deploy/call/storage-assert flow."
        )
        namespace_seed = (
            f"upstream-memory-mcopy-mem{entry.mem_size}-copy{entry.copy_size}-"
            f"{'fixed' if entry.fixed_src_dst else 'dynamic-zero'}"
        )
        notes = [
            f"Upstream intent: benchmark MCOPY with mem_size={entry.mem_size}, copy_size={entry.copy_size}, fixed_src_dst={entry.fixed_src_dst}.",
            "RPC mapping: runtime executes the same admitted MCOPY shape, stores MSIZE immediately after MCOPY in slot0, then stores MSIZE after cleanup memory touches in slot1.",
            "Admitted because the MCOPY memory expansion and cleanup boundary are directly observable in final storage; dynamic source/destination is admitted only when copy_size=0 makes the gas-derived offsets irrelevant to final MSIZE.",
        ]
    else:
        assert entry.offset is not None and entry.offset_initialized is not None
        init_label = "initialized" if entry.offset_initialized else "uninitialized"
        description = (
            f"Mapped from execution-specs {entry.opcode} at offset {entry.offset} with {init_label} memory and mem_size {entry.mem_size} "
            "onto an RPC-only deploy/call/storage-assert flow."
        )
        namespace_seed = (
            f"upstream-memory-{entry.opcode.lower()}-offset{entry.offset}-{init_label}-mem{entry.mem_size}"
        )
        notes = [
            f"Upstream intent: benchmark {entry.opcode} at offset {entry.offset} with offset_initialized={entry.offset_initialized} and mem_size={entry.mem_size}.",
            "RPC mapping: runtime reproduces the benchmark setup shape, persists the observed result in slot0, and persists MSIZE in slot1.",
            "Admitted because both the operation result and the resulting memory size are directly observable in final storage.",
        ]
    return MemoryMappingTemplate(
        case_id=entry.case_id,
        description=description,
        namespace_seed=namespace_seed,
        upstream_ref=entry.upstream_ref,
        notes=notes,
        mode=entry.mode,
        opcode=entry.opcode,
        offset=entry.offset,
        offset_initialized=entry.offset_initialized,
        mem_size=entry.mem_size,
        copy_size=entry.copy_size,
        fixed_src_dst=entry.fixed_src_dst,
    )


def render_memory_case(template: MemoryMappingTemplate) -> dict[str, Any]:
    if template.mode == "msize":
        expected = {"storage": {"0x00": _word_hex(_simulate_msize_case(template.mem_size))}}
        runtime_code = _build_msize_runtime(template.mem_size)
        invoke_gas = _memory_gas_hex(template.mem_size)
        observe = {
            "storage_address": "$last_contract",
            "memory_probe": {
                "mode": "msize",
                "mem_size": template.mem_size,
            },
        }
    elif template.mode == "mcopy":
        assert template.copy_size is not None and template.fixed_src_dst is not None
        slot0, slot1 = _simulate_mcopy_case(
            template.mem_size,
            template.copy_size,
            template.fixed_src_dst,
        )
        expected = {"storage": {"0x00": _word_hex(slot0), "0x01": _word_hex(slot1)}}
        runtime_code = _build_mcopy_runtime(
            template.mem_size,
            template.copy_size,
            template.fixed_src_dst,
        )
        invoke_gas = _memory_gas_hex(max(template.mem_size, template.copy_size))
        observe = {
            "storage_address": "$last_contract",
            "memory_probe": {
                "mode": "mcopy",
                "mem_size": template.mem_size,
                "copy_size": template.copy_size,
                "fixed_src_dst": template.fixed_src_dst,
            },
        }
    else:
        assert template.offset is not None and template.offset_initialized is not None
        slot0, slot1 = _simulate_memory_access_case(
            template.opcode,
            template.offset,
            template.offset_initialized,
            template.mem_size,
        )
        expected = {"storage": {"0x00": _word_hex(slot0), "0x01": _word_hex(slot1)}}
        runtime_code = _build_memory_access_runtime(
            template.opcode,
            template.offset,
            template.offset_initialized,
            template.mem_size,
        )
        invoke_gas = _memory_gas_hex(max(template.mem_size, template.offset + 32))
        observe = {
            "storage_address": "$last_contract",
            "memory_probe": {
                "mode": "memory_access",
                "opcode": template.opcode,
                "offset": template.offset,
                "offset_initialized": template.offset_initialized,
                "mem_size": template.mem_size,
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
            invoke_contract_step(data_hex="0x", gas=invoke_gas),
            wait_receipt_step(),
        ],
        expected=expected,
    )
    case["family"] = "state/memory"
    case["observe"] = observe
    return case


def _build_memory_access_runtime(opcode: str, offset: int, offset_initialized: bool, mem_size: int) -> str:
    code = bytearray()
    if mem_size > 0:
        code += _push_int(1)
        code += _push_int(mem_size - 1)
        code.append(0x53)  # MSTORE8
    if offset_initialized:
        code += _push_int(WORD_2B)
        code += _push_int(offset)
        code.append(0x52)  # MSTORE
    if opcode == "MLOAD":
        code += _push_int(offset)
        code.append(0x51)  # MLOAD
        code += _push_int(0)
        code.append(0x55)  # SSTORE
    elif opcode == "MSTORE":
        code += _push_int(WORD_2A)
        code += _push_int(offset)
        code.append(0x52)  # MSTORE
        code += _push_int(offset)
        code.append(0x51)  # MLOAD
        code += _push_int(0)
        code.append(0x55)  # SSTORE
    elif opcode == "MSTORE8":
        code += _push_int(WORD_2A)
        code += _push_int(offset)
        code.append(0x53)  # MSTORE8
        code += _push_int((offset // 32) * 32)
        code.append(0x51)  # MLOAD
        code += _push_int(0)
        code.append(0x55)  # SSTORE
    else:
        raise ValueError(f"unsupported memory opcode: {opcode}")
    code.append(0x59)  # MSIZE
    code += _push_int(1)
    code.append(0x55)  # SSTORE
    code.append(0x00)  # STOP
    return "0x" + code.hex()


def _build_msize_runtime(mem_size: int) -> str:
    code = bytearray()
    code += _push_int(mem_size)
    code.append(0x51)  # MLOAD
    code.append(0x50)  # POP
    code.append(0x59)  # MSIZE
    code += _push_int(0)
    code.append(0x55)  # SSTORE
    code.append(0x00)  # STOP
    return "0x" + code.hex()


def _build_mcopy_runtime(mem_size: int, copy_size: int, fixed_src_dst: bool) -> str:
    code = bytearray()
    code += _push_int(copy_size)
    if fixed_src_dst:
        code += _push_int(0)
        code += _push_int(0)
    else:
        code.append(0x5A)  # GAS
        code += _push_int(7)
        code.append(0x06)  # MOD
        code.append(0x5A)  # GAS
        code += _push_int(7)
        code.append(0x06)  # MOD
    code.append(0x5E)  # MCOPY
    code.append(0x59)  # MSIZE
    code += _push_int(0)
    code.append(0x55)  # SSTORE
    if mem_size > 0:
        for offset in (0, mem_size // 2, mem_size - 1):
            code.append(0x5A)  # GAS
            code += _push_int(offset)
            code.append(0x53)  # MSTORE8
    code.append(0x59)  # MSIZE
    code += _push_int(1)
    code.append(0x55)  # SSTORE
    code.append(0x00)  # STOP
    return "0x" + code.hex()


def _simulate_memory_access_case(
    opcode: str,
    offset: int,
    offset_initialized: bool,
    mem_size: int,
) -> tuple[int, int]:
    memory = _MemoryState()
    if mem_size > 0:
        memory.mstore8(mem_size - 1, 1)
    if offset_initialized:
        memory.mstore(offset, WORD_2B)
    if opcode == "MLOAD":
        slot0 = memory.mload(offset)
    elif opcode == "MSTORE":
        memory.mstore(offset, WORD_2A)
        slot0 = memory.mload(offset)
    elif opcode == "MSTORE8":
        memory.mstore8(offset, WORD_2A)
        slot0 = memory.mload((offset // 32) * 32)
    else:
        raise ValueError(f"unsupported memory opcode: {opcode}")
    return slot0, memory.msize()


def _simulate_msize_case(mem_size: int) -> int:
    memory = _MemoryState()
    memory.mload(mem_size)
    return memory.msize()


def _simulate_mcopy_case(mem_size: int, copy_size: int, fixed_src_dst: bool) -> tuple[int, int]:
    memory = _MemoryState()
    src_dst = 0 if fixed_src_dst else 6
    memory.mcopy(src_dst, src_dst, copy_size)
    slot0 = memory.msize()
    if mem_size > 0:
        memory.mstore8(0, 0)
        memory.mstore8(mem_size // 2, 0)
        memory.mstore8(mem_size - 1, 0)
    return slot0, memory.msize()


class _MemoryState:
    def __init__(self) -> None:
        self._memory = bytearray()

    def _ensure(self, size: int) -> None:
        if size <= len(self._memory):
            return
        target = ((size + 31) // 32) * 32
        self._memory.extend(b"\x00" * (target - len(self._memory)))

    def mstore8(self, offset: int, value: int) -> None:
        self._ensure(offset + 1)
        self._memory[offset] = value & 0xFF

    def mstore(self, offset: int, value: int) -> None:
        self._ensure(offset + 32)
        self._memory[offset : offset + 32] = value.to_bytes(32, "big")

    def mload(self, offset: int) -> int:
        self._ensure(offset + 32)
        return int.from_bytes(self._memory[offset : offset + 32], "big")

    def mcopy(self, destination_offset: int, source_offset: int, size: int) -> None:
        if size == 0:
            return
        self._ensure(source_offset + size)
        self._ensure(destination_offset + size)
        segment = bytes(self._memory[source_offset : source_offset + size])
        self._memory[destination_offset : destination_offset + size] = segment

    def msize(self) -> int:
        return len(self._memory)


def _memory_gas_hex(size_hint: int) -> str:
    if size_hint >= 1_000_000:
        return "0x1e8480"  # 2,000,000
    if size_hint >= 100_000:
        return "0x0f4240"  # 1,000,000
    if size_hint >= 10_240:
        return "0x061a80"  # 400,000
    if size_hint >= 1_024:
        return "0x030d40"  # 200,000
    return "0xc350"  # 50,000


def _extract_param_values(text: str, pattern: str) -> list[str]:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise ValueError(f"could not match pattern: {pattern}")
    return [value.strip() for value in match.group("values").split(",") if value.strip()]


def _extract_decorator_region(text: str, *, function_name: str) -> str:
    func_marker = f"def {function_name}("
    func = text.find(func_marker)
    if func == -1:
        raise ValueError(f"could not find benchmark function {function_name}")
    start = text.rfind("\n\n", 0, func)
    if start == -1:
        start = 0
    else:
        start += 2
    return text[start:func]


def _extract_param_block(block: str, param_name: str) -> str | None:
    pattern = re.compile(
        rf'@pytest\.mark\.parametrize\(\s*"{re.escape(param_name)}",\s*\[(?P<values>.*?)\]\s*,?\s*\)',
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(block)
    if not match:
        return None
    return match.group("values")


def _extract_param_values_from_block(block: str, param_name: str, *, function_name: str) -> list[str]:
    values_block = _extract_param_block(block, param_name)
    if values_block is None:
        raise ValueError(f"could not find parameter block for {function_name}")
    return [value.strip() for value in values_block.split(",") if value.strip()]


def _parse_bool_literal(value: str) -> bool:
    if value == "True":
        return True
    if value == "False":
        return False
    raise ValueError(f"unsupported boolean literal: {value}")


def _parse_int_literal(value: str) -> int:
    normalized = value.replace("_", "").strip()
    if "*" in normalized:
        left, right = [part.strip() for part in normalized.split("*", 1)]
        return int(left) * int(right)
    return int(normalized)
