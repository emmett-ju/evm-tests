from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from adapter.generator import build_case, deploy_contract_step, invoke_contract_step, wait_receipt_step
from adapter.manifest import resolve_execution_specs_ref


MEM_MLOAD_INIT = "0x6012600c60003960126000f360602a600052600051600055595560015500"
MEM_MLOAD_RUNTIME = "0x602a600052600051600055595560015500"
MEM_MSTORE_INIT = "0x6012600c60003960126000f3602a600052600051600055595560015500"
MEM_MSTORE_RUNTIME = "0x602a600052600051600055595560015500"
MEM_MSTORE8_INIT = "0x6014600c60003960146000f3602a601f53602051600055595960015500"
MEM_MSTORE8_RUNTIME = "0x602a601f53602051600055595960015500"
MEM_MSIZE_ZERO_INIT = "0x6008600c60003960086000f35960005500"
MEM_MSIZE_ZERO_RUNTIME = "0x5960005500"
MEM_MSIZE_TOUCHED_INIT = "0x600f600c600039600f6000f35f515960005500"
MEM_MSIZE_TOUCHED_RUNTIME = "0x5f515960005500"

WORD_00 = "0x0000000000000000000000000000000000000000000000000000000000000000"
WORD_20 = "0x0000000000000000000000000000000000000000000000000000000000000020"
WORD_2A = "0x000000000000000000000000000000000000000000000000000000000000002a"
WORD_2A_BYTE_AT_31 = "0x2a00000000000000000000000000000000000000000000000000000000000000"

MemoryTemplateMode = Literal[
    "mload_offset0_initialized_mem0",
    "mstore_offset0_uninitialized_mem0",
    "mstore8_offset31_initialized_mem32",
    "msize_mem0",
    "msize_mem1",
]


@dataclass(frozen=True, slots=True)
class MemoryMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: MemoryTemplateMode


@dataclass(frozen=True, slots=True)
class AutoMemoryInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str


MEMORY_MODE_SPECS: dict[MemoryTemplateMode, dict[str, str]] = {
    "mload_offset0_initialized_mem0": {
        "description": "Mapped from execution-specs MLOAD at offset 0 with initialized memory onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-memory-mload-offset0-initialized-mem0",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark MLOAD after writing a known word at offset 0.",
                "RPC mapping: runtime writes 0x2a into memory, reads it back with MLOAD, then persists the loaded word and MSIZE into storage.",
                "Admitted because final storage captures the semantic result directly; gas benchmarking is intentionally excluded.",
            ]
        ),
    },
    "mstore_offset0_uninitialized_mem0": {
        "description": "Mapped from execution-specs MSTORE at offset 0 on fresh memory onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-memory-mstore-offset0-uninitialized-mem0",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark MSTORE on untouched memory.",
                "RPC mapping: runtime writes a known word at offset 0, then persists that word and MSIZE into storage.",
                "Admitted because final storage captures the semantic write result directly.",
            ]
        ),
    },
    "mstore8_offset31_initialized_mem32": {
        "description": "Mapped from execution-specs MSTORE8 at offset 31 with initialized memory onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-memory-mstore8-offset31-initialized-mem32",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark MSTORE8 at a word boundary edge after memory expansion.",
                "RPC mapping: runtime writes byte 0x2a at offset 31, then loads the containing word and stores it together with MSIZE into storage.",
                "Admitted because the byte placement is visible in final storage.",
            ]
        ),
    },
    "msize_mem0": {
        "description": "Mapped from execution-specs MSIZE with fresh memory onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-memory-msize-mem0",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark MSIZE without prior memory expansion.",
                "RPC mapping: runtime records MSIZE directly into storage slot0.",
                "Admitted because the semantic result is directly observable on-chain.",
            ]
        ),
    },
    "msize_mem1": {
        "description": "Mapped from execution-specs MSIZE after a minimal memory touch onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-memory-msize-mem1",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark MSIZE after memory has been expanded slightly.",
                "RPC mapping: runtime touches memory with MLOAD and persists the resulting MSIZE into storage slot0.",
                "Admitted because the semantic result is directly observable on-chain.",
            ]
        ),
    },
}


def generate_upstream_memory_templates(
    *,
    repo_root: str | Path,
    source_path: str | Path | None = None,
    output_path: str | Path,
    inventory_path: str | Path | None = None,
) -> dict[str, Any]:
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
    output = Path(output_path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2) + "\n")
    if inventory_path is not None:
        inventory_payload = {
            "name": "upstream-memory-auto-inventory",
            "version": "1",
            "source": payload["source"],
            "entries": [asdict(entry) for entry in inventory],
        }
        inventory_file = Path(inventory_path).resolve()
        inventory_file.parent.mkdir(parents=True, exist_ok=True)
        inventory_file.write_text(json.dumps(inventory_payload, indent=2) + "\n")
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
        )
        for entry in data["cases"]
    )


def scan_memory_cases(
    source_path: str | Path,
) -> tuple[tuple[MemoryMappingTemplate, ...], tuple[AutoMemoryInventoryEntry, ...]]:
    source = Path(source_path)
    text = source.read_text()
    inventory = sorted(_scan_msize_cases(text) + _scan_memory_access_cases(text), key=lambda item: item.upstream_ref)
    templates = tuple(
        _memory_inventory_entry_to_template(entry)
        for entry in inventory
        if entry.admitted and entry.mode is not None
    )
    return templates, tuple(inventory)


def _scan_msize_cases(text: str) -> list[AutoMemoryInventoryEntry]:
    values = _extract_param_values(text, r'@pytest\.mark\.parametrize\("mem_size", \[(?P<values>[^\]]+)\]\)\ndef test_msize')
    results: list[AutoMemoryInventoryEntry] = []
    for raw in values:
        mem_size = _parse_int_literal(raw)
        upstream_ref = f"tests/benchmark/compute/instruction/test_memory.py::test_msize[mem_size={mem_size}]"
        case_id = f"upstream.benchmark.memory.msize.mem_size_{mem_size}.success"
        admitted_mode, reasons = _resolve_msize_mode(mem_size)
        results.append(
            AutoMemoryInventoryEntry(
                upstream_ref=upstream_ref,
                case_id=case_id,
                admitted=admitted_mode is not None,
                mode=admitted_mode,
                reasons=reasons,
                source="msize",
            )
        )
    return results


def _scan_memory_access_cases(text: str) -> list[AutoMemoryInventoryEntry]:
    opcodes = [value.split(".")[-1] for value in _extract_param_values(text, r'@pytest\.mark\.parametrize\("opcode", \[(?P<values>[^\]]+)\]\)')]
    offsets = [_parse_int_literal(value) for value in _extract_param_values(text, r'@pytest\.mark\.parametrize\("offset", \[(?P<values>[^\]]+)\]\)')]
    initialized = [value == "True" for value in _extract_param_values(text, r'@pytest\.mark\.parametrize\("offset_initialized", \[(?P<values>[^\]]+)\]\)')]
    mem_sizes = [_parse_int_literal(value) for value in _extract_param_values(text, r'@pytest\.mark\.parametrize\("mem_size", \[(?P<values>[^\]]+)\]\)\ndef test_memory_access')]
    results: list[AutoMemoryInventoryEntry] = []
    for opcode in opcodes:
        for offset in offsets:
            for offset_initialized in initialized:
                for mem_size in mem_sizes:
                    upstream_ref = (
                        "tests/benchmark/compute/instruction/test_memory.py::"
                        f"test_memory_access[mem_size={mem_size}-offset_initialized={offset_initialized}-offset={offset}-opcode={opcode}]"
                    )
                    case_id = (
                        f"upstream.benchmark.memory.{opcode.lower()}.offset_{offset}."
                        f"{'initialized' if offset_initialized else 'uninitialized'}.mem_size_{mem_size}.success"
                    )
                    admitted_mode, reasons = _resolve_memory_access_mode(opcode, offset, offset_initialized, mem_size)
                    results.append(
                        AutoMemoryInventoryEntry(
                            upstream_ref=upstream_ref,
                            case_id=case_id,
                            admitted=admitted_mode is not None,
                            mode=admitted_mode,
                            reasons=reasons,
                            source="memory_access",
                        )
                    )
    return results


def _extract_param_values(text: str, pattern: str) -> list[str]:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise ValueError(f"could not match pattern: {pattern}")
    return [value.strip() for value in match.group("values").split(",")]


def _parse_int_literal(value: str) -> int:
    normalized = value.replace("_", "").strip()
    if "*" in normalized:
        left, right = [part.strip() for part in normalized.split("*", 1)]
        return int(left) * int(right)
    return int(normalized)


def _resolve_msize_mode(mem_size: int) -> tuple[MemoryTemplateMode | None, list[str]]:
    if mem_size == 0:
        return "msize_mem0", []
    if mem_size == 1:
        return "msize_mem1", []
    return None, ["requires broad memory-expansion benchmark coverage not yet mapped"]


def _resolve_memory_access_mode(
    opcode: str,
    offset: int,
    offset_initialized: bool,
    mem_size: int,
) -> tuple[MemoryTemplateMode | None, list[str]]:
    if opcode == "MLOAD" and offset == 0 and offset_initialized and mem_size == 0:
        return "mload_offset0_initialized_mem0", []
    if opcode == "MSTORE" and offset == 0 and not offset_initialized and mem_size == 0:
        return "mstore_offset0_uninitialized_mem0", []
    if opcode == "MSTORE8" and offset == 31 and offset_initialized and mem_size == 32:
        return "mstore8_offset31_initialized_mem32", []
    return None, ["requires arbitrary memory layout or gas-sensitive benchmark shape not yet mapped"]


def _memory_inventory_entry_to_template(entry: AutoMemoryInventoryEntry) -> MemoryMappingTemplate:
    assert entry.mode is not None
    spec = MEMORY_MODE_SPECS[entry.mode]
    return MemoryMappingTemplate(
        case_id=entry.case_id,
        description=spec["description"],
        namespace_seed=spec["namespace_seed"],
        upstream_ref=entry.upstream_ref,
        notes=json.loads(spec["notes"]),
        mode=entry.mode,
    )


def render_memory_case(template: MemoryMappingTemplate) -> dict[str, Any]:
    if template.mode == "mload_offset0_initialized_mem0":
        return _build_memory_case(
            template,
            init_code=MEM_MLOAD_INIT,
            runtime_code=MEM_MLOAD_RUNTIME,
            expected={"storage": {"0x00": WORD_2A, "0x01": WORD_20}},
        )
    if template.mode == "mstore_offset0_uninitialized_mem0":
        return _build_memory_case(
            template,
            init_code=MEM_MSTORE_INIT,
            runtime_code=MEM_MSTORE_RUNTIME,
            expected={"storage": {"0x00": WORD_2A, "0x01": WORD_20}},
        )
    if template.mode == "mstore8_offset31_initialized_mem32":
        return _build_memory_case(
            template,
            init_code=MEM_MSTORE8_INIT,
            runtime_code=MEM_MSTORE8_RUNTIME,
            expected={"storage": {"0x00": WORD_2A_BYTE_AT_31, "0x01": WORD_20}},
        )
    if template.mode == "msize_mem0":
        return _build_memory_case(
            template,
            init_code=MEM_MSIZE_ZERO_INIT,
            runtime_code=MEM_MSIZE_ZERO_RUNTIME,
            expected={"storage": {"0x00": WORD_00}},
        )
    if template.mode == "msize_mem1":
        return _build_memory_case(
            template,
            init_code=MEM_MSIZE_TOUCHED_INIT,
            runtime_code=MEM_MSIZE_TOUCHED_RUNTIME,
            expected={"storage": {"0x00": WORD_20}},
        )
    raise ValueError(f"unsupported memory mapping mode: {template.mode}")


def _build_memory_case(
    template: MemoryMappingTemplate,
    *,
    init_code: str,
    runtime_code: str,
    expected: dict[str, Any],
) -> dict[str, Any]:
    case = build_case(
        template,  # type: ignore[arg-type]
        steps=[
            deploy_contract_step(init_code=init_code, runtime_code=runtime_code),
            wait_receipt_step(),
            invoke_contract_step(data_hex="0x"),
            wait_receipt_step(),
        ],
        expected=expected,
    )
    case["family"] = "state/memory"
    return case
