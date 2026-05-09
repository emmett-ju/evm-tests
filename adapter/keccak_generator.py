from __future__ import annotations

import json
import math
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from adapter.assembler import _build_init_code, _push_int, _word_hex
from adapter.generator import build_case, deploy_contract_step, invoke_contract_step, wait_receipt_step
from adapter.inventory import write_inventory_payload
from adapter.manifest import resolve_execution_specs_ref
from adapter.signer import keccak256


KECCAK_RATE = 136
KECCAK_BENCHMARK_GAS_LIMIT = 120_000_000
KECCAK_INTRINSIC_GAS = 21_000
KECCAK_PER_WORD_GAS = 6
KECCAK_BASE_GAS = 30
POP_GAS = 2

KeccakTemplateMode = Literal[
    "max_permutations",
    "keccak",
    "diff_mem_msg_sizes",
]

WORD_EMPTY_KECCAK = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


@dataclass(frozen=True, slots=True)
class KeccakMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: KeccakTemplateMode
    mem_alloc_hex: str | None = None
    mem_alloc_label: str | None = None
    offset: int | None = None
    mem_update: bool | None = None
    mem_size: int | None = None
    msg_size: int | None = None
    witness_input_length: int | None = None


@dataclass(frozen=True, slots=True)
class AutoKeccakInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str
    mem_alloc_hex: str | None = None
    mem_alloc_label: str | None = None
    offset: int | None = None
    mem_update: bool | None = None
    mem_size: int | None = None
    msg_size: int | None = None
    witness_input_length: int | None = None


KECCAK_MODE_SPECS: dict[KeccakTemplateMode, dict[str, str]] = {
    "max_permutations": {
        "description": "Admitted execution-specs KECCAK256 max-permutations benchmark mapped as a deterministic input-shape witness.",
        "namespace_seed": "upstream-keccak-max-permutations",
        "notes": json.dumps(
            [
                "Upstream intent: maximize KECCAK256 permutations per block by choosing an input length that best trades off per-call cost against permutations per call.",
                "RPC mapping: compute a single KECCAK256 over zeroed memory at the traced optimal input length, then persist the digest, chosen input length, and resulting memory size into storage.",
                "Admitted as a storage-observable witness of the selected input shape only; it does not claim upstream throughput or gas-accounting parity.",
            ]
        ),
    },
    "keccak": {
        "description": "Admitted execution-specs KECCAK256 calldata/offset benchmark mapped as a storage-observable memory-layout witness.",
        "namespace_seed": "upstream-keccak-basic",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark KECCAK256 with different calldata allocations, offsets, and post-hash memory updates.",
                "RPC mapping: reproduce the benchmark setup, persist the resulting digest, persist a post-attack memory witness word, and persist the pre-instrumentation MSIZE for drift localization.",
                "Admitted because final storage truthfully captures the digest and memory-layout consequences without pretending to measure upstream throughput.",
            ]
        ),
    },
    "diff_mem_msg_sizes": {
        "description": "Admitted execution-specs KECCAK256 memory/message-size benchmark mapped as a storage-observable witness.",
        "namespace_seed": "upstream-keccak-diff-mem-msg-sizes",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark KECCAK256 with different pre-expanded memory sizes and different hashed message sizes.",
                "RPC mapping: reproduce the benchmark setup, persist the resulting digest, persist the hashed message length as an explicit witness, and persist the pre-instrumentation MSIZE.",
                "Admitted because final storage truthfully captures the digest and size witnesses without reproducing upstream gas-benchmark internals.",
            ]
        ),
    },
}


def generate_upstream_keccak_templates(
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
        / "test_keccak.py"
    )
    templates, inventory = scan_keccak_cases(source)
    payload = {
        "name": "upstream-keccak-mapping-templates",
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
            family="keccak",
            name="upstream-keccak-auto-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload


def generate_upstream_keccak_manifest(
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
        else repo_root_path / "suites" / "templates" / "upstream_keccak_templates.json"
    )
    templates = load_keccak_templates(template_file)
    execution_specs_ref = resolve_execution_specs_ref(
        repo_root_path / "suites" / "manifests" / "upstream_keccak_mapped.json",
        "submodule-pending",
    )
    manifest = {
        "name": "upstream-keccak-mapped",
        "version": "1",
        "execution_specs_ref": execution_specs_ref,
        "suite_version": suite_version,
        "chain_profile_version": chain_profile_version,
        "cases": [render_keccak_case(template) for template in templates],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def load_keccak_templates(path: str | Path) -> tuple[KeccakMappingTemplate, ...]:
    template_path = Path(path)
    data = json.loads(template_path.read_text())
    entries = data.get("cases")
    if not isinstance(entries, list):
        raise ValueError("keccak template payload must contain a list 'cases'")
    return tuple(_load_keccak_template_entry(entry, index=index) for index, entry in enumerate(entries))


def scan_keccak_cases(
    source_path: str | Path,
) -> tuple[tuple[KeccakMappingTemplate, ...], tuple[AutoKeccakInventoryEntry, ...]]:
    source = Path(source_path)
    text = source.read_text()
    inventory = sorted(
        _scan_max_permutations_case(text)
        + _scan_test_keccak_cases(text)
        + _scan_diff_mem_msg_sizes_cases(text),
        key=lambda item: item.upstream_ref,
    )
    if len(inventory) != 35:
        raise ValueError(f"expected 35 keccak benchmark cases, found {len(inventory)}")
    templates = tuple(
        _inventory_entry_to_template(entry)
        for entry in inventory
        if entry.admitted and entry.mode is not None
    )
    return templates, tuple(inventory)


def render_keccak_case(template: KeccakMappingTemplate) -> dict[str, Any]:
    runtime_code = _build_keccak_runtime(template)
    observe = {
        "storage_address": "$last_contract",
        "keccak_probe": _keccak_probe_metadata(template),
    }

    if template.mode == "max_permutations":
        witness_length = _require_int(template.witness_input_length, field="witness_input_length")
        expected = _expected_max_permutations_storage(witness_length)
        return _build_keccak_case(
            template,
            observe=observe,
            steps=[
                deploy_contract_step(
                    init_code=_build_init_code(runtime_code),
                    runtime_code=runtime_code,
                    gas="0x1e8480",
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex="0x", gas="0x1e8480"),
                wait_receipt_step(),
            ],
            expected=expected,
        )

    if template.mode == "keccak":
        mem_alloc_hex = _require_str(template.mem_alloc_hex, field="mem_alloc_hex")
        offset = _require_int(template.offset, field="offset")
        mem_update = _require_bool(template.mem_update, field="mem_update")
        expected = _expected_keccak_storage(mem_alloc_hex=mem_alloc_hex, offset=offset, mem_update=mem_update)
        invoke_data = "0x" + mem_alloc_hex
        return _build_keccak_case(
            template,
            observe=observe,
            steps=[
                deploy_contract_step(
                    init_code=_build_init_code(runtime_code),
                    runtime_code=runtime_code,
                    gas="0x186a0",
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex=invoke_data, gas=_memory_gas_hex(max(offset + len(bytes.fromhex(mem_alloc_hex or "")), 32))),
                wait_receipt_step(),
            ],
            expected=expected,
        )

    if template.mode == "diff_mem_msg_sizes":
        mem_size = _require_int(template.mem_size, field="mem_size")
        msg_size = _require_int(template.msg_size, field="msg_size")
        expected = _expected_diff_mem_msg_sizes_storage(mem_size=mem_size, msg_size=msg_size)
        return _build_keccak_case(
            template,
            observe=observe,
            steps=[
                deploy_contract_step(
                    init_code=_build_init_code(runtime_code),
                    runtime_code=runtime_code,
                    gas="0x186a0",
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex="0x", gas=_memory_gas_hex(max(mem_size, msg_size, 32))),
                wait_receipt_step(),
            ],
            expected=expected,
        )

    raise ValueError(f"unsupported keccak mapping mode: {template.mode}")


def compute_keccak_max_permutations_input_length() -> int:
    available_gas = KECCAK_BENCHMARK_GAS_LIMIT - KECCAK_INTRINSIC_GAS
    max_keccak_perm_per_block = 0
    optimal_input_length = 0
    for i in range(1, 1_000_000, 32):
        words = math.ceil(i / 32)
        iteration_gas_cost = POP_GAS + KECCAK_BASE_GAS + KECCAK_PER_WORD_GAS * words
        available_gas_after_expansion = max(0, available_gas - _memory_expansion_cost(i))
        num_keccak_calls = available_gas_after_expansion // iteration_gas_cost
        num_keccak_permutations = num_keccak_calls * math.ceil(i / KECCAK_RATE)
        if num_keccak_permutations > max_keccak_perm_per_block:
            max_keccak_perm_per_block = num_keccak_permutations
            optimal_input_length = i
    return optimal_input_length


def _scan_max_permutations_case(text: str) -> list[AutoKeccakInventoryEntry]:
    _require_function(text, "test_keccak_max_permutations")
    return [
        AutoKeccakInventoryEntry(
            upstream_ref="tests/benchmark/compute/instruction/test_keccak.py::test_keccak_max_permutations",
            case_id="upstream.benchmark.keccak.test_keccak_max_permutations",
            admitted=True,
            mode="max_permutations",
            reasons=[],
            source="test_keccak_max_permutations",
            witness_input_length=compute_keccak_max_permutations_input_length(),
        )
    ]


def _scan_test_keccak_cases(text: str) -> list[AutoKeccakInventoryEntry]:
    mem_alloc_entries = _extract_pytest_param_entries(text, function_name="test_keccak", param_name="mem_alloc")
    offsets = [
        _parse_int_literal(value)
        for value in _extract_param_values(
            text,
            r'@pytest\.mark\.parametrize\("offset", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("mem_update", \[(?P<values2>[^\]]+)\]\)\ndef test_keccak',
            group="values",
        )
    ]
    mem_updates = [
        _parse_bool_literal(value)
        for value in _extract_param_values(
            text,
            r'@pytest\.mark\.parametrize\("offset", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("mem_update", \[(?P<values2>[^\]]+)\]\)\ndef test_keccak',
            group="values2",
        )
    ]
    results: list[AutoKeccakInventoryEntry] = []
    for mem_alloc_value, mem_alloc_label in mem_alloc_entries:
        mem_alloc_slug = _slugify_label(mem_alloc_label)
        mem_alloc_hex = _parse_bytes_literal(mem_alloc_value).hex()
        for offset in offsets:
            for mem_update in mem_updates:
                mem_update_slug = "true" if mem_update else "false"
                upstream_ref = (
                    "tests/benchmark/compute/instruction/test_keccak.py::"
                    f"test_keccak[mem_alloc={mem_alloc_label}-offset={offset}-mem_update={mem_update}]"
                )
                case_id = (
                    "upstream.benchmark.keccak.test_keccak."
                    f"mem_alloc_{mem_alloc_slug}.offset_{offset}.mem_update_{mem_update_slug}"
                )
                results.append(
                    AutoKeccakInventoryEntry(
                        upstream_ref=upstream_ref,
                        case_id=case_id,
                        admitted=True,
                        mode="keccak",
                        reasons=[],
                        source="test_keccak",
                        mem_alloc_hex=mem_alloc_hex,
                        mem_alloc_label=mem_alloc_label,
                        offset=offset,
                        mem_update=mem_update,
                    )
                )
    if len(results) != 18:
        raise ValueError(f"expected 18 keccak parameterized cases, found {len(results)}")
    return results


def _scan_diff_mem_msg_sizes_cases(text: str) -> list[AutoKeccakInventoryEntry]:
    _require_function(text, "test_keccak_diff_mem_msg_sizes")
    mem_sizes = [
        _parse_int_literal(value)
        for value in _extract_param_values(
            text,
            r'@pytest\.mark\.parametrize\("mem_size", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("msg_size", \[(?P<values2>[^\]]+)\]\)\ndef test_keccak_diff_mem_msg_sizes',
            group="values",
        )
    ]
    msg_sizes = [
        _parse_int_literal(value)
        for value in _extract_param_values(
            text,
            r'@pytest\.mark\.parametrize\("mem_size", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("msg_size", \[(?P<values2>[^\]]+)\]\)\ndef test_keccak_diff_mem_msg_sizes',
            group="values2",
        )
    ]
    results: list[AutoKeccakInventoryEntry] = []
    for mem_size in mem_sizes:
        for msg_size in msg_sizes:
            results.append(
                AutoKeccakInventoryEntry(
                    upstream_ref=(
                        "tests/benchmark/compute/instruction/test_keccak.py::"
                        f"test_keccak_diff_mem_msg_sizes[mem_size={mem_size}-msg_size={msg_size}]"
                    ),
                    case_id=(
                        "upstream.benchmark.keccak.test_keccak_diff_mem_msg_sizes."
                        f"mem_size_{mem_size}.msg_size_{msg_size}"
                    ),
                    admitted=True,
                    mode="diff_mem_msg_sizes",
                    reasons=[],
                    source="test_keccak_diff_mem_msg_sizes",
                    mem_size=mem_size,
                    msg_size=msg_size,
                )
            )
    if len(results) != 16:
        raise ValueError(f"expected 16 keccak diff mem/msg cases, found {len(results)}")
    return results


def _inventory_entry_to_template(entry: AutoKeccakInventoryEntry) -> KeccakMappingTemplate:
    assert entry.mode is not None
    mode = entry.mode
    if mode not in KECCAK_MODE_SPECS:
        raise ValueError(f"unsupported keccak template mode: {mode}")
    spec = KECCAK_MODE_SPECS[mode]
    description = spec["description"]
    namespace_seed = spec["namespace_seed"]
    notes = json.loads(spec["notes"])
    if mode == "keccak":
        assert entry.mem_alloc_label is not None and entry.offset is not None and entry.mem_update is not None
        description = (
            f"Mapped from execution-specs KECCAK256 calldata benchmark with mem_alloc {entry.mem_alloc_label}, offset {entry.offset}, and mem_update={entry.mem_update}."
        )
        namespace_seed = (
            f"upstream-keccak-{_slugify_label(entry.mem_alloc_label)}-offset{entry.offset}-memupdate-{'true' if entry.mem_update else 'false'}"
        )
        notes = [
            f"Upstream intent: benchmark KECCAK256 after CALLDATACOPY of mem_alloc={entry.mem_alloc_label!r} into offset {entry.offset} with mem_update={entry.mem_update}.",
            "RPC mapping: runtime reproduces the CALLDATACOPY + SHA3 shape, persists the digest into slot0, persists a post-attack memory witness word into slot1, and persists the pre-instrumentation MSIZE into slot2.",
            "Admitted because the stored digest and memory witnesses make offset and mem_update drift visible without pretending to prove upstream throughput.",
        ]
    elif mode == "diff_mem_msg_sizes":
        assert entry.mem_size is not None and entry.msg_size is not None
        description = (
            f"Mapped from execution-specs KECCAK256 benchmark with pre-expanded mem_size {entry.mem_size} and hashed msg_size {entry.msg_size}."
        )
        namespace_seed = f"upstream-keccak-diff-mem{entry.mem_size}-msg{entry.msg_size}"
        notes = [
            f"Upstream intent: benchmark KECCAK256 with setup memory size {entry.mem_size} and message size {entry.msg_size}.",
            "RPC mapping: runtime reproduces the setup MSTORE8 when present, hashes msg_size bytes from memory offset 0, stores the digest in slot0, stores msg_size in slot1, and stores the pre-instrumentation MSIZE in slot2.",
            "Admitted because the digest and explicit size witnesses make memory/message drift visible in final storage.",
        ]
    elif mode == "max_permutations":
        assert entry.witness_input_length is not None
        description = (
            f"Mapped from execution-specs KECCAK256 max-permutations benchmark using deterministic witness input length {entry.witness_input_length}."
        )
        namespace_seed = f"upstream-keccak-max-permutations-len{entry.witness_input_length}"
        notes = [
            f"Upstream intent: maximize KECCAK256 permutations per block; traced witness length is {entry.witness_input_length} bytes under the Prague benchmark gas budget.",
            "RPC mapping: runtime performs a single SHA3 over zero-initialized memory of that length, stores the digest in slot0, the selected input length in slot1, and the pre-instrumentation MSIZE in slot2.",
            "Admitted as a deterministic input-shape witness only; it does not claim benchmark throughput parity.",
        ]
    return KeccakMappingTemplate(
        case_id=entry.case_id,
        description=description,
        namespace_seed=namespace_seed,
        upstream_ref=entry.upstream_ref,
        notes=notes,
        mode=mode,
        mem_alloc_hex=entry.mem_alloc_hex,
        mem_alloc_label=entry.mem_alloc_label,
        offset=entry.offset,
        mem_update=entry.mem_update,
        mem_size=entry.mem_size,
        msg_size=entry.msg_size,
        witness_input_length=entry.witness_input_length,
    )


def _keccak_probe_metadata(template: KeccakMappingTemplate) -> dict[str, Any]:
    metadata: dict[str, Any] = {"mode": template.mode}
    if template.mode == "max_permutations":
        metadata["witness_input_length"] = _require_int(template.witness_input_length, field="witness_input_length")
    elif template.mode == "keccak":
        metadata["mem_alloc_hex"] = _require_str(template.mem_alloc_hex, field="mem_alloc_hex")
        metadata["offset"] = _require_int(template.offset, field="offset")
        metadata["mem_update"] = _require_bool(template.mem_update, field="mem_update")
    elif template.mode == "diff_mem_msg_sizes":
        metadata["mem_size"] = _require_int(template.mem_size, field="mem_size")
        metadata["msg_size"] = _require_int(template.msg_size, field="msg_size")
    else:
        raise ValueError(f"unsupported keccak mapping mode: {template.mode}")
    return metadata


def _expected_max_permutations_storage(witness_length: int) -> dict[str, dict[str, str]]:
    digest = _keccak_digest_hex(b"\x00" * witness_length)
    msize = _round_up_32(witness_length)
    return {
        "storage": {
            "0x00": digest,
            "0x01": _word_hex(witness_length),
            "0x02": _word_hex(msize),
        }
    }


def _expected_keccak_storage(*, mem_alloc_hex: str, offset: int, mem_update: bool) -> dict[str, dict[str, str]]:
    calldata = bytes.fromhex(mem_alloc_hex)
    digest, memory_witness_word, pre_witness_msize = simulate_basic_keccak_case(
        calldata=calldata,
        offset=offset,
        mem_update=mem_update,
    )
    return {
        "storage": {
            "0x00": digest,
            "0x01": _word_hex(memory_witness_word),
            "0x02": _word_hex(pre_witness_msize),
        }
    }


def _expected_diff_mem_msg_sizes_storage(*, mem_size: int, msg_size: int) -> dict[str, dict[str, str]]:
    digest, pre_witness_msize = simulate_diff_mem_msg_sizes_case(mem_size=mem_size, msg_size=msg_size)
    return {
        "storage": {
            "0x00": digest,
            "0x01": _word_hex(msg_size),
            "0x02": _word_hex(pre_witness_msize),
        }
    }


def simulate_basic_keccak_case(*, calldata: bytes, offset: int, mem_update: bool) -> tuple[str, int, int]:
    memory = _MemoryState()
    memory.calldatacopy(offset, calldata)
    digest = memory.sha3(offset, len(calldata))
    if mem_update:
        memory.mstore(0, int.from_bytes(bytes.fromhex(digest[2:]), "big"))
    pre_witness_msize = memory.msize()
    memory_witness_word = memory.mload(0)
    return digest, memory_witness_word, pre_witness_msize


def simulate_diff_mem_msg_sizes_case(*, mem_size: int, msg_size: int) -> tuple[str, int]:
    memory = _MemoryState()
    if mem_size > 0:
        memory.mstore8(mem_size - 1, 0xFF)
    digest = memory.sha3(0, msg_size)
    memory.mstore(0, int.from_bytes(bytes.fromhex(digest[2:]), "big"))
    return digest, memory.msize()


def _build_keccak_runtime(template: KeccakMappingTemplate) -> str:
    if template.mode == "max_permutations":
        return _build_max_permutations_runtime(_require_int(template.witness_input_length, field="witness_input_length"))
    if template.mode == "keccak":
        return _build_basic_keccak_runtime(
            offset=_require_int(template.offset, field="offset"),
            mem_update=_require_bool(template.mem_update, field="mem_update"),
        )
    if template.mode == "diff_mem_msg_sizes":
        return _build_diff_mem_msg_sizes_runtime(
            mem_size=_require_int(template.mem_size, field="mem_size"),
            msg_size=_require_int(template.msg_size, field="msg_size"),
        )
    raise ValueError(f"unsupported keccak mapping mode: {template.mode}")


def _build_basic_keccak_runtime(*, offset: int, mem_update: bool) -> str:
    code = bytearray()
    code.append(0x36)  # CALLDATASIZE
    code.append(0x80)  # DUP1
    code += _push_int(0)
    code += _push_int(offset)
    code.append(0x37)  # CALLDATACOPY
    code.append(0x36)  # CALLDATASIZE
    code += _push_int(offset)
    code.append(0x20)  # SHA3
    code.append(0x80)  # DUP1
    code += _push_int(0)
    code.append(0x55)  # SSTORE slot0=digest, leaves digest
    if mem_update:
        code += _push_int(0)
        code.append(0x52)  # MSTORE(0, digest)
    else:
        code.append(0x50)  # POP digest
    code.append(0x59)  # MSIZE
    code += _push_int(2)
    code.append(0x55)  # SSTORE slot2=msize before witness read
    code += _push_int(0)
    code.append(0x51)  # MLOAD(0)
    code += _push_int(1)
    code.append(0x55)  # SSTORE slot1=memory witness word
    code.append(0x00)
    return "0x" + code.hex()


def _build_diff_mem_msg_sizes_runtime(*, mem_size: int, msg_size: int) -> str:
    code = bytearray()
    if mem_size > 0:
        code += _push_int(0xFF)
        code += _push_int(mem_size - 1)
        code.append(0x53)  # MSTORE8
    code += _push_int(msg_size)
    code += _push_int(0)
    code.append(0x20)  # SHA3
    code.append(0x80)  # DUP1
    code += _push_int(0)
    code.append(0x55)  # SSTORE slot0=digest, leaves digest
    code += _push_int(0)
    code.append(0x52)  # MSTORE(0, digest)
    code += _push_int(msg_size)
    code += _push_int(1)
    code.append(0x55)  # SSTORE slot1=msg_size
    code.append(0x59)  # MSIZE
    code += _push_int(2)
    code.append(0x55)  # SSTORE slot2=pre-instrumentation msize
    code.append(0x00)
    return "0x" + code.hex()


def _build_max_permutations_runtime(witness_input_length: int) -> str:
    code = bytearray()
    code += _push_int(witness_input_length)
    code.append(0x80)  # DUP1 keep length witness
    code += _push_int(0)
    code.append(0x20)  # SHA3 over zero memory
    code.append(0x80)  # DUP1
    code += _push_int(0)
    code.append(0x55)  # SSTORE slot0=digest
    code.append(0x50)  # POP extra digest
    code.append(0x80)  # DUP1 length witness
    code += _push_int(1)
    code.append(0x55)  # SSTORE slot1=length
    code.append(0x59)  # MSIZE
    code += _push_int(2)
    code.append(0x55)  # SSTORE slot2=msize
    code.append(0x00)
    return "0x" + code.hex()


def _build_keccak_case(
    template: KeccakMappingTemplate,
    *,
    observe: dict[str, Any],
    steps: list[dict[str, Any]],
    expected: dict[str, Any],
) -> dict[str, Any]:
    case = build_case(template, steps=steps, expected=expected)  # type: ignore[arg-type]
    case["family"] = "state/keccak"
    case["observe"] = observe
    return case


def _load_keccak_template_entry(entry: object, *, index: int) -> KeccakMappingTemplate:
    if not isinstance(entry, dict):
        raise ValueError(f"keccak template entry {index} must be an object")
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
            raise ValueError(f"keccak template entry {index} missing required field: {field}")
    mode = entry["mode"]
    if mode not in KECCAK_MODE_SPECS:
        raise ValueError(f"unsupported keccak template mode: {mode}")
    notes = entry["notes"]
    if not isinstance(notes, list) or not all(isinstance(note, str) for note in notes):
        raise ValueError(f"keccak template entry {index} field 'notes' must be a list of strings")
    return KeccakMappingTemplate(
        case_id=str(entry["case_id"]),
        description=str(entry["description"]),
        namespace_seed=str(entry["namespace_seed"]),
        upstream_ref=str(entry["upstream_ref"]),
        notes=list(notes),
        mode=mode,
        mem_alloc_hex=_opt_str(entry.get("mem_alloc_hex")),
        mem_alloc_label=_opt_str(entry.get("mem_alloc_label")),
        offset=_opt_int(entry.get("offset")),
        mem_update=_opt_bool(entry.get("mem_update")),
        mem_size=_opt_int(entry.get("mem_size")),
        msg_size=_opt_int(entry.get("msg_size")),
        witness_input_length=_opt_int(entry.get("witness_input_length")),
    )


def _require_function(text: str, function_name: str) -> None:
    if f"def {function_name}(" not in text:
        raise ValueError(f"could not find benchmark function {function_name}")


def _extract_param_values(text: str, pattern: str, *, group: str = "values") -> list[str]:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise ValueError(f"could not match pattern: {pattern}")
    return [value.strip() for value in match.group(group).split(",") if value.strip()]


def _extract_pytest_param_entries(text: str, *, function_name: str, param_name: str) -> list[tuple[str, str]]:
    func_marker = f"def {function_name}("
    func = text.find(func_marker)
    if func == -1:
        raise ValueError(f"could not find benchmark function {function_name}")
    prefix = text[:func]
    pattern = re.compile(
        rf'@pytest\.mark\.parametrize\(\s*"{re.escape(param_name)}",\s*\[(?P<values>.*?)\]\s*\)',
        re.MULTILINE | re.DOTALL,
    )
    matches = list(pattern.finditer(prefix))
    if not matches:
        raise ValueError(f"could not find parameter block for {function_name} field {param_name}")
    values_block = matches[-1].group("values")
    entries: list[tuple[str, str]] = []
    if "pytest.param" in values_block:
        for param_match in re.finditer(
            r'pytest\.param\((?P<value>b"[^"]*"(?:\s*\*\s*\d+)?),\s*id="(?P<label>[^"]+)"\)',
            values_block,
        ):
            entries.append((param_match.group("value"), param_match.group("label")))
    else:
        raw_values = [value.strip() for value in values_block.split(",") if value.strip()]
        for raw in raw_values:
            label = raw.removeprefix('b"').removesuffix('"') or "empty"
            entries.append((raw, label))
    if not entries:
        raise ValueError(f"could not parse pytest.param entries for {function_name} field {param_name}")
    return entries


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


def _parse_bytes_literal(value: str) -> bytes:
    normalized = value.strip()
    match = re.fullmatch(r'b"(?P<body>[^"]*)"(?:\s*\*\s*(?P<repeat>\d+))?', normalized)
    if not match:
        raise ValueError(f"unsupported bytes literal: {value}")
    body = match.group("body")
    repeat = int(match.group("repeat") or "1")
    return body.encode() * repeat


def _slugify_label(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")


def _keccak_digest_hex(data: bytes) -> str:
    return "0x" + keccak256(data).hex()


def _memory_expansion_cost(new_bytes: int) -> int:
    words = math.ceil(new_bytes / 32)
    return 3 * words + (words * words) // 512


def _round_up_32(size: int) -> int:
    if size <= 0:
        return 0
    return ((size + 31) // 32) * 32


def _memory_gas_hex(size_hint: int) -> str:
    if size_hint >= 100_000:
        return "0x1e8480"  # 2,000,000
    if size_hint >= 10_240:
        return "0x0f4240"  # 1,000,000
    if size_hint >= 1_024:
        return "0x061a80"  # 400,000
    return "0xc350"  # 50,000


class _MemoryState:
    def __init__(self) -> None:
        self._memory = bytearray()

    def _ensure(self, size: int) -> None:
        if size <= len(self._memory):
            return
        target = _round_up_32(size)
        self._memory.extend(b"\x00" * (target - len(self._memory)))

    def calldatacopy(self, offset: int, calldata: bytes) -> None:
        if not calldata:
            return
        self._ensure(offset + len(calldata))
        self._memory[offset : offset + len(calldata)] = calldata

    def mstore8(self, offset: int, value: int) -> None:
        self._ensure(offset + 1)
        self._memory[offset] = value & 0xFF

    def mstore(self, offset: int, value: int) -> None:
        self._ensure(offset + 32)
        self._memory[offset : offset + 32] = value.to_bytes(32, "big")

    def mload(self, offset: int) -> int:
        self._ensure(offset + 32)
        return int.from_bytes(self._memory[offset : offset + 32], "big")

    def sha3(self, offset: int, size: int) -> str:
        if size > 0:
            self._ensure(offset + size)
            payload = bytes(self._memory[offset : offset + size])
        else:
            payload = b""
        return _keccak_digest_hex(payload)

    def msize(self) -> int:
        return len(self._memory)


def _opt_str(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _opt_int(value: object) -> int | None:
    if value is None:
        return None
    return int(value)


def _opt_bool(value: object) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    raise ValueError(f"expected bool, got {value!r}")


def _require_str(value: str | None, *, field: str) -> str:
    if value is None:
        raise ValueError(f"missing keccak template field: {field}")
    return value


def _require_int(value: int | None, *, field: str) -> int:
    if value is None:
        raise ValueError(f"missing keccak template field: {field}")
    return value


def _require_bool(value: bool | None, *, field: str) -> bool:
    if value is None:
        raise ValueError(f"missing keccak template field: {field}")
    return value
