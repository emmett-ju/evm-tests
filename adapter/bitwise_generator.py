from __future__ import annotations

import json
import random
import re
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from adapter.generator import build_case, deploy_contract_step, invoke_contract_step, wait_receipt_step
from adapter.inventory import write_inventory_payload
from adapter.manifest import resolve_execution_specs_ref
from adapter.assembler import _push_int, _word_hex, _build_init_code


BLOCKED_REASON = "requires gas-sensitive benchmark shape not yet mapped"
SHIFT_WITNESS_DEPLOY_GAS = "0x989680"
SHIFT_WITNESS_INVOKE_GAS = "0x0f4240"
UPSTREAM_MAX_CODE_SIZE = 24_576
UPSTREAM_SHIFT_PREFIX_LEN = 34
UPSTREAM_SHIFT_SUFFIX_LEN = 4
UPSTREAM_CLZ_DIFF_PREFIX_LEN = 1
UPSTREAM_CLZ_DIFF_SUFFIX_LEN = 2
CLZ_DIFF_DEPLOY_GAS = "0x989680"
CLZ_DIFF_INVOKE_GAS = "0x0f4240"
SHIFT_INITIAL_VALUE = (1 << 256) - 1
SHIFT_AMOUNTS: tuple[int, ...] = tuple(x + (x >= 8) + (x >= 15) for x in range(1, 16))


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


@dataclass(frozen=True, slots=True)
class ShiftWitness:
    opcode: str
    rounds: int
    final_value: int
    schedule: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class ClzDiffWitness:
    rounds: int
    final_accumulator: int
    schedule: tuple[tuple[int, int], ...]


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
        (
            "AND",
            (
                115792089237316195423570985008687907853269984665640564039457584007908834671663,
                52435875175126190479447740508185965837690552500527637822603658699938581184513,
            ),
        ),
        (
            "OR",
            (
                115792089237316195423570985008687907853269984665640564039457584007908834671663,
                52435875175126190479447740508185965837690552500527637822603658699938581184513,
            ),
        ),
        (
            "XOR",
            (
                115792089237316195423570985008687907853269984665640564039457584007908834671663,
                52435875175126190479447740508185965837690552500527637822603658699938581184513,
            ),
        ),
        (
            "BYTE",
            (
                31,
                115792089237316195423570985008687907853269984665640564039457584007908834671663,
            ),
        ),
        (
            "SHL",
            (
                1,
                115792089237316195423570985008687907853269984665640564039457584007908834671663,
            ),
        ),
        (
            "SHR",
            (
                1,
                115792089237316195423570985008687907853269984665640564039457584007908834671663,
            ),
        ),
        (
            "SAR",
            (
                1,
                115792089237316195423570985008687907853269984665640564039457584007908834671663,
            ),
        ),
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
                admitted=True,
                mode="test_shifts",
                reasons=[],
                source="test_shifts",
                opcode=opcode,
                args=(),
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
                admitted=True,
                mode="test_clz_diff",
                reasons=[],
                source="test_clz_diff",
                opcode="CLZ",
                args=(),
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
    opcode = entry.opcode or ""
    if entry.source == "test_shifts":
        witness = _compute_shift_witness(opcode)
        return BitwiseMappingTemplate(
            case_id=entry.case_id,
            description=(
                f"Mapped from execution-specs {opcode} shift benchmark onto an RPC-only deterministic witness flow."
            ),
            namespace_seed=f"upstream-bitwise-shifts-{opcode.lower()}",
            upstream_ref=entry.upstream_ref,
            notes=[
                f"Upstream intent: benchmark {opcode} inside the fixed-seed `test_shifts` benchmark shape.",
                (
                    "RPC mapping: replay the upstream-derived finite shift schedule as a benchmark-shape witness, "
                    "store the final post-schedule value in slot0, and validate the exact runtime bytes in the mock backend."
                ),
                (
                    f"Admitted as a deterministic witness of the current benchmark shape only; it does not claim throughput parity. "
                    f"This witness currently replays {witness.rounds} upstream-derived shift pairs."
                ),
            ],
            mode="test_shifts",
            opcode=opcode,
            args=(),
        )
    if entry.source == "test_clz_diff":
        witness = _compute_clz_diff_witness()
        return BitwiseMappingTemplate(
            case_id=entry.case_id,
            description="Mapped from execution-specs CLZ-diff benchmark onto an RPC-only deterministic witness flow.",
            namespace_seed="upstream-bitwise-clz-diff",
            upstream_ref=entry.upstream_ref,
            notes=[
                "Upstream intent: benchmark CLZ across a max-code-size-bounded sequence of different immediate inputs.",
                (
                    "RPC mapping: replay the upstream-derived finite CLZ input schedule as a benchmark-shape witness, "
                    "accumulate each CLZ result into a final storage word, and validate the exact runtime bytes in the mock backend."
                ),
                (
                    f"Admitted as a deterministic witness of the current benchmark shape only; it does not claim throughput parity. "
                    f"This witness currently replays {witness.rounds} CLZ inputs derived from the upstream max-code-size loop."
                ),
            ],
            mode="test_clz_diff",
            opcode="CLZ",
            args=(),
        )
    return BitwiseMappingTemplate(
        case_id=entry.case_id,
        description=f"Mapped from execution-specs {opcode} onto an RPC-only deploy/call/storage-assert flow.",
        namespace_seed=f"upstream-bitwise-{opcode.lower()}",
        upstream_ref=entry.upstream_ref,
        notes=[
            f"Upstream intent: benchmark {opcode} with specific parameters.",
            "RPC mapping: runtime pushes parameters, executes the opcode, and writes the result to storage slot0.",
            "Admitted because the mathematical result is perfectly deterministic and observable in final storage.",
        ],
        mode=entry.mode or "",
        opcode=opcode,
        args=entry.args or (),
    )


def _to_signed(value: int) -> int:
    return value if value < (1 << 255) else value - (1 << 256)


def _to_unsigned(value: int) -> int:
    return value if value >= 0 else value + (1 << 256)


def _simulate_bitwise(opcode: str, args: tuple[int, ...]) -> int:
    if opcode == "AND":
        return args[0] & args[1]
    if opcode == "OR":
        return args[0] | args[1]
    if opcode == "XOR":
        return args[0] ^ args[1]
    if opcode == "NOT":
        return ~args[0] & ((1 << 256) - 1)
    if opcode == "BYTE":
        idx, val = args[0], args[1]
        if idx >= 32:
            return 0
        return (val >> ((31 - idx) * 8)) & 0xFF
    if opcode == "SHL":
        shift, val = args[0], args[1]
        if shift >= 256:
            return 0
        return (val << shift) & ((1 << 256) - 1)
    if opcode == "SHR":
        shift, val = args[0], args[1]
        if shift >= 256:
            return 0
        return val >> shift
    if opcode == "SAR":
        shift, val = args[0], args[1]
        is_neg = (val & (1 << 255)) != 0
        if shift >= 256:
            return ((1 << 256) - 1) if is_neg else 0
        if is_neg:
            val_signed = val - (1 << 256)
            res = val_signed >> shift
            return res + (1 << 256)
        return val >> shift
    if opcode == "CLZ":
        val = args[0]
        if val == 0:
            return 256
        return 256 - val.bit_length()
    raise ValueError(f"unsupported bitwise opcode: {opcode}")


@lru_cache(maxsize=None)
def _compute_shift_witness(opcode: str) -> ShiftWitness:
    if opcode not in {"SHR", "SAR"}:
        raise ValueError(f"unsupported shift witness opcode: {opcode}")
    shift_right_fn = _shift_right_function(opcode)
    rng = random.Random(1)
    value = SHIFT_INITIAL_VALUE
    code_body_len = UPSTREAM_MAX_CODE_SIZE - UPSTREAM_SHIFT_PREFIX_LEN - UPSTREAM_SHIFT_SUFFIX_LEN
    schedule: list[tuple[int, int]] = []
    code_body_bytes = 0
    while code_body_bytes <= code_body_len - 4:
        value, left_index = _select_shift_amount(rng, value, _shift_left_mod)
        value, right_index = _select_shift_amount(rng, value, shift_right_fn)
        schedule.append((left_index, right_index))
        code_body_bytes += 4
    return ShiftWitness(
        opcode=opcode,
        rounds=len(schedule),
        final_value=value,
        schedule=tuple(schedule),
    )


def _shift_left_mod(value: int, shift: int) -> int:
    return (value << shift) % (1 << 256)


def _shift_right_function(opcode: str):
    if opcode == "SHR":
        return lambda value, shift: value >> shift
    if opcode == "SAR":
        return lambda value, shift: _to_unsigned(_to_signed(value) >> shift)
    raise ValueError(f"unsupported shift witness opcode: {opcode}")


def _select_shift_amount(rng: random.Random, value: int, shift_fn) -> tuple[int, int]:
    while True:
        index = rng.randint(0, len(SHIFT_AMOUNTS) - 1)
        shift = SHIFT_AMOUNTS[index]
        new_value = shift_fn(value, shift) % (1 << 256)
        if new_value != 0:
            return new_value, index


@lru_cache(maxsize=None)
def _compute_clz_diff_witness() -> ClzDiffWitness:
    schedule: list[tuple[int, int]] = []
    code_body_len = UPSTREAM_MAX_CODE_SIZE - UPSTREAM_CLZ_DIFF_PREFIX_LEN - UPSTREAM_CLZ_DIFF_SUFFIX_LEN
    code_body_bytes = 0
    accumulator = 0
    for i in range(code_body_len):
        value = ((1 << 256) - 1) >> (i % 256)
        clz_result = _simulate_bitwise("CLZ", (value,))
        op_len = len(_push_int(value)) + 2  # CLZ + POP in the upstream benchmark body.
        if code_body_bytes + op_len > code_body_len:
            break
        schedule.append((value, clz_result))
        accumulator = (accumulator + clz_result) % (1 << 256)
        code_body_bytes += op_len
    return ClzDiffWitness(
        rounds=len(schedule),
        final_accumulator=accumulator,
        schedule=tuple(schedule),
    )


def _build_clz_diff_witness_runtime() -> str:
    witness = _compute_clz_diff_witness()
    code = bytearray()
    code += _push_int(0)  # accumulator
    for value, _ in witness.schedule:
        code += _push_int(value)
        code.append(OPCODES["CLZ"])
        code.append(0x01)  # ADD accumulator += CLZ(value)
    code += _push_int(0)
    code.append(0x55)  # SSTORE slot0 <- accumulated CLZ witness
    code.append(0x00)  # STOP
    runtime = "0x" + code.hex()
    if len(bytes.fromhex(runtime.removeprefix("0x"))) > UPSTREAM_MAX_CODE_SIZE:
        raise ValueError("CLZ-diff witness runtime exceeds max code size")
    return runtime


OPCODES: dict[str, int] = {
    "AND": 0x16,
    "OR": 0x17,
    "XOR": 0x18,
    "NOT": 0x19,
    "BYTE": 0x1A,
    "SHL": 0x1B,
    "SHR": 0x1C,
    "SAR": 0x1D,
    "CLZ": 0x1E,
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


def _build_large_init_code(runtime_code: str) -> str:
    runtime_hex = runtime_code.removeprefix("0x")
    runtime_bytes = bytes.fromhex(runtime_hex)
    length = len(runtime_bytes)
    if length == 0:
        raise ValueError("runtime_code must not be empty")
    if length <= 0xFF:
        return _build_init_code(runtime_code)
    length_push = _push_int(length)
    offset = 0
    while True:
        offset_push = _push_int(offset)
        header = length_push + offset_push + _push_int(0) + bytes([0x39]) + length_push + _push_int(0) + bytes([0xF3])
        if len(header) == offset:
            break
        offset = len(header)
    return "0x" + header.hex() + runtime_hex


def _build_shift_witness_runtime(opcode: str) -> str:
    witness = _compute_shift_witness(opcode)
    code = bytearray()
    for shift in SHIFT_AMOUNTS:
        code += _push_int(shift)
    code += _push_int(0)
    code.append(0x35)  # CALLDATALOAD
    for left_index, right_index in witness.schedule:
        code.append(_dup_opcode_for_shift_index(left_index))
        code.append(OPCODES["SHL"])
        code.append(_dup_opcode_for_shift_index(right_index))
        code.append(OPCODES[opcode])
    code += _push_int(0)
    code.append(0x55)  # SSTORE slot0 <- final witness value
    code.append(0x00)  # STOP
    runtime = "0x" + code.hex()
    if len(bytes.fromhex(runtime.removeprefix("0x"))) > UPSTREAM_MAX_CODE_SIZE:
        raise ValueError(f"shift witness runtime exceeds max code size for {opcode}")
    return runtime


def _dup_opcode_for_shift_index(index: int) -> int:
    stack_index = len(SHIFT_AMOUNTS) - index
    if not 1 <= stack_index <= 15:
        raise ValueError(f"unsupported shift-index duplication target: {index}")
    return 0x80 + stack_index


def render_bitwise_case(template: BitwiseMappingTemplate) -> dict[str, Any]:
    deploy_gas = "0x186a0"
    invoke_gas = "0xc350"
    invoke_data = "0x"
    if template.mode == "test_shifts":
        witness = _compute_shift_witness(template.opcode)
        expected_val = witness.final_value
        runtime_code = _build_shift_witness_runtime(template.opcode)
        init_code = _build_large_init_code(runtime_code)
        observe = {
            "storage_address": "$last_contract",
            "bitwise_probe": {
                "mode": template.mode,
                "opcode": template.opcode,
                "args": list(template.args),
                "expected_result": expected_val,
                "initial_value": SHIFT_INITIAL_VALUE,
                "witness_rounds": witness.rounds,
            },
        }
        deploy_gas = SHIFT_WITNESS_DEPLOY_GAS
        invoke_gas = SHIFT_WITNESS_INVOKE_GAS
        invoke_data = _word_hex(SHIFT_INITIAL_VALUE)
    elif template.mode == "test_clz_diff":
        witness = _compute_clz_diff_witness()
        expected_val = witness.final_accumulator
        runtime_code = _build_clz_diff_witness_runtime()
        init_code = _build_large_init_code(runtime_code)
        observe = {
            "storage_address": "$last_contract",
            "bitwise_probe": {
                "mode": template.mode,
                "opcode": template.opcode,
                "args": list(template.args),
                "expected_result": expected_val,
                "witness_rounds": witness.rounds,
            },
        }
        deploy_gas = CLZ_DIFF_DEPLOY_GAS
        invoke_gas = CLZ_DIFF_INVOKE_GAS
    else:
        expected_val = _simulate_bitwise(template.opcode, template.args)
        runtime_code = _build_bitwise_runtime(template.opcode, template.args)
        init_code = _build_init_code(runtime_code)
        observe = {
            "storage_address": "$last_contract",
            "bitwise_probe": {
                "mode": template.mode,
                "opcode": template.opcode,
                "args": list(template.args),
                "expected_result": expected_val,
            },
        }
    expected = {"storage": {"0x00": _word_hex(expected_val)}}
    case = build_case(
        template,  # type: ignore[arg-type]
        steps=[
            deploy_contract_step(
                init_code=init_code,
                runtime_code=runtime_code,
                gas=deploy_gas,
            ),
            wait_receipt_step(),
            invoke_contract_step(data_hex=invoke_data, gas=invoke_gas),
            wait_receipt_step(),
        ],
        expected=expected,
    )
    case["family"] = "state/bitwise"
    case["observe"] = observe
    return case
