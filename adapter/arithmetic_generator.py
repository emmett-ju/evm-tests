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
class ArithmeticMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: str
    opcode: str
    args: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class AutoArithmeticInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str
    opcode: str | None = None
    args: tuple[int, ...] | None = None


def generate_upstream_arithmetic_templates(
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
        else repo_root_path / "third_party" / "execution-specs" / "tests" / "benchmark" / "compute" / "instruction" / "test_arithmetic.py"
    )
    templates, inventory = scan_arithmetic_cases(source)
    payload = {
        "name": "upstream-arithmetic-mapping-templates",
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
            family="arithmetic",
            name="upstream-arithmetic-auto-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload


def generate_upstream_arithmetic_manifest(
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
        else repo_root_path / "suites" / "templates" / "upstream_arithmetic_templates.json"
    )
    data = json.loads(template_file.read_text())
    templates = [
        ArithmeticMappingTemplate(
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
        repo_root_path / "suites" / "manifests" / "upstream_arithmetic_mapped.json",
        "submodule-pending",
    )
    manifest = {
        "name": "upstream-arithmetic-mapped",
        "version": "1",
        "execution_specs_ref": execution_specs_ref,
        "suite_version": suite_version,
        "chain_profile_version": chain_profile_version,
        "cases": [render_arithmetic_case(template) for template in templates],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def scan_arithmetic_cases(
    source_path: str | Path,
) -> tuple[tuple[ArithmeticMappingTemplate, ...], tuple[AutoArithmeticInventoryEntry, ...]]:
    source = Path(source_path)
    text = source.read_text()
    inventory = sorted(
        _scan_test_arithmetic_cases(text)
        + _scan_test_mod_cases(text)
        + _scan_test_mod_arithmetic_cases(text)
        + _scan_test_exp_bench_cases(text),
        key=lambda item: item.upstream_ref,
    )
    templates = tuple(_arithmetic_inventory_entry_to_template(entry) for entry in inventory if entry.admitted)
    return templates, tuple(inventory)


def _scan_test_arithmetic_cases(text: str) -> list[AutoArithmeticInventoryEntry]:
    block = _extract_param_block(text, function_name="test_arithmetic")
    opcodes = [
        match.group("opcode")
        for match in re.finditer(r"^\s*Op\.(?P<opcode>[A-Z0-9_]+),", block, re.MULTILINE)
    ]
    if len(opcodes) != 13:
        raise ValueError(f"expected 13 arithmetic benchmark cases, found {len(opcodes)}")
    
    exact_args = [
        ('ADD', (115792089237316195423570985008687907853269984665640564039457584007908834671663, 52435875175126190479447740508185965837690552500527637822603658699938581184513)),
        ('MUL', (115792089237316195423570985008687907853269984665640564039457584007908834671663, 52435875175126190479447740508185965837690552500527637822603658699938581184513)),
        ('SUB', (115792089237316195423570985008687907853269984665640564039457584007908834671663, 52435875175126190479447740508185965837690552500527637822603658699938581184513)),
        ('DIV', (115792089237316195423570985008687907853269984665640564039457584007908834671663, 340282366920938463463374607431768211507)),
        ('DIV', (115792089237316195423570985008687907853269984665640564039457584007908834671663, 18446744073709551667)),
        ('SDIV', (57896044618658097711785492504343953926634992332820282019728792003952269851695, 115792089237316195423570985008687907852929702298719625575994209400481361428429)),
        ('SDIV', (57896044618658097711785492504343953926634992332820282019728792003952269851695, 115792089237316195423570985008687907853269984665640564039439137263839420088269)),
        ('MOD', (115792089237316195423570985008687907853269984665640564039457584007908834671663, 52435875175126190479447740508185965837690552500527637822603658699938581184513)),
        ('SMOD', (115792089237316195423570985008687907853269984665640564039457584007908834671663, 52435875175126190479447740508185965837690552500527637822603658699938581184513)),
        ('EXP', (115792089237316195423570985008687907853269984665640564039457584007913129639935, 115792089237316195423570985008687907853269984665640564039457584007913129639935)),
        ('SIGNEXTEND', (3, 4292532954)),
        ('ADDMOD', (115792089237316195423570985008687907853269984665640564039457584007908834671663, 52435875175126190479447740508185965837690552500527637822603658699938581184513, 340282366920938463463374607431768211507)),
        ('MULMOD', (115792089237316195423570985008687907853269984665640564039457584007908834671663, 52435875175126190479447740508185965837690552500527637822603658699938581184513, 340282366920938463463374607431768211507))
    ]
    
    entries: list[AutoArithmeticInventoryEntry] = []
    ordinal_by_opcode: dict[str, int] = {}
    for opcode, args in zip(opcodes, [v[1] for v in exact_args]):
        arg_arity = 3 if opcode in {"ADDMOD", "MULMOD"} else 2
        ordinal = ordinal_by_opcode.get(opcode, 0)
        ordinal_by_opcode[opcode] = ordinal + 1
        suffix = f"variant_{ordinal}" if ordinal else "base"
        upstream_ref = (
            "tests/benchmark/compute/instruction/test_arithmetic.py::"
            f"test_arithmetic[opcode={opcode}-variant={suffix}]"
        )
        case_id = f"upstream.benchmark.arithmetic.test_arithmetic.{opcode.lower()}.{suffix}.arity_{arg_arity}"
        entries.append(
            AutoArithmeticInventoryEntry(
                upstream_ref=upstream_ref,
                case_id=case_id,
                admitted=True,
                mode="test_arithmetic",
                reasons=[],
                source="test_arithmetic",
                opcode=opcode,
                args=args,
            )
        )
    return entries


def _scan_test_mod_cases(text: str) -> list[AutoArithmeticInventoryEntry]:
    mod_bits = _extract_param_values(
        text,
        r'@pytest\.mark\.parametrize\("mod_bits", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("opcode", \[(?P<values2>[^\]]+)\]\)\n@pytest\.mark\.repricing\ndef test_mod',
        group="values",
    )
    opcodes = _extract_param_values(
        text,
        r'@pytest\.mark\.parametrize\("mod_bits", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("opcode", \[(?P<values2>[^\]]+)\]\)\n@pytest\.mark\.repricing\ndef test_mod',
        group="values2",
    )
    entries: list[AutoArithmeticInventoryEntry] = []
    for opcode in [value.split(".")[-1] for value in opcodes]:
        for mod_bit in [_parse_int_literal(value) for value in mod_bits]:
            upstream_ref = (
                "tests/benchmark/compute/instruction/test_arithmetic.py::"
                f"test_mod[opcode={opcode}-mod_bits={mod_bit}]"
            )
            case_id = f"upstream.benchmark.arithmetic.test_mod.{opcode.lower()}.mod_bits_{mod_bit}"
            args = ((1 << 256) - 1, (1 << mod_bit) - 1)
            entries.append(
                AutoArithmeticInventoryEntry(
                    upstream_ref=upstream_ref,
                    case_id=case_id,
                    admitted=True,
                    mode="test_mod",
                    reasons=[],
                    source="test_mod",
                    opcode=opcode,
                    args=args,
                )
            )
    if len(entries) != 8:
        raise ValueError(f"expected 8 mod benchmark cases, found {len(entries)}")
    return entries


def _scan_test_mod_arithmetic_cases(text: str) -> list[AutoArithmeticInventoryEntry]:
    mod_bits = _extract_param_values(
        text,
        r'@pytest\.mark\.repricing\(mod_bits=191\)\n@pytest\.mark\.parametrize\("mod_bits", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("opcode", \[(?P<values2>[^\]]+)\]\)\ndef test_mod_arithmetic',
        group="values",
    )
    opcodes = _extract_param_values(
        text,
        r'@pytest\.mark\.repricing\(mod_bits=191\)\n@pytest\.mark\.parametrize\("mod_bits", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("opcode", \[(?P<values2>[^\]]+)\]\)\ndef test_mod_arithmetic',
        group="values2",
    )
    entries: list[AutoArithmeticInventoryEntry] = []
    for opcode in [value.split(".")[-1] for value in opcodes]:
        for mod_bit in [_parse_int_literal(value) for value in mod_bits]:
            upstream_ref = (
                "tests/benchmark/compute/instruction/test_arithmetic.py::"
                f"test_mod_arithmetic[opcode={opcode}-mod_bits={mod_bit}]"
            )
            case_id = f"upstream.benchmark.arithmetic.test_mod_arithmetic.{opcode.lower()}.mod_bits_{mod_bit}"
            args = ((1 << 256) - 1, (1 << 256) - 2, (1 << mod_bit) - 1)
            entries.append(
                AutoArithmeticInventoryEntry(
                    upstream_ref=upstream_ref,
                    case_id=case_id,
                    admitted=True,
                    mode="test_mod_arithmetic",
                    reasons=[],
                    source="test_mod_arithmetic",
                    opcode=opcode,
                    args=args,
                )
            )
    if len(entries) != 8:
        raise ValueError(f"expected 8 mod_arithmetic benchmark cases, found {len(entries)}")
    return entries


def _scan_test_exp_bench_cases(text: str) -> list[AutoArithmeticInventoryEntry]:
    bases = _extract_param_values(
        text,
        r'@pytest\.mark\.parametrize\("base", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("exp", \[(?P<values2>[^\]]+)\]\)\ndef test_exp_bench_arithmetic',
        group="values",
    )
    exponents = _extract_param_values(
        text,
        r'@pytest\.mark\.parametrize\("base", \[(?P<values>[^\]]+)\]\)\n@pytest\.mark\.parametrize\("exp", \[(?P<values2>[^\]]+)\]\)\ndef test_exp_bench_arithmetic',
        group="values2",
    )
    entries: list[AutoArithmeticInventoryEntry] = []
    for exp in [_parse_int_literal(value) for value in exponents]:
        for base in [_parse_int_literal(value) for value in bases]:
            upstream_ref = (
                "tests/benchmark/compute/instruction/test_arithmetic.py::"
                f"test_exp_bench_arithmetic[exp={exp}-base={base}]"
            )
            case_id = f"upstream.benchmark.arithmetic.test_exp_bench_arithmetic.exp_{exp}.base_{base}"
            args = (base, exp)
            entries.append(
                AutoArithmeticInventoryEntry(
                    upstream_ref=upstream_ref,
                    case_id=case_id,
                    admitted=True,
                    mode="test_exp_bench_arithmetic",
                    reasons=[],
                    source="test_exp_bench_arithmetic",
                    opcode="EXP",
                    args=args,
                )
            )
    if len(entries) != 36:
        raise ValueError(f"expected 36 exp benchmark cases, found {len(entries)}")
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


def _extract_param_values(text: str, pattern: str, *, group: str = "values") -> list[str]:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise ValueError(f"could not match pattern: {pattern}")
    values = match.group(group)
    return [value.strip() for value in values.split(",") if value.strip()]


def _parse_int_literal(value: str) -> int:
    normalized = value.replace("_", "").strip()
    if "*" in normalized:
        left, right = [part.strip() for part in normalized.split("*", 1)]
        return int(left) * int(right)
    return int(normalized)


def _arithmetic_inventory_entry_to_template(entry: AutoArithmeticInventoryEntry) -> ArithmeticMappingTemplate:
    return ArithmeticMappingTemplate(
        case_id=entry.case_id,
        description=f"Mapped from execution-specs {entry.opcode} onto an RPC-only deploy/call/storage-assert flow.",
        namespace_seed=f"upstream-arithmetic-{entry.opcode.lower()}",
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


def _simulate_math(opcode: str, args: tuple[int, ...]) -> int:
    if opcode == 'ADD':
        return (args[0] + args[1]) & ((1<<256)-1)
    elif opcode == 'MUL':
        return (args[0] * args[1]) & ((1<<256)-1)
    elif opcode == 'SUB':
        return (args[0] - args[1]) & ((1<<256)-1)
    elif opcode == 'DIV':
        return 0 if args[1] == 0 else args[0] // args[1]
    elif opcode == 'SDIV':
        def to_signed(v: int) -> int:
            return v if v < (1<<255) else v - (1<<256)
        def from_signed(v: int) -> int:
            return v if v >= 0 else v + (1<<256)
        a, b = to_signed(args[0]), to_signed(args[1])
        if b == 0:
            return 0
        res = abs(a) // abs(b)
        if (a < 0) != (b < 0) and res != 0:
            res = -res
        return from_signed(res) & ((1<<256)-1)
    elif opcode == 'MOD':
        return 0 if args[1] == 0 else args[0] % args[1]
    elif opcode == 'SMOD':
        def to_signed(v: int) -> int:
            return v if v < (1<<255) else v - (1<<256)
        def from_signed(v: int) -> int:
            return v if v >= 0 else v + (1<<256)
        a, b = to_signed(args[0]), to_signed(args[1])
        if b == 0:
            return 0
        res = abs(a) % abs(b)
        if a < 0 and res != 0:
            res = -res
        return from_signed(res) & ((1<<256)-1)
    elif opcode == 'EXP':
        return pow(args[0], args[1], 1<<256)
    elif opcode == 'SIGNEXTEND':
        size = args[0]
        val = args[1]
        if size > 31:
            return val
        sign_bit = (val >> (size * 8 + 7)) & 1
        mask = (1 << ((size + 1) * 8)) - 1
        if sign_bit:
            return val | ~mask & ((1<<256)-1)
        else:
            return val & mask
    elif opcode == 'ADDMOD':
        return 0 if args[2] == 0 else (args[0] + args[1]) % args[2]
    elif opcode == 'MULMOD':
        return 0 if args[2] == 0 else (args[0] * args[1]) % args[2]
    raise ValueError(f"unsupported arithmetic opcode: {opcode}")


OPCODES: dict[str, int] = {
    'ADD': 0x01,
    'MUL': 0x02,
    'SUB': 0x03,
    'DIV': 0x04,
    'SDIV': 0x05,
    'MOD': 0x06,
    'SMOD': 0x07,
    'ADDMOD': 0x08,
    'MULMOD': 0x09,
    'EXP': 0x0A,
    'SIGNEXTEND': 0x0B,
}


def _build_arithmetic_runtime(opcode: str, args: tuple[int, ...]) -> str:
    code = bytearray()
    for arg in reversed(args):
        code += _push_int(arg)
    code.append(OPCODES[opcode])
    code += _push_int(0)
    code.append(0x55)  # SSTORE
    code.append(0x00)  # STOP
    return "0x" + code.hex()


def render_arithmetic_case(template: ArithmeticMappingTemplate) -> dict[str, Any]:
    expected_val = _simulate_math(template.opcode, template.args)
    expected = {"storage": {"0x00": _word_hex(expected_val)}}
    runtime_code = _build_arithmetic_runtime(template.opcode, template.args)
    
    observe = {
        "storage_address": "$last_contract",
        "arithmetic_probe": {
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
    case["family"] = "state/arithmetic"
    case["observe"] = observe
    return case
