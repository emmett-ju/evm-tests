from __future__ import annotations

import ast
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
class ComparisonMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: str
    opcode: str
    args: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class AutoComparisonInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str
    opcode: str | None = None
    args: tuple[int, ...] | None = None


def generate_upstream_comparison_templates(
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
        else repo_root_path / "third_party" / "execution-specs" / "tests" / "benchmark" / "compute" / "instruction" / "test_comparison.py"
    )
    templates, inventory = scan_comparison_cases(source)
    payload = {
        "name": "upstream-comparison-mapping-templates",
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
            family="comparison",
            name="upstream-comparison-auto-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload


def generate_upstream_comparison_manifest(
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
        else repo_root_path / "suites" / "templates" / "upstream_comparison_templates.json"
    )
    data = json.loads(template_file.read_text())
    templates = [
        ComparisonMappingTemplate(
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
        repo_root_path / "suites" / "manifests" / "upstream_comparison_mapped.json",
        "submodule-pending",
    )
    manifest = {
        "name": "upstream-comparison-mapped",
        "version": "1",
        "execution_specs_ref": execution_specs_ref,
        "suite_version": suite_version,
        "chain_profile_version": chain_profile_version,
        "cases": [render_comparison_case(template) for template in templates],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def scan_comparison_cases(
    source_path: str | Path,
) -> tuple[tuple[ComparisonMappingTemplate, ...], tuple[AutoComparisonInventoryEntry, ...]]:
    source = Path(source_path)
    text = source.read_text()
    inventory = sorted(
        _scan_test_comparison_cases(text) + _scan_test_iszero_cases(text),
        key=lambda item: item.upstream_ref,
    )
    templates = tuple(_comparison_inventory_entry_to_template(entry) for entry in inventory if entry.admitted)
    return templates, tuple(inventory)


def _scan_test_comparison_cases(text: str) -> list[AutoComparisonInventoryEntry]:
    parsed_entries = _parse_test_comparison_param_entries(text)
    if len(parsed_entries) != 5:
        raise ValueError(f"expected 5 comparison benchmark cases, found {len(parsed_entries)}")

    entries: list[AutoComparisonInventoryEntry] = []
    for opcode, args in parsed_entries:
        upstream_ref = (
            "tests/benchmark/compute/instruction/test_comparison.py::"
            f"test_comparison[opcode={opcode}]"
        )
        case_id = f"upstream.benchmark.comparison.test_comparison.{opcode.lower()}"
        entries.append(
            AutoComparisonInventoryEntry(
                upstream_ref=upstream_ref,
                case_id=case_id,
                admitted=True,
                mode="test_comparison",
                reasons=[],
                source="test_comparison",
                opcode=opcode,
                args=args,
            )
        )
    return entries


def _scan_test_iszero_cases(text: str) -> list[AutoComparisonInventoryEntry]:
    entries: list[AutoComparisonInventoryEntry] = []
    if "def test_iszero(" in text:
        entries.append(
            AutoComparisonInventoryEntry(
                upstream_ref="tests/benchmark/compute/instruction/test_comparison.py::test_iszero",
                case_id="upstream.benchmark.comparison.test_iszero.iszero",
                admitted=True,
                mode="test_iszero",
                reasons=[],
                source="test_iszero",
                opcode="ISZERO",
                args=(0,),
            )
        )
    if len(entries) != 1:
        raise ValueError(f"expected 1 iszero benchmark case, found {len(entries)}")
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


def _parse_test_comparison_param_entries(text: str) -> list[tuple[str, tuple[int, int]]]:
    module = ast.parse(text)
    function = next(
        (
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef) and node.name == "test_comparison"
        ),
        None,
    )
    if function is None:
        raise ValueError("could not find benchmark function test_comparison")

    param_decorator = next(
        (
            decorator
            for decorator in function.decorator_list
            if isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr == "parametrize"
            and decorator.args
            and isinstance(decorator.args[0], ast.Constant)
            and decorator.args[0].value == "opcode,opcode_args"
        ),
        None,
    )
    if param_decorator is None:
        raise ValueError("could not find parameter block for test_comparison")
    if len(param_decorator.args) < 2:
        raise ValueError("parameter block for test_comparison is missing benchmark entries")

    entries_node = param_decorator.args[1]
    if not isinstance(entries_node, (ast.List, ast.Tuple)):
        raise ValueError("parameter block for test_comparison must be a list or tuple literal")

    entries: list[tuple[str, tuple[int, int]]] = []
    for index, entry_node in enumerate(entries_node.elts):
        if not isinstance(entry_node, ast.Tuple) or len(entry_node.elts) != 2:
            raise ValueError(f"parameter block for test_comparison entry {index} must be a 2-tuple")
        opcode_node, args_node = entry_node.elts
        opcode = _parse_comparison_opcode(opcode_node, index=index)
        args = _parse_comparison_args(args_node, index=index)
        entries.append((opcode, args))
    return entries


def _parse_comparison_opcode(node: ast.AST, *, index: int) -> str:
    if not isinstance(node, ast.Attribute) or not isinstance(node.value, ast.Name) or node.value.id != "Op":
        raise ValueError(f"parameter block for test_comparison entry {index} has malformed opcode")
    if not re.fullmatch(r"[A-Z0-9_]+", node.attr):
        raise ValueError(f"parameter block for test_comparison entry {index} has malformed opcode name")
    return node.attr


def _parse_comparison_args(node: ast.AST, *, index: int) -> tuple[int, int]:
    if not isinstance(node, ast.Tuple) or len(node.elts) != 2:
        raise ValueError(f"parameter block for test_comparison entry {index} must define exactly two opcode_args")
    try:
        values = tuple(_literal_int(element) for element in node.elts)
    except ValueError as exc:
        raise ValueError(f"parameter block for test_comparison entry {index} has malformed opcode_args") from exc
    return values  # type: ignore[return-value]


def _literal_int(node: ast.AST) -> int:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -_literal_int(node.operand)
    if isinstance(node, ast.BinOp):
        left = _literal_int(node.left)
        right = _literal_int(node.right)
        if isinstance(node.op, ast.LShift):
            return left << right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Mult):
            return left * right
    raise ValueError("unsupported integer literal expression")


def _comparison_inventory_entry_to_template(entry: AutoComparisonInventoryEntry) -> ComparisonMappingTemplate:
    return ComparisonMappingTemplate(
        case_id=entry.case_id,
        description=f"Mapped from execution-specs {entry.opcode} onto an RPC-only deploy/call/storage-assert flow.",
        namespace_seed=f"upstream-comparison-{entry.opcode.lower()}",
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


def _simulate_comparison(opcode: str, args: tuple[int, ...]) -> int:
    if opcode == 'LT':
        return 1 if args[0] < args[1] else 0
    elif opcode == 'GT':
        return 1 if args[0] > args[1] else 0
    elif opcode == 'SLT':
        def to_signed(v: int) -> int:
            return v if v < (1<<255) else v - (1<<256)
        return 1 if to_signed(args[0]) < to_signed(args[1]) else 0
    elif opcode == 'SGT':
        def to_signed(v: int) -> int:
            return v if v < (1<<255) else v - (1<<256)
        return 1 if to_signed(args[0]) > to_signed(args[1]) else 0
    elif opcode == 'EQ':
        return 1 if args[0] == args[1] else 0
    elif opcode == 'ISZERO':
        return 1 if args[0] == 0 else 0
    raise ValueError(f"unsupported comparison opcode: {opcode}")


OPCODES: dict[str, int] = {
    'LT': 0x10,
    'GT': 0x11,
    'SLT': 0x12,
    'SGT': 0x13,
    'EQ': 0x14,
    'ISZERO': 0x15,
}


def _build_comparison_runtime(opcode: str, args: tuple[int, ...]) -> str:
    code = bytearray()
    for arg in reversed(args):
        code += _push_int(arg)
    code.append(OPCODES[opcode])
    code += _push_int(0)
    code.append(0x55)  # SSTORE
    code.append(0x00)  # STOP
    return "0x" + code.hex()


def render_comparison_case(template: ComparisonMappingTemplate) -> dict[str, Any]:
    expected_val = _simulate_comparison(template.opcode, template.args)
    expected = {"storage": {"0x00": _word_hex(expected_val)}}
    runtime_code = _build_comparison_runtime(template.opcode, template.args)
    
    observe = {
        "storage_address": "$last_contract",
        "comparison_probe": {
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
    case["family"] = "state/comparison"
    case["observe"] = observe
    return case
