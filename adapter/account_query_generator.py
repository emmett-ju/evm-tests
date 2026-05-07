from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from adapter.inventory import write_inventory_payload


BLOCKED_CODECOPY_REASON = "requires byte-range code-copy observation not yet mapped"
BLOCKED_EXTCODECOPY_REASON = (
    "requires external-account code-copy fixtures and byte-range observation not yet mapped"
)

AccountQueryTemplateMode = Literal[
    "selfbalance_contract_balance_0",
    "selfbalance_contract_balance_1",
    "codesize",
    "balance_cold_absent_accounts",
    "balance_cold_present_accounts",
]


@dataclass(frozen=True, slots=True)
class AccountQueryMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: AccountQueryTemplateMode


@dataclass(frozen=True, slots=True)
class AutoAccountQueryInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str


ACCOUNT_QUERY_MODE_SPECS: dict[AccountQueryTemplateMode, dict[str, str]] = {
    "selfbalance_contract_balance_0": {
        "description": "Admitted execution-specs SELFBALANCE benchmark variant with zero contract balance.",
        "namespace_seed": "upstream-account-query-selfbalance-balance-0",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark SELFBALANCE on the currently executing account with zero balance.",
                "Admitted because the executing contract balance is directly observable and can be asserted without block-environment control.",
                "This template is scan-stage inventory for later runtime wiring; CODECOPY and EXTCODE* neighbors stay blocked until their observation model is implemented.",
            ]
        ),
    },
    "selfbalance_contract_balance_1": {
        "description": "Admitted execution-specs SELFBALANCE benchmark variant with non-zero contract balance.",
        "namespace_seed": "upstream-account-query-selfbalance-balance-1",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark SELFBALANCE on the currently executing account with a funded balance.",
                "Admitted because the executing contract balance is directly observable and can be asserted without block-environment control.",
                "This template is scan-stage inventory for later runtime wiring; CODECOPY and EXTCODE* neighbors stay blocked until their observation model is implemented.",
            ]
        ),
    },
    "codesize": {
        "description": "Admitted execution-specs CODESIZE benchmark variant.",
        "namespace_seed": "upstream-account-query-codesize",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark CODESIZE on the currently executing account.",
                "Admitted because deployed runtime bytecode size is directly observable from the deployed contract code.",
                "This template is scan-stage inventory for later runtime wiring; CODECOPY and EXTCODE* neighbors stay blocked until their observation model is implemented.",
            ]
        ),
    },
    "balance_cold_absent_accounts": {
        "description": "Admitted execution-specs BALANCE cold-account benchmark variant against absent target accounts.",
        "namespace_seed": "upstream-account-query-balance-cold-absent-accounts",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark BALANCE over cold absent target accounts.",
                "Admitted because target-account balance outcomes can be observed directly without copying account code or controlling block internals.",
                "This template is scan-stage inventory for later runtime wiring; CODECOPY and EXTCODE* neighbors stay blocked until their observation model is implemented.",
            ]
        ),
    },
    "balance_cold_present_accounts": {
        "description": "Admitted execution-specs BALANCE cold-account benchmark variant against present target accounts.",
        "namespace_seed": "upstream-account-query-balance-cold-present-accounts",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark BALANCE over cold present target accounts.",
                "Admitted because target-account balance outcomes can be observed directly without copying account code or controlling block internals.",
                "This template is scan-stage inventory for later runtime wiring; CODECOPY and EXTCODE* neighbors stay blocked until their observation model is implemented.",
            ]
        ),
    },
}


def generate_upstream_account_query_templates(
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
        / "test_account_query.py"
    )
    templates, inventory = scan_account_query_cases(source)
    payload = {
        "name": "upstream-account-query-mapping-templates",
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
            family="account-query",
            name="upstream-account-query-auto-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload


def load_account_query_templates(path: str | Path) -> tuple[AccountQueryMappingTemplate, ...]:
    template_path = Path(path)
    data = json.loads(template_path.read_text())
    return tuple(
        AccountQueryMappingTemplate(
            case_id=entry["case_id"],
            description=entry["description"],
            namespace_seed=entry["namespace_seed"],
            upstream_ref=entry["upstream_ref"],
            notes=list(entry["notes"]),
            mode=entry["mode"],
        )
        for entry in data["cases"]
    )


def scan_account_query_cases(
    source_path: str | Path,
) -> tuple[tuple[AccountQueryMappingTemplate, ...], tuple[AutoAccountQueryInventoryEntry, ...]]:
    source = Path(source_path)
    text = source.read_text()
    inventory = sorted(
        _scan_selfbalance_cases(text)
        + _scan_codesize_cases(text)
        + _scan_codecopy_cases(text)
        + _scan_codecopy_benchmark_cases(text)
        + _scan_extcodecopy_warm_cases(text)
        + _scan_balance_cold_cases(text),
        key=lambda item: item.upstream_ref,
    )
    templates = tuple(
        _inventory_entry_to_template(entry)
        for entry in inventory
        if entry.admitted and entry.mode is not None
    )
    return templates, tuple(inventory)


def _scan_selfbalance_cases(text: str) -> list[AutoAccountQueryInventoryEntry]:
    block = _extract_decorator_region(text, function_name="test_selfbalance")
    values = [_parse_int_literal(value) for value in _extract_param_values_from_block(block, "contract_balance", function_name="test_selfbalance")]
    results: list[AutoAccountQueryInventoryEntry] = []
    for contract_balance in values:
        mode, namespace = _resolve_selfbalance_mode(contract_balance)
        results.append(
            AutoAccountQueryInventoryEntry(
                upstream_ref=(
                    "tests/benchmark/compute/instruction/test_account_query.py::"
                    f"test_selfbalance[contract_balance={contract_balance}]"
                ),
                case_id=(
                    "upstream.benchmark.account_query.selfbalance."
                    f"contract_balance_{contract_balance}.success"
                ),
                admitted=True,
                mode=mode,
                reasons=[],
                source=namespace,
            )
        )
    if len(results) != 2:
        raise ValueError(f"expected 2 selfbalance benchmark cases, found {len(results)}")
    return results


def _scan_codesize_cases(text: str) -> list[AutoAccountQueryInventoryEntry]:
    _require_function(text, "test_codesize")
    return [
        AutoAccountQueryInventoryEntry(
            upstream_ref="tests/benchmark/compute/instruction/test_account_query.py::test_codesize",
            case_id="upstream.benchmark.account_query.codesize.success",
            admitted=True,
            mode="codesize",
            reasons=[],
            source="codesize",
        )
    ]


def _scan_codecopy_cases(text: str) -> list[AutoAccountQueryInventoryEntry]:
    block = _extract_decorator_region(text, function_name="test_codecopy")
    ratio_entries = _extract_pytest_param_entries_from_block(
        block,
        "max_code_size_ratio",
        function_name="test_codecopy",
    )
    fixed_src_dst_values = [
        _parse_bool_literal(value)
        for value in _extract_param_values_from_block(block, "fixed_src_dst", function_name="test_codecopy")
    ]
    results: list[AutoAccountQueryInventoryEntry] = []
    for fixed_src_dst in fixed_src_dst_values:
        for ratio_value, ratio_label in ratio_entries:
            ratio_slug = _slugify_label(ratio_label)
            fixed_slug = "fixed" if fixed_src_dst else "dynamic"
            results.append(
                AutoAccountQueryInventoryEntry(
                    upstream_ref=(
                        "tests/benchmark/compute/instruction/test_account_query.py::"
                        f"test_codecopy[fixed_src_dst={fixed_src_dst}-max_code_size_ratio={ratio_label}]"
                    ),
                    case_id=(
                        "upstream.benchmark.account_query.codecopy."
                        f"{fixed_slug}.max_code_size_ratio_{ratio_slug}.success"
                    ),
                    admitted=False,
                    mode=None,
                    reasons=[BLOCKED_CODECOPY_REASON],
                    source="codecopy",
                )
            )
    if len(results) != 10:
        raise ValueError(f"expected 10 codecopy benchmark cases, found {len(results)}")
    return results


def _scan_codecopy_benchmark_cases(text: str) -> list[AutoAccountQueryInventoryEntry]:
    block = _extract_decorator_region(text, function_name="test_codecopy_benchmark")
    mem_sizes = [
        _parse_int_literal(value)
        for value in _extract_param_values_from_block(block, "mem_size", function_name="test_codecopy_benchmark")
    ]
    code_sizes = [
        _parse_int_literal(value)
        for value in _extract_param_values_from_block(block, "code_size", function_name="test_codecopy_benchmark")
    ]
    results: list[AutoAccountQueryInventoryEntry] = []
    for mem_size in mem_sizes:
        for code_size in code_sizes:
            results.append(
                AutoAccountQueryInventoryEntry(
                    upstream_ref=(
                        "tests/benchmark/compute/instruction/test_account_query.py::"
                        f"test_codecopy_benchmark[code_size={code_size}-mem_size={mem_size}]"
                    ),
                    case_id=(
                        "upstream.benchmark.account_query.codecopy_benchmark."
                        f"mem_size_{mem_size}.code_size_{code_size}.success"
                    ),
                    admitted=False,
                    mode=None,
                    reasons=[BLOCKED_CODECOPY_REASON],
                    source="codecopy_benchmark",
                )
            )
    if len(results) != 20:
        raise ValueError(f"expected 20 codecopy benchmark cases, found {len(results)}")
    return results


def _scan_extcodecopy_warm_cases(text: str) -> list[AutoAccountQueryInventoryEntry]:
    block = _extract_decorator_region(text, function_name="test_extcodecopy_warm")
    copy_sizes = [
        _parse_int_literal(value)
        for value in _extract_param_values_from_block(block, "copy_size", function_name="test_extcodecopy_warm")
    ]
    results = [
        AutoAccountQueryInventoryEntry(
            upstream_ref=(
                "tests/benchmark/compute/instruction/test_account_query.py::"
                f"test_extcodecopy_warm[copy_size={copy_size}]"
            ),
            case_id=f"upstream.benchmark.account_query.extcodecopy.warm.copy_size_{copy_size}.success",
            admitted=False,
            mode=None,
            reasons=[BLOCKED_EXTCODECOPY_REASON],
            source="extcodecopy_warm",
        )
        for copy_size in copy_sizes
    ]
    if len(results) != 5:
        raise ValueError(f"expected 5 extcodecopy benchmark cases, found {len(results)}")
    return results


def _scan_balance_cold_cases(text: str) -> list[AutoAccountQueryInventoryEntry]:
    block = _extract_decorator_region(text, function_name="test_ext_account_query_cold")
    opcodes = [
        value.split(".")[-1]
        for value in _extract_param_values_from_block(block, "opcode", function_name="test_ext_account_query_cold")
    ]
    absent_values = [
        _parse_bool_literal(value)
        for value in _extract_param_values_from_block(block, "absent_accounts", function_name="test_ext_account_query_cold")
    ]
    results: list[AutoAccountQueryInventoryEntry] = []
    for absent_accounts in absent_values:
        for opcode in opcodes:
            mode, case_suffix = _resolve_balance_mode(opcode, absent_accounts)
            results.append(
                AutoAccountQueryInventoryEntry(
                    upstream_ref=(
                        "tests/benchmark/compute/instruction/test_account_query.py::"
                        f"test_ext_account_query_cold[absent_accounts={absent_accounts}-opcode={opcode}]"
                    ),
                    case_id=f"upstream.benchmark.account_query.balance.cold.{case_suffix}.success",
                    admitted=True,
                    mode=mode,
                    reasons=[],
                    source="ext_account_query_cold",
                )
            )
    if len(results) != 2:
        raise ValueError(f"expected 2 balance benchmark cases, found {len(results)}")
    return results


def _resolve_selfbalance_mode(contract_balance: int) -> tuple[AccountQueryTemplateMode, str]:
    if contract_balance == 0:
        return "selfbalance_contract_balance_0", "selfbalance"
    if contract_balance == 1:
        return "selfbalance_contract_balance_1", "selfbalance"
    raise ValueError(f"unsupported selfbalance contract_balance={contract_balance}")


def _resolve_balance_mode(opcode: str, absent_accounts: bool) -> tuple[AccountQueryTemplateMode, str]:
    if opcode != "BALANCE":
        raise ValueError(f"unsupported cold account query opcode {opcode}")
    if absent_accounts:
        return "balance_cold_absent_accounts", "absent_accounts"
    return "balance_cold_present_accounts", "present_accounts"


def _inventory_entry_to_template(entry: AutoAccountQueryInventoryEntry) -> AccountQueryMappingTemplate:
    assert entry.mode is not None
    spec = ACCOUNT_QUERY_MODE_SPECS[entry.mode]
    return AccountQueryMappingTemplate(
        case_id=entry.case_id,
        description=spec["description"],
        namespace_seed=spec["namespace_seed"],
        upstream_ref=entry.upstream_ref,
        notes=json.loads(spec["notes"]),
        mode=entry.mode,
    )


def _require_function(text: str, function_name: str) -> None:
    if f"def {function_name}(" not in text:
        raise ValueError(f"could not find benchmark function {function_name}")


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


def _extract_pytest_param_entries_from_block(
    block: str,
    param_name: str,
    *,
    function_name: str,
) -> list[tuple[str, str]]:
    values_block = _extract_param_block(block, param_name)
    if values_block is None:
        raise ValueError(f"could not find parameter block for {function_name}")
    entries = [
        (match.group("value").strip(), match.group("label"))
        for match in re.finditer(
            r'pytest\.param\((?P<value>[^,]+),\s*id="(?P<label>[^"]+)"\)',
            values_block,
        )
    ]
    if not entries:
        raise ValueError(f"could not parse pytest.param entries for {function_name}")
    return entries


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


def _slugify_label(label: str) -> str:
    slug = label.lower().replace(".", "_")
    slug = re.sub(r"[^a-z0-9]+", "_", slug)
    return slug.strip("_")
