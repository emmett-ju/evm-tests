from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal

from adapter.assembler import _push_int, _word_hex
from adapter.generator import build_case, deploy_contract_step, invoke_contract_step, wait_receipt_step
from adapter.inventory import write_inventory_payload
from adapter.manifest import resolve_execution_specs_ref
from adapter.signer import keccak256


BLOCKED_CODECOPY_REASON = "requires byte-range code-copy observation not yet mapped"
BLOCKED_EXTCODECOPY_REASON = (
    "requires external-account code-copy fixtures and byte-range observation not yet mapped"
)

ABSENT_TARGET_ADDRESS = "0x10000000000000000000000000000000000000a1"
PRESENT_TARGET_ADDRESS = "0x20000000000000000000000000000000000000b2"
PRESENT_TARGET_FUNDING_VALUE = "0x2a"
SELFBALANCE_RUNTIME = "0x4760005500"
CODESIZE_RUNTIME = "0x3860005500"
BALANCE_RUNTIME = "0x5f353160005500"
WORD_00 = "0x0000000000000000000000000000000000000000000000000000000000000000"
WORD_01 = "0x0000000000000000000000000000000000000000000000000000000000000001"
WORD_05 = "0x0000000000000000000000000000000000000000000000000000000000000005"
UPSTREAM_MAX_CODE_SIZE = 24_576

AccountQueryTemplateMode = Literal[
    "selfbalance_contract_balance_0",
    "selfbalance_contract_balance_1",
    "codesize",
    "balance_cold_absent_accounts",
    "balance_cold_present_accounts",
    "codecopy_fixed",
    "codecopy_dynamic",
]


@dataclass(frozen=True, slots=True)
class AccountQueryMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: AccountQueryTemplateMode
    copy_size: int | None = None


@dataclass(frozen=True, slots=True)
class AutoAccountQueryInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str
    copy_size: int | None = None


ACCOUNT_QUERY_MODE_SPECS: dict[AccountQueryTemplateMode, dict[str, str]] = {
    "selfbalance_contract_balance_0": {
        "description": "Admitted execution-specs SELFBALANCE benchmark variant with zero contract balance.",
        "namespace_seed": "upstream-account-query-selfbalance-balance-0",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark SELFBALANCE on the currently executing account with zero balance.",
                "Admitted because the executing contract balance is directly observable and can be asserted without block-environment control.",
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
            ]
        ),
    },
    "codecopy_dynamic": {
        "description": "Admitted execution-specs CODECOPY benchmark variant with dynamic memory offset.",
        "namespace_seed": "upstream-account-query-codecopy-dynamic",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark CODECOPY with offset=GAS % 7.",
                "Admitted because the dynamically evaluated memory offset is stored in the runtime prior to execution, allowing dynamic hash expectation derivation.",
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


def generate_upstream_account_query_manifest(
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
        else repo_root_path / "suites" / "templates" / "upstream_account_query_templates.json"
    )
    templates = load_account_query_templates(template_file)
    execution_specs_ref = resolve_execution_specs_ref(
        repo_root_path / "suites" / "manifests" / "upstream_account_query_mapped.json",
        "submodule-pending",
    )
    manifest = {
        "name": "upstream-account-query-mapped",
        "version": "1",
        "execution_specs_ref": execution_specs_ref,
        "suite_version": suite_version,
        "chain_profile_version": chain_profile_version,
        "cases": [render_account_query_case(template) for template in templates],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def load_account_query_templates(path: str | Path) -> tuple[AccountQueryMappingTemplate, ...]:
    template_path = Path(path)
    data = json.loads(template_path.read_text())
    entries = data.get("cases")
    if not isinstance(entries, list):
        raise ValueError("account query template payload must contain a list 'cases'")
    return tuple(_load_account_query_template_entry(entry, index=index) for index, entry in enumerate(entries))


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


def render_account_query_case(template: AccountQueryMappingTemplate) -> dict[str, Any]:
    if template.mode == "selfbalance_contract_balance_0":
        return build_account_query_case(
            template,
            steps=[
                deploy_account_query_contract_step(
                    runtime_code=SELFBALANCE_RUNTIME,
                    value="0x0",
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex="0x"),
                wait_receipt_step(),
            ],
            expected={"storage": {"0x00": WORD_00}},
        )
    if template.mode == "selfbalance_contract_balance_1":
        return build_account_query_case(
            template,
            steps=[
                deploy_account_query_contract_step(
                    runtime_code=SELFBALANCE_RUNTIME,
                    value="0x1",
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex="0x"),
                wait_receipt_step(),
            ],
            expected={"storage": {"0x00": WORD_01}},
        )
    if template.mode == "codesize":
        return build_account_query_case(
            template,
            steps=[
                deploy_account_query_contract_step(
                    runtime_code=CODESIZE_RUNTIME,
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex="0x"),
                wait_receipt_step(),
            ],
            expected={"storage": {"0x00": WORD_05}},
        )
    if template.mode == "balance_cold_absent_accounts":
        return build_account_query_case(
            template,
            steps=[
                deploy_account_query_contract_step(
                    runtime_code=BALANCE_RUNTIME,
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex=_address_to_word(ABSENT_TARGET_ADDRESS)),
                wait_receipt_step(),
            ],
            expected={"storage": {"0x00": WORD_00}},
        )
    if template.mode == "balance_cold_present_accounts":
        return build_account_query_case(
            template,
            steps=[
                {
                    "action": "transfer_native",
                    "to": PRESENT_TARGET_ADDRESS,
                    "value": PRESENT_TARGET_FUNDING_VALUE,
                    "gas": "0x5208",
                    "capture_balance_before": "$present_target_balance_before",
                },
                wait_receipt_step(),
                deploy_account_query_contract_step(
                    runtime_code=BALANCE_RUNTIME,
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex=_address_to_word(PRESENT_TARGET_ADDRESS)),
                wait_receipt_step(),
            ],
            expected={"storage": {"0x00": "$present_target_balance_after_word"}},
        )
    if template.mode == "codecopy_fixed":
        copy_size = _require_template_copy_size(template)
        runtime_code = _build_codecopy_fixed_runtime(copy_size)
        return build_account_query_case(
            template,
            steps=[
                deploy_account_query_contract_step(runtime_code=runtime_code),
                wait_receipt_step(),
                invoke_contract_step(data_hex="0x", gas=_codecopy_invoke_gas(copy_size)),
                wait_receipt_step(),
            ],
            expected={
                "storage": {
                    "0x00": _word_hex(copy_size),
                    "0x01": _codecopy_fixed_digest(runtime_code, copy_size),
                }
            },
            observe_extra={"account_query_probe": {"mode": "codecopy_fixed", "copy_size": copy_size}},
        )
    if template.mode == "codecopy_dynamic":
        copy_size = _require_template_copy_size(template)
        runtime_code = _build_codecopy_dynamic_runtime(copy_size)
        return build_account_query_case(
            template,
            steps=[
                deploy_account_query_contract_step(runtime_code=runtime_code),
                wait_receipt_step(),
                invoke_contract_step(data_hex="0x", gas=_codecopy_invoke_gas(copy_size)),
                wait_receipt_step(),
            ],
            expected={
                "storage": {
                    "0x00": _word_hex(copy_size),
                    "0x01": _codecopy_dynamic_digest(runtime_code, 0, copy_size),
                }
            },
            observe_extra={
                "account_query_probe": {
                    "mode": "codecopy",
                    "copy_size": copy_size,
                    "dynamic_offset_slot": "0x02",
                }
            },
        )
    raise ValueError(f"unsupported account-query mapping mode: {template.mode}")


def build_account_query_case(
    template: AccountQueryMappingTemplate,
    *,
    steps: list[dict[str, Any]],
    expected: dict[str, Any],
    observe_extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    observe = {"storage_address": "$last_contract", "code_address": "$last_contract"}
    if observe_extra:
        observe.update(observe_extra)
    return {
        "kind": "upstream_mapped",
        "case_id": template.case_id,
        "family": "state/account-query",
        "description": template.description,
        "namespace_seed": template.namespace_seed,
        "upstream_ref": template.upstream_ref,
        "notes": template.notes,
        "observe": observe,
        "filters": {},
        "steps": steps,
        "expected": expected,
    }


def deploy_account_query_contract_step(
    *,
    runtime_code: str,
    value: str = "0x0",
    gas: str = "0x186a0",
) -> dict[str, Any]:
    return {
        "action": "deploy_contract",
        "bytecode_init": _build_init_code(runtime_code),
        "bytecode_runtime": runtime_code,
        "value": value,
        "gas": gas,
    }


def _load_account_query_template_entry(entry: object, *, index: int) -> AccountQueryMappingTemplate:
    if not isinstance(entry, dict):
        raise ValueError(f"account query template entry {index} must be an object")
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
            raise ValueError(f"account query template entry {index} missing required field: {field}")
    mode = entry["mode"]
    if mode not in ACCOUNT_QUERY_MODE_SPECS and mode != "codecopy_fixed":
        raise ValueError(f"unsupported account query template mode: {mode}")
    notes = entry["notes"]
    if not isinstance(notes, list) or not all(isinstance(note, str) for note in notes):
        raise ValueError(f"account query template entry {index} field 'notes' must be a list of strings")
    copy_size = entry.get("copy_size")
    if mode in ("codecopy_fixed", "codecopy_dynamic"):
        if not isinstance(copy_size, int) or isinstance(copy_size, bool) or copy_size < 0:
            raise ValueError(f"account query template entry {index} field 'copy_size' must be a non-negative integer")
    elif copy_size is not None:
        raise ValueError(f"account query template entry {index} field 'copy_size' is only supported for codecopy families")
    return AccountQueryMappingTemplate(
        case_id=str(entry["case_id"]),
        description=str(entry["description"]),
        namespace_seed=str(entry["namespace_seed"]),
        upstream_ref=str(entry["upstream_ref"]),
        notes=list(notes),
        mode=mode,
        copy_size=copy_size,
    )


def _scan_selfbalance_cases(text: str) -> list[AutoAccountQueryInventoryEntry]:
    block = _extract_decorator_region(text, function_name="test_selfbalance")
    values = [
        _parse_int_literal(value)
        for value in _extract_param_values_from_block(block, "contract_balance", function_name="test_selfbalance")
    ]
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
        for _ratio_value, ratio_label in ratio_entries:
            ratio_slug = _slugify_label(ratio_label)
            fixed_slug = "fixed" if fixed_src_dst else "dynamic"
            admitted = True
            mode = "codecopy_fixed" if fixed_src_dst else "codecopy_dynamic"
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
                    admitted=admitted,
                    mode=mode,
                    reasons=[],
                    source="codecopy",
                    copy_size=_codecopy_size_for_ratio(_ratio_value),
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
                    admitted=True,
                    mode="codecopy_dynamic",
                    reasons=[],
                    source="codecopy_benchmark",
                    copy_size=code_size,
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
    if entry.mode == "codecopy_fixed":
        copy_size = _require_copy_size(entry)
        return AccountQueryMappingTemplate(
            case_id=entry.case_id,
            description=f"Admitted execution-specs CODECOPY fixed source/destination benchmark variant copying {copy_size} byte(s).",
            namespace_seed=_build_namespace_seed(entry.case_id),
            upstream_ref=entry.upstream_ref,
            notes=[
                f"Upstream intent: benchmark CODECOPY with fixed source and destination offsets while copying {copy_size} byte(s).",
                "RPC mapping: deploy a deterministic runtime that executes CODECOPY(0, 0, size), stores the copied byte count in slot0, and stores KECCAK256 of the copied memory window in slot1.",
                "Admitted because fixed source/destination removes the gas-derived byte-window branch and the copied byte count plus digest are deterministic final storage observables.",
            ],
            mode="codecopy_fixed",
            copy_size=copy_size,
        )
    if entry.mode == "codecopy_dynamic":
        copy_size = _require_copy_size(entry)
        return AccountQueryMappingTemplate(
            case_id=entry.case_id,
            description=f"Admitted execution-specs CODECOPY dynamic-offset benchmark variant copying {copy_size} byte(s).",
            namespace_seed=_build_namespace_seed(entry.case_id),
            upstream_ref=entry.upstream_ref,
            notes=[
                f"Upstream intent: benchmark CODECOPY with gas-derived dynamic memory offsets while copying {copy_size} byte(s).",
                "RPC mapping: deploy a runtime that stores the evaluated dynamic offset in slot0x02, executes CODECOPY(offset, offset, size), and stores the result count and hash.",
                "Admitted because the dynamically evaluated memory offset is stored in the runtime prior to execution, allowing dynamic hash expectation derivation.",
            ],
            mode="codecopy_dynamic",
            copy_size=copy_size,
        )
    spec = ACCOUNT_QUERY_MODE_SPECS[entry.mode]
    return AccountQueryMappingTemplate(
        case_id=entry.case_id,
        description=spec["description"],
        namespace_seed=spec["namespace_seed"],
        upstream_ref=entry.upstream_ref,
        notes=json.loads(spec["notes"]),
        mode=entry.mode,
    )


def _codecopy_size_for_ratio(ratio_literal: str) -> int:
    ratio = Decimal(ratio_literal.replace("_", "").strip())
    size = int(Decimal(UPSTREAM_MAX_CODE_SIZE) * ratio)
    if size < 0 or size > UPSTREAM_MAX_CODE_SIZE:
        raise ValueError(f"unsupported CODECOPY max_code_size_ratio: {ratio_literal}")
    return size


def _build_namespace_seed(case_id: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", case_id.removeprefix("upstream.benchmark.account_query.").lower()).strip("-")
    return f"upstream-account-query-{slug}"


def _require_copy_size(entry: AutoAccountQueryInventoryEntry) -> int:
    if entry.copy_size is None:
        raise ValueError(f"missing account-query CODECOPY copy_size for {entry.case_id}")
    return entry.copy_size


def _require_template_copy_size(template: AccountQueryMappingTemplate) -> int:
    if template.copy_size is None:
        raise ValueError(f"missing account-query CODECOPY copy_size for {template.case_id}")
    return template.copy_size


def _build_codecopy_fixed_runtime(copy_size: int) -> str:
    if copy_size < 0 or copy_size > UPSTREAM_MAX_CODE_SIZE:
        raise ValueError(f"unsupported CODECOPY copy_size: {copy_size}")
    code = bytearray()
    code += _push_int(copy_size)
    code += _push_int(0)
    code += _push_int(0)
    code.append(0x39)  # CODECOPY(0, 0, copy_size)
    code += _push_int(copy_size)
    code += _push_int(0)
    code.append(0x20)  # KECCAK256(memory[0:copy_size])
    code.append(0x80)  # duplicate digest for storage
    code += _push_int(1)
    code.append(0x55)  # slot1 <- digest
    code.append(0x50)  # discard duplicate digest
    code += _push_int(copy_size)
    code += _push_int(0)
    code.append(0x55)  # slot0 <- copied byte count
    code.append(0x00)
    return "0x" + code.hex()


def _codecopy_fixed_digest(runtime_code: str, copy_size: int) -> str:
    runtime = bytes.fromhex(runtime_code.removeprefix("0x"))
    copied = runtime[:copy_size] + (b"\x00" * max(0, copy_size - len(runtime)))
    return "0x" + keccak256(copied).hex()


def _codecopy_dynamic_digest(runtime_code: str, offset: int, copy_size: int) -> str:
    runtime = bytes.fromhex(runtime_code.removeprefix("0x"))
    if offset >= len(runtime):
        copied = b"\x00" * copy_size
    else:
        available = runtime[offset:]
        copied = available[:copy_size] + (b"\x00" * max(0, copy_size - len(available)))
    return "0x" + keccak256(copied).hex()


def derive_codecopy_expectation(probe: dict[str, Any], runtime_code: str, dynamic_offset: int | None = None) -> dict[str, str]:
    copy_size = probe["copy_size"]
    offset = dynamic_offset if dynamic_offset is not None else 0
    slot0 = _word_hex(copy_size)
    slot1 = _codecopy_dynamic_digest(runtime_code, offset, copy_size)
    return {"0x00": slot0, "0x01": slot1}


def _build_codecopy_dynamic_runtime(copy_size: int) -> str:
    if copy_size < 0 or copy_size > UPSTREAM_MAX_CODE_SIZE:
        raise ValueError(f"unsupported CODECOPY copy_size: {copy_size}")
    code = bytearray()
    code += _push_int(copy_size)
    code.append(0x5A)  # GAS
    code += _push_int(7)
    code.append(0x06)  # MOD (offset)
    code.append(0x80)  # DUP1 (keep offset for SSTORE)
    code += _push_int(2)
    code.append(0x55)  # slot2 <- offset
    code.append(0x80)  # DUP1 (restore offset for CODECOPY)
    code.append(0x39)  # CODECOPY(offset, offset, copy_size)

    code += _push_int(copy_size)
    code += _push_int(2)
    code.append(0x54)  # SLOAD slot2 -> offset
    code.append(0x20)  # KECCAK256(memory[offset:offset+copy_size])
    code.append(0x80)  # duplicate digest for storage
    code += _push_int(1)
    code.append(0x55)  # slot1 <- digest
    code.append(0x50)  # discard duplicate digest
    code += _push_int(copy_size)
    code += _push_int(0)
    code.append(0x55)  # slot0 <- copy_size
    code.append(0x00)
    return "0x" + code.hex()


def _codecopy_invoke_gas(copy_size: int) -> str:
    if copy_size >= UPSTREAM_MAX_CODE_SIZE:
        return "0x400000"
    return "0x200000"


def _build_init_code(runtime_code: str) -> str:
    from adapter.assembler import _build_init_code as _shared_build_init_code
    return _shared_build_init_code(runtime_code)


def _address_to_word(address: str) -> str:
    if not address.startswith("0x") or len(address) != 42:
        raise ValueError(f"unsupported address literal: {address}")
    return "0x" + address[2:].lower().rjust(64, "0")


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
