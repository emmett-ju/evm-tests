from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from adapter.inventory import write_inventory_payload
from adapter.manifest import resolve_execution_specs_ref


STORAGE_WRITE_CONTRACT_INIT = "0x6007600c60003960076000f360003560005500"
STORAGE_WRITE_CONTRACT_RUNTIME = "0x60003560005500"
STORAGE_WRITE_CONTRACT_INIT_REVERT = "0x600b600c600039600b6000f360003560005560006000fd"
STORAGE_WRITE_CONTRACT_RUNTIME_REVERT = "0x60003560005560006000fd"
STORAGE_READ_CONTRACT_INIT = "0x602a6000556007601160003960076000f360005460015500"
STORAGE_READ_CONTRACT_INIT_EMPTY = "0x6007600c60003960076000f360005460015500"
STORAGE_READ_CONTRACT_RUNTIME = "0x60005460015500"
STORAGE_WRITE_CONTRACT_INIT_PRESENT_ONE = "0x60016000556007601160003960076000f360003560005500"
STORAGE_WRITE_CONTRACT_INIT_PRESENT_ONE_REVERT = (
    "0x6001600055600b6011600039600b6000f360003560005560006000fd"
)
STORAGE_WARM_SAME_RUNTIME = "0x60005460005500"
STORAGE_WARM_NEW_RUNTIME = "0x602b60005500"
SLOT0_VALUE_00 = "0x0000000000000000000000000000000000000000000000000000000000000000"
SLOT0_VALUE_01 = "0x0000000000000000000000000000000000000000000000000000000000000001"
SLOT0_VALUE_2A = "0x000000000000000000000000000000000000000000000000000000000000002a"
SLOT0_VALUE_2B = "0x000000000000000000000000000000000000000000000000000000000000002b"
SLOT0_VALUE_FF = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
OOG_INVOKE_GAS = "0x55f0"

StorageTemplateMode = Literal[
    "read_absent",
    "read_present",
    "warm_read_present",
    "warm_write_new_present",
    "warm_write_same_present",
    "write_new_value_absent_oog",
    "write_new_value_absent_revert",
    "write_new_value_absent",
    "write_new_value_present_oog",
    "write_new_value_present_revert",
    "write_new_value_present",
    "write_same_value_absent_oog",
    "write_same_value_absent_revert",
    "write_same_value_absent",
    "write_same_value_present_oog",
    "write_same_value_present_revert",
    "write_same_value_present",
]


@dataclass(frozen=True, slots=True)
class StorageMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: StorageTemplateMode


@dataclass(frozen=True, slots=True)
class AutoTemplateInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str


STORAGE_MODE_SPECS: dict[StorageTemplateMode, dict[str, str]] = {
    "write_new_value_absent": {
        "description": "Mapped from execution-specs SSTORE new value success path onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-storage-write-new-value-absent-success",
        "notes": json.dumps(
            [
                "Upstream intent: cold SSTORE to an absent slot, writing a new non-zero value with successful completion.",
                "RPC mapping: deploy a minimal storage contract, invoke it once with calldata 0x2a, then assert slot0 on-chain.",
                "Admitted because the truth source is final storage state; excluded upstream gas-benchmark accounting is intentionally not reproduced.",
            ]
        ),
    },
    "write_new_value_absent_revert": {
        "description": "Mapped from execution-specs SSTORE new value revert path onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-storage-write-new-value-absent-revert",
        "notes": json.dumps(
            [
                "Upstream intent: cold SSTORE to an absent slot, writing a new non-zero value before the transaction reverts.",
                "RPC mapping: deploy a minimal storage contract whose runtime writes slot0 then REVERTs, invoke it once with calldata 0x2a, then assert receipt failure and unchanged storage.",
                "Admitted because final receipt status and rolled-back storage are directly observable over RPC without reproducing upstream gas benchmarking internals.",
            ]
        ),
    },
    "write_new_value_absent_oog": {
        "description": "Mapped from execution-specs SSTORE new value out-of-gas path onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-storage-write-new-value-absent-oog",
        "notes": json.dumps(
            [
                "Upstream intent: cold SSTORE to an absent slot, writing a new non-zero value before the transaction runs out of gas.",
                "RPC mapping: deploy a minimal storage contract, invoke it once with low gas so execution fails during storage write, then assert receipt failure and unchanged storage.",
                "Admitted because final receipt status and rolled-back storage are directly observable over RPC without reproducing upstream gas benchmarking internals.",
            ]
        ),
    },
    "write_same_value_absent": {
        "description": "Mapped from execution-specs SSTORE same value cold path on an absent slot onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-storage-write-same-value-absent-success",
        "notes": json.dumps(
            [
                "Upstream intent: cold SSTORE to an absent slot, using the same benchmark write shape with successful completion.",
                "RPC mapping: deploy a minimal storage contract, invoke it once with calldata 0x01, then assert slot0 on-chain.",
                "Admitted because the truth source is final storage state; excluded upstream gas-benchmark accounting is intentionally not reproduced.",
            ]
        ),
    },
    "write_same_value_absent_revert": {
        "description": "Mapped from execution-specs SSTORE same value revert path on an absent slot onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-storage-write-same-value-absent-revert",
        "notes": json.dumps(
            [
                "Upstream intent: cold SSTORE to an absent slot, using the benchmark write shape before the transaction reverts.",
                "RPC mapping: deploy a minimal storage contract whose runtime writes slot0 then REVERTs, invoke it once with calldata 0x01, then assert receipt failure and unchanged storage.",
                "Admitted because final receipt status and rolled-back storage are directly observable over RPC without reproducing upstream gas benchmarking internals.",
            ]
        ),
    },
    "write_same_value_absent_oog": {
        "description": "Mapped from execution-specs SSTORE same value out-of-gas path on an absent slot onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-storage-write-same-value-absent-oog",
        "notes": json.dumps(
            [
                "Upstream intent: cold SSTORE to an absent slot, using the benchmark write shape before the transaction runs out of gas.",
                "RPC mapping: deploy a minimal storage contract, invoke it once with low gas so execution fails during storage write, then assert receipt failure and unchanged storage.",
                "Admitted because final receipt status and rolled-back storage are directly observable over RPC without reproducing upstream gas benchmarking internals.",
            ]
        ),
    },
    "write_same_value_present": {
        "description": "Mapped from execution-specs SSTORE same value success path onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-storage-write-same-value-present-success",
        "notes": json.dumps(
            [
                "Upstream intent: cold SSTORE to a present slot, writing back the same value with successful completion.",
                "RPC mapping: deploy a minimal storage contract, write 0x2a once to establish present storage, then write 0x2a again and assert slot0 remains unchanged.",
                "Admitted because the truth source is final storage state; excluded upstream gas-benchmark accounting is intentionally not reproduced.",
            ]
        ),
    },
    "write_same_value_present_revert": {
        "description": "Mapped from execution-specs SSTORE same value revert path on a present slot onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-storage-write-same-value-present-revert",
        "notes": json.dumps(
            [
                "Upstream intent: cold SSTORE to a present slot, writing back the same value before the transaction reverts.",
                "RPC mapping: deploy a contract whose constructor initializes slot0=0x01 and whose runtime writes then REVERTs, invoke it with calldata 0x01, then assert receipt failure and unchanged storage.",
                "Admitted because final receipt status and rolled-back storage are directly observable over RPC without reproducing upstream gas benchmarking internals.",
            ]
        ),
    },
    "write_same_value_present_oog": {
        "description": "Mapped from execution-specs SSTORE same value out-of-gas path on a present slot onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-storage-write-same-value-present-oog",
        "notes": json.dumps(
            [
                "Upstream intent: cold SSTORE to a present slot, writing back the same value before the transaction runs out of gas.",
                "RPC mapping: deploy a contract whose constructor initializes slot0=0x01, invoke it with calldata 0x01 and low gas, then assert receipt failure and unchanged storage.",
                "Admitted because final receipt status and rolled-back storage are directly observable over RPC without reproducing upstream gas benchmarking internals.",
            ]
        ),
    },
    "write_new_value_present": {
        "description": "Mapped from execution-specs SSTORE new value cold path on a present slot onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-storage-write-new-value-present-success",
        "notes": json.dumps(
            [
                "Upstream intent: cold SSTORE to a present slot, writing a new non-zero value with successful completion.",
                "RPC mapping: deploy a contract whose constructor initializes slot0=0x01, then invoke runtime that writes 0xffff...ffff and assert slot0 changes.",
                "Admitted because the truth source is final storage state; excluded upstream gas-benchmark accounting is intentionally not reproduced.",
            ]
        ),
    },
    "write_new_value_present_revert": {
        "description": "Mapped from execution-specs SSTORE new value revert path on a present slot onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-storage-write-new-value-present-revert",
        "notes": json.dumps(
            [
                "Upstream intent: cold SSTORE to a present slot, writing a new non-zero value before the transaction reverts.",
                "RPC mapping: deploy a contract whose constructor initializes slot0=0x01 and whose runtime writes then REVERTs, invoke it with calldata 0xffff...ffff, then assert receipt failure and unchanged storage.",
                "Admitted because final receipt status and rolled-back storage are directly observable over RPC without reproducing upstream gas benchmarking internals.",
            ]
        ),
    },
    "write_new_value_present_oog": {
        "description": "Mapped from execution-specs SSTORE new value out-of-gas path on a present slot onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-storage-write-new-value-present-oog",
        "notes": json.dumps(
            [
                "Upstream intent: cold SSTORE to a present slot, writing a new non-zero value before the transaction runs out of gas.",
                "RPC mapping: deploy a contract whose constructor initializes slot0=0x01, invoke it with calldata 0xffff...ffff and low gas, then assert receipt failure and unchanged storage.",
                "Admitted because final receipt status and rolled-back storage are directly observable over RPC without reproducing upstream gas benchmarking internals.",
            ]
        ),
    },
    "read_present": {
        "description": "Mapped from execution-specs SLOAD success path onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-storage-read-present-success",
        "notes": json.dumps(
            [
                "Upstream intent: cold SLOAD from a present slot with successful completion.",
                "RPC mapping: deploy a contract whose constructor initializes slot0=0x2a, then invoke runtime that SLOADs slot0 and SSTOREs the read value into slot1.",
                "Admitted because the truth source is final storage state; excluded upstream gas-benchmark accounting is intentionally not reproduced.",
            ]
        ),
    },
    "read_absent": {
        "description": "Mapped from execution-specs SLOAD cold path on an absent slot onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-storage-read-absent-success",
        "notes": json.dumps(
            [
                "Upstream intent: cold SLOAD from an absent slot with successful completion.",
                "RPC mapping: deploy a contract with a runtime SLOAD/SSTORE mirror and assert the read value remains zero in storage.",
                "Admitted because the truth source is final storage state; excluded upstream gas-benchmark accounting is intentionally not reproduced.",
            ]
        ),
    },
    "warm_read_present": {
        "description": "Mapped from execution-specs warm SLOAD success path onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-storage-warm-read-present-success",
        "notes": json.dumps(
            [
                "Upstream intent: warm SLOAD from a present slot in a looping execution contract.",
                "RPC mapping: deploy a contract whose constructor initializes slot0=0x2a, then invoke runtime that mirrors the read-then-write shape and assert storage state.",
                "Admitted because the truth source is final storage state; excluded upstream gas-benchmark accounting is intentionally not reproduced.",
            ]
        ),
    },
    "warm_write_same_present": {
        "description": "Mapped from execution-specs warm SSTORE same value success path onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-storage-warm-write-same-present-success",
        "notes": json.dumps(
            [
                "Upstream intent: warm SSTORE to a present slot, writing the same value in a looping execution contract.",
                "RPC mapping: deploy a contract whose constructor initializes slot0=0x2a, then invoke runtime that preserves the stored value and assert slot0 remains unchanged.",
                "Admitted because the truth source is final storage state; excluded upstream gas-benchmark accounting is intentionally not reproduced.",
            ]
        ),
    },
    "warm_write_new_present": {
        "description": "Mapped from execution-specs warm SSTORE new value success path onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-storage-warm-write-new-present-success",
        "notes": json.dumps(
            [
                "Upstream intent: warm SSTORE to a present slot, writing a new value in a looping execution contract.",
                "RPC mapping: deploy a contract whose constructor initializes slot0=0x2a, then invoke runtime that writes a different nonzero value and assert slot0 becomes 0x2b.",
                "Admitted because the truth source is final storage state; excluded upstream gas-benchmark accounting is intentionally not reproduced.",
            ]
        ),
    },
}


def generate_upstream_storage_templates(
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
        else repo_root_path / "third_party" / "execution-specs" / "tests" / "benchmark" / "compute" / "instruction" / "test_storage.py"
    )
    templates, inventory = scan_storage_cases(source)
    payload = {
        "name": "upstream-storage-mapping-templates",
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
            family="storage",
            name="upstream-storage-auto-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload


def generate_upstream_storage_manifest(
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
        else repo_root_path / "suites" / "templates" / "upstream_storage_templates.json"
    )
    templates = load_storage_templates(template_file)
    execution_specs_ref = resolve_execution_specs_ref(
        repo_root_path / "suites" / "manifests" / "upstream_storage_mapped.json",
        "submodule-pending",
    )
    manifest = {
        "name": "upstream-storage-mapped",
        "version": "1",
        "execution_specs_ref": execution_specs_ref,
        "suite_version": suite_version,
        "chain_profile_version": chain_profile_version,
        "cases": [render_storage_case(template) for template in templates],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def load_storage_templates(path: str | Path) -> tuple[StorageMappingTemplate, ...]:
    template_path = Path(path)
    data = json.loads(template_path.read_text())
    return tuple(
        StorageMappingTemplate(
            case_id=entry["case_id"],
            description=entry["description"],
            namespace_seed=entry["namespace_seed"],
            upstream_ref=entry["upstream_ref"],
            notes=list(entry["notes"]),
            mode=entry["mode"],
        )
        for entry in data["cases"]
    )


def scan_storage_cases(source_path: str | Path) -> tuple[tuple[StorageMappingTemplate, ...], tuple[AutoTemplateInventoryEntry, ...]]:
    source = Path(source_path)
    text = source.read_text()
    cold_cases = _scan_cold_cases(text)
    warm_cases = _scan_warm_cases(text)
    inventory = sorted(cold_cases + warm_cases, key=lambda item: item.upstream_ref)
    templates = tuple(
        _inventory_entry_to_template(entry)
        for entry in inventory
        if entry.admitted and entry.mode is not None
    )
    return templates, tuple(inventory)


def _scan_cold_cases(text: str) -> list[AutoTemplateInventoryEntry]:
    param_block = _extract_param_block(
        text,
        marker='@pytest.mark.parametrize(\n    "storage_action,tx_result",',
        function_name="test_storage_access_cold",
    )
    entries = _extract_pytest_params(param_block)
    results: list[AutoTemplateInventoryEntry] = []
    for absent_slots in (True, False):
        absent_label = "absent_slots" if absent_slots else "present_slots"
        for storage_action, tx_result, display_id in entries:
            upstream_ref = (
                "tests/benchmark/compute/instruction/test_storage.py::"
                f"test_storage_access_cold[absent_slots={absent_slots}-{display_id}]"
            )
            case_id = _build_cold_case_id(storage_action, absent_label, tx_result)
            admitted_mode, reasons = _resolve_cold_mode(storage_action, absent_slots, tx_result)
            results.append(
                AutoTemplateInventoryEntry(
                    upstream_ref=upstream_ref,
                    case_id=case_id,
                    admitted=admitted_mode is not None,
                    mode=admitted_mode,
                    reasons=reasons,
                    source="cold",
                )
            )
    return results


def _scan_warm_cases(text: str) -> list[AutoTemplateInventoryEntry]:
    param_block = _extract_param_block(
        text,
        marker='@pytest.mark.parametrize(\n    "storage_action",',
        function_name="test_storage_access_warm",
    )
    entries = _extract_pytest_params(param_block)
    results: list[AutoTemplateInventoryEntry] = []
    for storage_action, _tx_result, display_id in entries:
        upstream_ref = (
            "tests/benchmark/compute/instruction/test_storage.py::"
            f"test_storage_access_warm[storage_action={storage_action}]"
        )
        case_id = _build_warm_case_id(storage_action)
        admitted_mode = _resolve_warm_mode(storage_action)
        results.append(
            AutoTemplateInventoryEntry(
                upstream_ref=upstream_ref,
                case_id=case_id,
                admitted=admitted_mode is not None,
                mode=admitted_mode,
                reasons=[] if admitted_mode is not None else ["unsupported warm storage action"],
                source="warm",
            )
        )
    return results


def _extract_param_block(text: str, *, marker: str, function_name: str) -> str:
    func = text.index(f"def {function_name}(")
    start = text.rfind(marker, 0, func)
    if start == -1:
        raise ValueError(f"could not find parameter block for {function_name}")
    return text[start:func]


def _extract_pytest_params(block: str) -> list[tuple[str, str | None, str]]:
    pattern = re.compile(
        r"pytest\.param\(\s*"
        r"StorageAction\.(?P<storage_action>[A-Z_]+)"
        r"(?:,\s*TransactionResult\.(?P<tx_result>[A-Z_]+))?"
        r",\s*id=\"(?P<display_id>[^\"]+)\"",
        re.MULTILINE,
    )
    return [
        (match.group("storage_action"), match.group("tx_result"), match.group("display_id"))
        for match in pattern.finditer(block)
    ]


def _build_cold_case_id(storage_action: str, absent_label: str, tx_result: str | None) -> str:
    action_slug = {
        "READ": "read",
        "WRITE_SAME_VALUE": "write_same_value",
        "WRITE_NEW_VALUE": "write_new_value",
    }[storage_action]
    suffix = {
        "SUCCESS": "success",
        "REVERT": "revert",
        "OUT_OF_GAS": "out_of_gas",
        None: "success",
    }[tx_result]
    return f"upstream.benchmark.storage.{action_slug}.{absent_label}.{suffix}"


def _build_warm_case_id(storage_action: str) -> str:
    action_slug = {
        "READ": "read",
        "WRITE_SAME_VALUE": "write_same_value",
        "WRITE_NEW_VALUE": "write_new_value",
    }[storage_action]
    return f"upstream.benchmark.storage.warm.{action_slug}.present_slots.success"


def _resolve_cold_mode(
    storage_action: str,
    absent_slots: bool,
    tx_result: str | None,
) -> tuple[StorageTemplateMode | None, list[str]]:
    if tx_result == "REVERT":
        if storage_action == "WRITE_SAME_VALUE":
            return ("write_same_value_absent_revert" if absent_slots else "write_same_value_present_revert"), []
        if storage_action == "WRITE_NEW_VALUE":
            return ("write_new_value_absent_revert" if absent_slots else "write_new_value_present_revert"), []
        return None, ["unsupported revert storage action"]
    if tx_result == "OUT_OF_GAS":
        if storage_action == "WRITE_SAME_VALUE":
            return ("write_same_value_absent_oog" if absent_slots else "write_same_value_present_oog"), []
        if storage_action == "WRITE_NEW_VALUE":
            return ("write_new_value_absent_oog" if absent_slots else "write_new_value_present_oog"), []
        return None, ["unsupported out-of-gas storage action"]
    if tx_result != "SUCCESS":
        return None, ["unsupported transaction result"]
    if storage_action == "READ":
        return ("read_absent" if absent_slots else "read_present"), []
    if storage_action == "WRITE_SAME_VALUE":
        return ("write_same_value_absent" if absent_slots else "write_same_value_present"), []
    if storage_action == "WRITE_NEW_VALUE":
        return ("write_new_value_absent" if absent_slots else "write_new_value_present"), []
    return None, ["unsupported cold storage action"]


def _resolve_warm_mode(storage_action: str) -> StorageTemplateMode | None:
    return {
        "READ": "warm_read_present",
        "WRITE_SAME_VALUE": "warm_write_same_present",
        "WRITE_NEW_VALUE": "warm_write_new_present",
    }.get(storage_action)


def _inventory_entry_to_template(entry: AutoTemplateInventoryEntry) -> StorageMappingTemplate:
    assert entry.mode is not None
    spec = STORAGE_MODE_SPECS[entry.mode]
    return StorageMappingTemplate(
        case_id=entry.case_id,
        description=spec["description"],
        namespace_seed=spec["namespace_seed"],
        upstream_ref=entry.upstream_ref,
        notes=json.loads(spec["notes"]),
        mode=entry.mode,
    )


def render_storage_case(template: StorageMappingTemplate) -> dict[str, Any]:
    if template.mode == "write_new_value_absent":
        return build_case(
            template,
            steps=[
                deploy_contract_step(
                    init_code=STORAGE_WRITE_CONTRACT_INIT,
                    runtime_code=STORAGE_WRITE_CONTRACT_RUNTIME,
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex=SLOT0_VALUE_2A),
                wait_receipt_step(),
            ],
            expected={"storage": {"0x00": SLOT0_VALUE_2A}},
        )
    if template.mode == "write_new_value_absent_revert":
        return build_case(
            template,
            steps=[
                deploy_contract_step(
                    init_code=STORAGE_WRITE_CONTRACT_INIT_REVERT,
                    runtime_code=STORAGE_WRITE_CONTRACT_RUNTIME_REVERT,
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex=SLOT0_VALUE_2A, expected_receipt_status="0x0"),
                wait_receipt_step(),
            ],
            expected={"receipt_status": "0x0", "storage": {"0x00": SLOT0_VALUE_00}},
        )
    if template.mode == "write_new_value_absent_oog":
        return build_case(
            template,
            steps=[
                deploy_contract_step(
                    init_code=STORAGE_WRITE_CONTRACT_INIT,
                    runtime_code=STORAGE_WRITE_CONTRACT_RUNTIME,
                ),
                wait_receipt_step(),
                invoke_contract_step(
                    data_hex=SLOT0_VALUE_2A,
                    gas=OOG_INVOKE_GAS,
                    expected_receipt_status="0x0",
                ),
                wait_receipt_step(),
            ],
            expected={"receipt_status": "0x0", "storage": {"0x00": SLOT0_VALUE_00}},
        )
    if template.mode == "write_same_value_absent":
        return build_case(
            template,
            steps=[
                deploy_contract_step(
                    init_code=STORAGE_WRITE_CONTRACT_INIT,
                    runtime_code=STORAGE_WRITE_CONTRACT_RUNTIME,
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex=SLOT0_VALUE_01),
                wait_receipt_step(),
            ],
            expected={"storage": {"0x00": SLOT0_VALUE_01}},
        )
    if template.mode == "write_same_value_absent_revert":
        return build_case(
            template,
            steps=[
                deploy_contract_step(
                    init_code=STORAGE_WRITE_CONTRACT_INIT_REVERT,
                    runtime_code=STORAGE_WRITE_CONTRACT_RUNTIME_REVERT,
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex=SLOT0_VALUE_01, expected_receipt_status="0x0"),
                wait_receipt_step(),
            ],
            expected={"receipt_status": "0x0", "storage": {"0x00": SLOT0_VALUE_00}},
        )
    if template.mode == "write_same_value_absent_oog":
        return build_case(
            template,
            steps=[
                deploy_contract_step(
                    init_code=STORAGE_WRITE_CONTRACT_INIT,
                    runtime_code=STORAGE_WRITE_CONTRACT_RUNTIME,
                ),
                wait_receipt_step(),
                invoke_contract_step(
                    data_hex=SLOT0_VALUE_01,
                    gas=OOG_INVOKE_GAS,
                    expected_receipt_status="0x0",
                ),
                wait_receipt_step(),
            ],
            expected={"receipt_status": "0x0", "storage": {"0x00": SLOT0_VALUE_00}},
        )
    if template.mode == "write_same_value_present":
        return build_case(
            template,
            steps=[
                deploy_contract_step(
                    init_code=STORAGE_WRITE_CONTRACT_INIT,
                    runtime_code=STORAGE_WRITE_CONTRACT_RUNTIME,
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex=SLOT0_VALUE_2A),
                wait_receipt_step(),
                invoke_contract_step(data_hex=SLOT0_VALUE_2A),
                wait_receipt_step(),
            ],
            expected={"storage": {"0x00": SLOT0_VALUE_2A}},
        )
    if template.mode == "write_same_value_present_revert":
        return build_case(
            template,
            steps=[
                deploy_contract_step(
                    init_code=STORAGE_WRITE_CONTRACT_INIT_PRESENT_ONE_REVERT,
                    runtime_code=STORAGE_WRITE_CONTRACT_RUNTIME_REVERT,
                    initial_storage={"0x00": SLOT0_VALUE_01},
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex=SLOT0_VALUE_01, expected_receipt_status="0x0"),
                wait_receipt_step(),
            ],
            expected={"receipt_status": "0x0", "storage": {"0x00": SLOT0_VALUE_01}},
        )
    if template.mode == "write_same_value_present_oog":
        return build_case(
            template,
            steps=[
                deploy_contract_step(
                    init_code=STORAGE_WRITE_CONTRACT_INIT_PRESENT_ONE,
                    runtime_code=STORAGE_WRITE_CONTRACT_RUNTIME,
                    initial_storage={"0x00": SLOT0_VALUE_01},
                ),
                wait_receipt_step(),
                invoke_contract_step(
                    data_hex=SLOT0_VALUE_01,
                    gas=OOG_INVOKE_GAS,
                    expected_receipt_status="0x0",
                ),
                wait_receipt_step(),
            ],
            expected={"receipt_status": "0x0", "storage": {"0x00": SLOT0_VALUE_01}},
        )
    if template.mode == "write_new_value_present":
        return build_case(
            template,
            steps=[
                deploy_contract_step(
                    init_code=STORAGE_WRITE_CONTRACT_INIT_PRESENT_ONE,
                    runtime_code=STORAGE_WRITE_CONTRACT_RUNTIME,
                    initial_storage={"0x00": SLOT0_VALUE_01},
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex=SLOT0_VALUE_FF),
                wait_receipt_step(),
            ],
            expected={"storage": {"0x00": SLOT0_VALUE_FF}},
        )
    if template.mode == "write_new_value_present_revert":
        return build_case(
            template,
            steps=[
                deploy_contract_step(
                    init_code=STORAGE_WRITE_CONTRACT_INIT_PRESENT_ONE_REVERT,
                    runtime_code=STORAGE_WRITE_CONTRACT_RUNTIME_REVERT,
                    initial_storage={"0x00": SLOT0_VALUE_01},
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex=SLOT0_VALUE_FF, expected_receipt_status="0x0"),
                wait_receipt_step(),
            ],
            expected={"receipt_status": "0x0", "storage": {"0x00": SLOT0_VALUE_01}},
        )
    if template.mode == "write_new_value_present_oog":
        return build_case(
            template,
            steps=[
                deploy_contract_step(
                    init_code=STORAGE_WRITE_CONTRACT_INIT_PRESENT_ONE,
                    runtime_code=STORAGE_WRITE_CONTRACT_RUNTIME,
                    initial_storage={"0x00": SLOT0_VALUE_01},
                ),
                wait_receipt_step(),
                invoke_contract_step(
                    data_hex=SLOT0_VALUE_FF,
                    gas=OOG_INVOKE_GAS,
                    expected_receipt_status="0x0",
                ),
                wait_receipt_step(),
            ],
            expected={"receipt_status": "0x0", "storage": {"0x00": SLOT0_VALUE_01}},
        )
    if template.mode == "read_present":
        return build_case(
            template,
            steps=[
                deploy_contract_step(
                    init_code=STORAGE_READ_CONTRACT_INIT,
                    runtime_code=STORAGE_READ_CONTRACT_RUNTIME,
                    initial_storage={"0x00": SLOT0_VALUE_2A},
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex="0x"),
                wait_receipt_step(),
            ],
            expected={
                "storage": {
                    "0x00": SLOT0_VALUE_2A,
                    "0x01": SLOT0_VALUE_2A,
                }
            },
        )
    if template.mode == "read_absent":
        return build_case(
            template,
            steps=[
                deploy_contract_step(
                    init_code=STORAGE_READ_CONTRACT_INIT_EMPTY,
                    runtime_code=STORAGE_READ_CONTRACT_RUNTIME,
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex="0x"),
                wait_receipt_step(),
            ],
            expected={"storage": {"0x01": SLOT0_VALUE_00}},
        )
    if template.mode == "warm_read_present":
        return build_case(
            template,
            steps=[
                deploy_contract_step(
                    init_code=STORAGE_READ_CONTRACT_INIT,
                    runtime_code=STORAGE_READ_CONTRACT_RUNTIME,
                    initial_storage={"0x00": SLOT0_VALUE_2A},
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex="0x"),
                wait_receipt_step(),
            ],
            expected={
                "storage": {
                    "0x00": SLOT0_VALUE_2A,
                    "0x01": SLOT0_VALUE_2A,
                }
            },
        )
    if template.mode == "warm_write_same_present":
        return build_case(
            template,
            steps=[
                deploy_contract_step(
                    init_code=STORAGE_READ_CONTRACT_INIT,
                    runtime_code=STORAGE_WARM_SAME_RUNTIME,
                    initial_storage={"0x00": SLOT0_VALUE_2A},
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex="0x"),
                wait_receipt_step(),
            ],
            expected={"storage": {"0x00": SLOT0_VALUE_2A}},
        )
    if template.mode == "warm_write_new_present":
        return build_case(
            template,
            steps=[
                deploy_contract_step(
                    init_code=STORAGE_READ_CONTRACT_INIT,
                    runtime_code=STORAGE_WARM_NEW_RUNTIME,
                    initial_storage={"0x00": SLOT0_VALUE_2A},
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex="0x"),
                wait_receipt_step(),
            ],
            expected={"storage": {"0x00": SLOT0_VALUE_2B}},
        )
    raise ValueError(f"unsupported storage mapping mode: {template.mode}")


def build_case(
    template: StorageMappingTemplate,
    *,
    steps: list[dict[str, Any]],
    expected: dict[str, Any],
) -> dict[str, Any]:
    return {
        "kind": "upstream_mapped",
        "case_id": template.case_id,
        "family": "state/storage",
        "description": template.description,
        "namespace_seed": template.namespace_seed,
        "upstream_ref": template.upstream_ref,
        "notes": template.notes,
        "observe": {"storage_address": "$last_contract"},
        "filters": {},
        "steps": steps,
        "expected": expected,
    }


def deploy_contract_step(
    *,
    init_code: str,
    runtime_code: str,
    initial_storage: dict[str, str] | None = None,
    gas: str = "0x186a0",
) -> dict[str, Any]:
    return {
        "action": "deploy_contract",
        "bytecode_init": init_code,
        "bytecode_runtime": runtime_code,
        **({"initial_storage": initial_storage} if initial_storage is not None else {}),
        "gas": gas,
    }


def wait_receipt_step() -> dict[str, Any]:
    return {
        "action": "wait_receipt",
        "tx_hash": "$last",
        "timeout_seconds": 60,
    }


def invoke_contract_step(
    *,
    data_hex: str,
    gas: str = "0xc350",
    expected_receipt_status: str | None = None,
) -> dict[str, Any]:
    return {
        "action": "invoke_contract",
        "to": "$last_contract",
        "data": data_hex,
        "gas": gas,
        **(
            {"expected_receipt_status": expected_receipt_status}
            if expected_receipt_status is not None
            else {}
        ),
    }
