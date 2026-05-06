from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adapter.manifest import resolve_execution_specs_ref


STORAGE_WRITE_CONTRACT_INIT = "0x6007600c60003960076000f360003560005500"
STORAGE_WRITE_CONTRACT_RUNTIME = "0x60003560005500"
STORAGE_READ_CONTRACT_INIT = "0x602a6000556007601160003960076000f360005460015500"
STORAGE_READ_CONTRACT_INIT_EMPTY = "0x6007600c60003960076000f360005460015500"
STORAGE_READ_CONTRACT_RUNTIME = "0x60005460015500"
STORAGE_WRITE_CONTRACT_INIT_PRESENT_ONE = "0x60016000556007601160003960076000f360003560005500"
STORAGE_WARM_SAME_RUNTIME = "0x60005460005500"
STORAGE_WARM_NEW_RUNTIME = "0x602b60005500"
SLOT0_VALUE_00 = "0x0000000000000000000000000000000000000000000000000000000000000000"
SLOT0_VALUE_01 = "0x0000000000000000000000000000000000000000000000000000000000000001"
SLOT0_VALUE_2A = "0x000000000000000000000000000000000000000000000000000000000000002a"
SLOT0_VALUE_2B = "0x000000000000000000000000000000000000000000000000000000000000002b"
SLOT0_VALUE_FF = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"


@dataclass(frozen=True, slots=True)
class StorageMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: str


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
    template_file = Path(template_path).resolve() if template_path is not None else repo_root_path / "suites" / "templates" / "upstream_storage_templates.json"
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
            expected={
                "storage": {
                    "0x01": SLOT0_VALUE_00,
                }
            },
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


def invoke_contract_step(*, data_hex: str) -> dict[str, Any]:
    return {
        "action": "invoke_contract",
        "to": "$last_contract",
        "data": data_hex,
        "gas": "0xc350",
    }
