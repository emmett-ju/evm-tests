from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from adapter.generator import build_case, deploy_contract_step, invoke_contract_step, wait_receipt_step
from adapter.assembler import _build_init_code
from adapter.inventory import write_inventory_payload
from adapter.manifest import resolve_execution_specs_ref


TX_CONTEXT_ORIGIN_RUNTIME = "0x3260005500"
TX_CONTEXT_GASPRICE_RUNTIME = "0x3a60005500"

TxContextTemplateMode = Literal["origin", "gasprice"]


@dataclass(frozen=True, slots=True)
class TxContextMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: TxContextTemplateMode


@dataclass(frozen=True, slots=True)
class AutoTxContextInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str


TX_CONTEXT_MODE_SPECS: dict[TxContextTemplateMode, dict[str, str]] = {
    "origin": {
        "description": "Mapped from execution-specs ORIGIN onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-tx-context-origin",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark ORIGIN in an external-call frame.",
                "RPC mapping: runtime writes ORIGIN to storage slot0 after deployment, then the harness asserts it against the active admin sender resolved at runtime.",
                "Admitted because the sender address is known from the chain profile and observable without block-level control.",
            ]
        ),
    },
    "gasprice": {
        "description": "Mapped from execution-specs GASPRICE onto an RPC-only deploy/call/storage-assert flow.",
        "namespace_seed": "upstream-tx-context-gasprice",
        "notes": json.dumps(
            [
                "Upstream intent: benchmark GASPRICE in an external-call frame.",
                "RPC mapping: runtime writes GASPRICE to storage slot0 after deployment, then the harness asserts it against the effective gas price observed on the invoke receipt.",
                "Admitted because the invoke transaction receipt exposes the effective gas price truthfully on both mock and jsonrpc backends without block-environment control.",
            ]
        ),
    },
}


def generate_upstream_tx_context_templates(
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
        else repo_root_path / "third_party" / "execution-specs" / "tests" / "benchmark" / "compute" / "instruction" / "test_tx_context.py"
    )
    templates, inventory = scan_tx_context_cases(source)
    payload = {
        "name": "upstream-tx-context-mapping-templates",
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
            family="tx-context",
            name="upstream-tx-context-auto-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload


def generate_upstream_tx_context_manifest(
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
        else repo_root_path / "suites" / "templates" / "upstream_tx_context_templates.json"
    )
    templates = load_tx_context_templates(template_file)
    execution_specs_ref = resolve_execution_specs_ref(
        repo_root_path / "suites" / "manifests" / "upstream_tx_context_mapped.json",
        "submodule-pending",
    )
    manifest = {
        "name": "upstream-tx-context-mapped",
        "version": "1",
        "execution_specs_ref": execution_specs_ref,
        "suite_version": suite_version,
        "chain_profile_version": chain_profile_version,
        "cases": [render_tx_context_case(template) for template in templates],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def load_tx_context_templates(path: str | Path) -> tuple[TxContextMappingTemplate, ...]:
    template_path = Path(path)
    data = json.loads(template_path.read_text())
    return tuple(
        TxContextMappingTemplate(
            case_id=entry["case_id"],
            description=entry["description"],
            namespace_seed=entry["namespace_seed"],
            upstream_ref=entry["upstream_ref"],
            notes=list(entry["notes"]),
            mode=entry["mode"],
        )
        for entry in data["cases"]
    )


def scan_tx_context_cases(
    source_path: str | Path,
) -> tuple[tuple[TxContextMappingTemplate, ...], tuple[AutoTxContextInventoryEntry, ...]]:
    source = Path(source_path)
    text = source.read_text()
    inventory = sorted(
        _scan_zero_param_cases(text) + _scan_blobhash_cases(text),
        key=lambda item: item.upstream_ref,
    )
    templates = tuple(
        _inventory_entry_to_template(entry)
        for entry in inventory
        if entry.admitted and entry.mode is not None
    )
    return templates, tuple(inventory)


def _scan_zero_param_cases(text: str) -> list[AutoTxContextInventoryEntry]:
    values = _extract_param_values(text, r'@pytest\.mark\.parametrize\(\s*"opcode",\s*\[(?P<values>[^\]]+)\]\s*,?\s*\)\s*def test_call_frame_context_ops')
    results: list[AutoTxContextInventoryEntry] = []
    for raw in values:
        opcode = raw.split(".")[-1]
        upstream_ref = f"tests/benchmark/compute/instruction/test_tx_context.py::test_call_frame_context_ops[opcode={opcode}]"
        case_id = f"upstream.benchmark.tx_context.{opcode.lower()}.success"
        admitted_mode, reasons = _resolve_zero_param_mode(opcode)
        results.append(
            AutoTxContextInventoryEntry(
                upstream_ref=upstream_ref,
                case_id=case_id,
                admitted=admitted_mode is not None,
                mode=admitted_mode,
                reasons=reasons,
                source="zero_param",
            )
        )
    return results


def _scan_blobhash_cases(text: str) -> list[AutoTxContextInventoryEntry]:
    block = _extract_param_block(text, function_name="test_blobhash")
    values = [
        int(match.group("blob_present"))
        for match in re.finditer(
            r"pytest\.param\((?P<blob_present>\d+),\s*id=\"(?P<label>[^\"]+)\"\)",
            block,
        )
    ]
    results: list[AutoTxContextInventoryEntry] = []
    for blob_present in values:
        label = "one_blob" if blob_present else "no_blobs"
        results.append(
            AutoTxContextInventoryEntry(
                upstream_ref=f"tests/benchmark/compute/instruction/test_tx_context.py::test_blobhash[blob_present={label}]",
                case_id=f"upstream.benchmark.tx_context.blobhash.{label}.success",
                admitted=False,
                mode=None,
                reasons=["requires blob transaction construction and BLOBHASH environment not yet mapped"],
                source="blobhash",
            )
        )
    return results


def _extract_param_block(text: str, *, function_name: str) -> str:
    marker = '@pytest.mark.parametrize(\n    "blob_present",'
    func = text.index(f"def {function_name}(")
    start = text.rfind(marker, 0, func)
    if start == -1:
        raise ValueError(f"could not find parameter block for {function_name}")
    return text[start:func]


def _extract_param_values(text: str, pattern: str) -> list[str]:
    match = re.search(pattern, text, re.MULTILINE | re.DOTALL)
    if not match:
        raise ValueError(f"could not match pattern: {pattern}")
    values = match.groupdict().get("values")
    if values is None:
        raise ValueError(f"pattern missing named group 'values': {pattern}")
    return [value.strip() for value in values.split(",") if value.strip()]


def _parse_int_literal(value: str) -> int:
    normalized = value.replace("_", "").strip()
    if "*" in normalized:
        left, right = [part.strip() for part in normalized.split("*", 1)]
        return int(left) * int(right)
    return int(normalized)


def _resolve_zero_param_mode(opcode: str) -> tuple[TxContextTemplateMode | None, list[str]]:
    if opcode == "ORIGIN":
        return "origin", []
    if opcode == "GASPRICE":
        return "gasprice", []
    return None, ["unsupported transaction-context opcode"]


def _inventory_entry_to_template(entry: AutoTxContextInventoryEntry) -> TxContextMappingTemplate:
    assert entry.mode is not None
    spec = TX_CONTEXT_MODE_SPECS[entry.mode]
    return TxContextMappingTemplate(
        case_id=entry.case_id,
        description=spec["description"],
        namespace_seed=spec["namespace_seed"],
        upstream_ref=entry.upstream_ref,
        notes=json.loads(spec["notes"]),
        mode=entry.mode,
    )


def render_tx_context_case(template: TxContextMappingTemplate) -> dict[str, Any]:
    if template.mode == "origin":
        case = build_case(
            template,  # type: ignore[arg-type]
            steps=[
                deploy_contract_step(
                    init_code=_build_init_code(TX_CONTEXT_ORIGIN_RUNTIME),
                    runtime_code=TX_CONTEXT_ORIGIN_RUNTIME,
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex="0x"),
                wait_receipt_step(),
            ],
            expected={"storage": {"0x00": "$admin_account_word"}},
        )
        case["family"] = "state/tx-context"
        return case
    if template.mode == "gasprice":
        case = build_case(
            template,  # type: ignore[arg-type]
            steps=[
                deploy_contract_step(
                    init_code=_build_init_code(TX_CONTEXT_GASPRICE_RUNTIME),
                    runtime_code=TX_CONTEXT_GASPRICE_RUNTIME,
                ),
                wait_receipt_step(),
                invoke_contract_step(data_hex="0x"),
                wait_receipt_step(),
            ],
            expected={"storage": {"0x00": "$gas_price_word"}},
        )
        case["family"] = "state/tx-context"
        return case
    raise ValueError(f"unsupported tx-context mapping mode: {template.mode}")
