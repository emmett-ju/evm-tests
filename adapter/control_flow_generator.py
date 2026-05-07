from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from adapter.inventory import write_inventory_payload


BLOCKED_REASON = "requires control-flow benchmark mapping support not yet mapped"
CONTROL_FLOW_FUNCTIONS = (
    "test_gas_op",
    "test_pc_op",
    "test_jumps",
    "test_jump_benchmark",
    "test_jumpi_fallthrough",
    "test_jumpis",
    "test_jumpdests",
)


@dataclass(frozen=True, slots=True)
class ControlFlowMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    mode: str


@dataclass(frozen=True, slots=True)
class AutoControlFlowInventoryEntry:
    upstream_ref: str
    case_id: str
    admitted: bool
    mode: str | None
    reasons: list[str]
    source: str


def generate_upstream_control_flow_templates(
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
        / "test_control_flow.py"
    )
    templates, inventory = scan_control_flow_cases(source)
    payload = {
        "name": "upstream-control-flow-mapping-templates",
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
            family="control-flow",
            name="upstream-control-flow-auto-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload


def scan_control_flow_cases(
    source_path: str | Path,
) -> tuple[tuple[ControlFlowMappingTemplate, ...], tuple[AutoControlFlowInventoryEntry, ...]]:
    source = Path(source_path)
    text = source.read_text()
    inventory = sorted(_scan_standalone_cases(text), key=lambda item: item.upstream_ref)
    if len(inventory) != 7:
        raise ValueError(f"expected 7 control-flow benchmark cases, found {len(inventory)}")
    return (), tuple(inventory)


def _scan_standalone_cases(text: str) -> list[AutoControlFlowInventoryEntry]:
    entries: list[AutoControlFlowInventoryEntry] = []
    for function_name in CONTROL_FLOW_FUNCTIONS:
        if f"def {function_name}(" not in text:
            raise ValueError(f"could not find benchmark function {function_name}")
        entries.append(
            AutoControlFlowInventoryEntry(
                upstream_ref=(
                    "tests/benchmark/compute/instruction/test_control_flow.py::"
                    f"{function_name}"
                ),
                case_id=f"upstream.benchmark.control_flow.{function_name}",
                admitted=False,
                mode=None,
                reasons=[BLOCKED_REASON],
                source=function_name,
            )
        )
    return entries
