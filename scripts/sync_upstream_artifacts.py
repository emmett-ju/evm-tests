#!/usr/bin/env python3
"""Safely regenerate upstream-derived template, inventory, and manifest artifacts.

The script stages all generated artifacts in a temporary directory first, validates the
staged manifests and inventory summary, and only copies files back into the working
tree when every automatic generation step succeeds.
"""

from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from adapter.account_query_generator import generate_upstream_account_query_manifest, generate_upstream_account_query_templates
from adapter.arithmetic_generator import generate_upstream_arithmetic_manifest, generate_upstream_arithmetic_templates
from adapter.bitwise_generator import generate_upstream_bitwise_manifest, generate_upstream_bitwise_templates
from adapter.block_context_generator import generate_upstream_block_context_manifest, generate_upstream_block_context_templates
from adapter.call_context_generator import generate_upstream_call_context_manifest, generate_upstream_call_context_templates
from adapter.comparison_generator import generate_upstream_comparison_manifest, generate_upstream_comparison_templates
from adapter.control_flow_generator import generate_upstream_control_flow_manifest, generate_upstream_control_flow_templates
from adapter.inventory import summarize_inventory_dir
from adapter.keccak_generator import generate_upstream_keccak_manifest, generate_upstream_keccak_templates
from adapter.log_generator import generate_upstream_log_manifest, generate_upstream_log_templates
from adapter.manifest import load_manifest
from adapter.memory_generator import generate_upstream_memory_manifest, generate_upstream_memory_templates
from adapter.stack_generator import generate_upstream_stack_manifest, generate_upstream_stack_templates
from adapter.generator import generate_upstream_storage_manifest, generate_upstream_storage_templates
from adapter.system_generator import generate_upstream_system_manifest, generate_upstream_system_templates
from adapter.tx_context_generator import generate_upstream_tx_context_manifest, generate_upstream_tx_context_templates

TemplateGenerator = Callable[..., Mapping[str, object]]
ManifestGenerator = Callable[..., Mapping[str, object]]


@dataclass(frozen=True)
class FamilySyncSpec:
    family: str
    source: str
    template_file: str
    inventory_file: str
    manifest_file: str
    generate_templates: TemplateGenerator
    generate_manifest: ManifestGenerator


FAMILY_SPECS: tuple[FamilySyncSpec, ...] = (
    FamilySyncSpec(
        family="account-query",
        source="third_party/execution-specs/tests/benchmark/compute/instruction/test_account_query.py",
        template_file="upstream_account_query_templates.json",
        inventory_file="upstream_account_query_inventory.json",
        manifest_file="upstream_account_query_mapped.json",
        generate_templates=generate_upstream_account_query_templates,
        generate_manifest=generate_upstream_account_query_manifest,
    ),
    FamilySyncSpec(
        family="arithmetic",
        source="third_party/execution-specs/tests/benchmark/compute/instruction/test_arithmetic.py",
        template_file="upstream_arithmetic_templates.json",
        inventory_file="upstream_arithmetic_inventory.json",
        manifest_file="upstream_arithmetic_mapped.json",
        generate_templates=generate_upstream_arithmetic_templates,
        generate_manifest=generate_upstream_arithmetic_manifest,
    ),
    FamilySyncSpec(
        family="bitwise",
        source="third_party/execution-specs/tests/benchmark/compute/instruction/test_bitwise.py",
        template_file="upstream_bitwise_templates.json",
        inventory_file="upstream_bitwise_inventory.json",
        manifest_file="upstream_bitwise_mapped.json",
        generate_templates=generate_upstream_bitwise_templates,
        generate_manifest=generate_upstream_bitwise_manifest,
    ),
    FamilySyncSpec(
        family="block-context",
        source="third_party/execution-specs/tests/benchmark/compute/instruction/test_block_context.py",
        template_file="upstream_block_context_templates.json",
        inventory_file="upstream_block_context_inventory.json",
        manifest_file="upstream_block_context_mapped.json",
        generate_templates=generate_upstream_block_context_templates,
        generate_manifest=generate_upstream_block_context_manifest,
    ),
    FamilySyncSpec(
        family="call-context",
        source="third_party/execution-specs/tests/benchmark/compute/instruction/test_call_context.py",
        template_file="upstream_call_context_templates.json",
        inventory_file="upstream_call_context_inventory.json",
        manifest_file="upstream_call_context_mapped.json",
        generate_templates=generate_upstream_call_context_templates,
        generate_manifest=generate_upstream_call_context_manifest,
    ),
    FamilySyncSpec(
        family="comparison",
        source="third_party/execution-specs/tests/benchmark/compute/instruction/test_comparison.py",
        template_file="upstream_comparison_templates.json",
        inventory_file="upstream_comparison_inventory.json",
        manifest_file="upstream_comparison_mapped.json",
        generate_templates=generate_upstream_comparison_templates,
        generate_manifest=generate_upstream_comparison_manifest,
    ),
    FamilySyncSpec(
        family="control-flow",
        source="third_party/execution-specs/tests/benchmark/compute/instruction/test_control_flow.py",
        template_file="upstream_control_flow_templates.json",
        inventory_file="upstream_control_flow_inventory.json",
        manifest_file="upstream_control_flow_mapped.json",
        generate_templates=generate_upstream_control_flow_templates,
        generate_manifest=generate_upstream_control_flow_manifest,
    ),
    FamilySyncSpec(
        family="keccak",
        source="third_party/execution-specs/tests/benchmark/compute/instruction/test_keccak.py",
        template_file="upstream_keccak_templates.json",
        inventory_file="upstream_keccak_inventory.json",
        manifest_file="upstream_keccak_mapped.json",
        generate_templates=generate_upstream_keccak_templates,
        generate_manifest=generate_upstream_keccak_manifest,
    ),
    FamilySyncSpec(
        family="log",
        source="third_party/execution-specs/tests/benchmark/compute/instruction/test_log.py",
        template_file="upstream_log_templates.json",
        inventory_file="upstream_log_inventory.json",
        manifest_file="upstream_log_mapped.json",
        generate_templates=generate_upstream_log_templates,
        generate_manifest=generate_upstream_log_manifest,
    ),
    FamilySyncSpec(
        family="memory",
        source="third_party/execution-specs/tests/benchmark/compute/instruction/test_memory.py",
        template_file="upstream_memory_templates.json",
        inventory_file="upstream_memory_inventory.json",
        manifest_file="upstream_memory_mapped.json",
        generate_templates=generate_upstream_memory_templates,
        generate_manifest=generate_upstream_memory_manifest,
    ),
    FamilySyncSpec(
        family="stack",
        source="third_party/execution-specs/tests/benchmark/compute/instruction/test_stack.py",
        template_file="upstream_stack_templates.json",
        inventory_file="upstream_stack_inventory.json",
        manifest_file="upstream_stack_mapped.json",
        generate_templates=generate_upstream_stack_templates,
        generate_manifest=generate_upstream_stack_manifest,
    ),
    FamilySyncSpec(
        family="storage",
        source="third_party/execution-specs/tests/benchmark/compute/instruction/test_storage.py",
        template_file="upstream_storage_templates.json",
        inventory_file="upstream_storage_inventory.json",
        manifest_file="upstream_storage_mapped.json",
        generate_templates=generate_upstream_storage_templates,
        generate_manifest=generate_upstream_storage_manifest,
    ),
    FamilySyncSpec(
        family="system",
        source="third_party/execution-specs/tests/benchmark/compute/instruction/test_system.py",
        template_file="upstream_system_templates.json",
        inventory_file="upstream_system_inventory.json",
        manifest_file="upstream_system_mapped.json",
        generate_templates=generate_upstream_system_templates,
        generate_manifest=generate_upstream_system_manifest,
    ),
    FamilySyncSpec(
        family="tx-context",
        source="third_party/execution-specs/tests/benchmark/compute/instruction/test_tx_context.py",
        template_file="upstream_tx_context_templates.json",
        inventory_file="upstream_tx_context_inventory.json",
        manifest_file="upstream_tx_context_mapped.json",
        generate_templates=generate_upstream_tx_context_templates,
        generate_manifest=generate_upstream_tx_context_manifest,
    ),
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Safely regenerate upstream-derived EVM test artifacts.")
    parser.add_argument("--repo-root", default=".", help="Repository root. Defaults to the current directory.")
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Generate and validate staged artifacts without copying them into the working tree.",
    )
    parser.add_argument(
        "--keep-staged-dir",
        action="store_true",
        help="Keep the temporary staged artifact directory and print its path for debugging.",
    )
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    with tempfile.TemporaryDirectory(prefix="evm-upstream-sync-") as tmpdir:
        staged_root = Path(tmpdir)
        staged_templates = staged_root / "templates"
        staged_manifests = staged_root / "manifests"
        staged_templates.mkdir(parents=True, exist_ok=True)
        staged_manifests.mkdir(parents=True, exist_ok=True)

        payload = sync_to_staging(repo_root, staged_templates, staged_manifests)
        if not args.check_only:
            apply_staged_artifacts(repo_root, staged_templates, staged_manifests)
            payload["applied"] = True
        else:
            payload["applied"] = False

        if args.keep_staged_dir:
            kept = repo_root / ".state" / "last-upstream-sync-staging"
            if kept.exists():
                shutil.rmtree(kept)
            kept.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(staged_root, kept)
            payload["staged_dir"] = str(kept)

        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def sync_to_staging(repo_root: Path, staged_templates: Path, staged_manifests: Path) -> dict[str, object]:
    generated: list[dict[str, str]] = []
    for spec in FAMILY_SPECS:
        source_path = repo_root / spec.source
        template_path = staged_templates / spec.template_file
        inventory_path = staged_templates / spec.inventory_file
        manifest_path = staged_manifests / spec.manifest_file

        spec.generate_templates(
            repo_root=repo_root,
            source_path=source_path,
            output_path=template_path,
            inventory_path=inventory_path,
        )
        spec.generate_manifest(
            repo_root=repo_root,
            template_path=template_path,
            output_path=manifest_path,
        )
        load_manifest(manifest_path)
        generated.append(
            {
                "family": spec.family,
                "template": str(template_path),
                "inventory": str(inventory_path),
                "manifest": str(manifest_path),
            }
        )

    summary = summarize_inventory_dir(staged_templates)
    validate_summary(summary)
    return {
        "families": [spec.family for spec in FAMILY_SPECS],
        "generated": generated,
        "summary": summary["totals"],
    }


def validate_summary(summary: Mapping[str, object]) -> None:
    totals = summary.get("totals")
    if not isinstance(totals, Mapping):
        raise ValueError("inventory summary missing totals")
    family_count = totals.get("families")
    if family_count != len(FAMILY_SPECS):
        raise ValueError(f"expected {len(FAMILY_SPECS)} inventory families, got {family_count!r}")
    if int(totals.get("cases", 0)) <= 0:
        raise ValueError("inventory summary generated no cases")
    if int(totals.get("admitted", 0)) <= 0:
        raise ValueError("inventory summary generated no admitted cases")


def apply_staged_artifacts(repo_root: Path, staged_templates: Path, staged_manifests: Path) -> None:
    destination_templates = repo_root / "suites" / "templates"
    destination_manifests = repo_root / "suites" / "manifests"
    for spec in FAMILY_SPECS:
        shutil.copy2(staged_templates / spec.template_file, destination_templates / spec.template_file)
        shutil.copy2(staged_templates / spec.inventory_file, destination_templates / spec.inventory_file)
        shutil.copy2(staged_manifests / spec.manifest_file, destination_manifests / spec.manifest_file)


if __name__ == "__main__":
    raise SystemExit(main())
